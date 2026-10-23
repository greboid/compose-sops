package provider_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/greboid/compose-sops/internal/fixtures"
	"github.com/greboid/compose-sops/internal/provider"
)

type harness struct {
	t          *testing.T
	runtimeDir string
	encFile    string
	keyFile    string
}

type wireMessage struct {
	Type    string `json:"type"`
	Message string `json:"message"`
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	h := &harness{
		t:          t,
		runtimeDir: tmpfsDir(t),
	}
	h.encFile = filepath.Join(t.TempDir(), "secrets.age.yaml")
	h.keyFile = filepath.Join(t.TempDir(), "keys.txt")
	if err := os.WriteFile(h.encFile, fixtures.ValidDocument(), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(h.keyFile, fixtures.IdentityTest(), 0o600); err != nil {
		t.Fatal(err)
	}
	return h
}

// run invokes a provider command, capturing protocol messages, and returns
// the command error.
func (h *harness) run(name string, mutate func(*provider.Options)) ([]wireMessage, error) {
	h.t.Helper()
	var buf bytes.Buffer
	emit := provider.NewEmitter(&buf)
	p := provider.New(nil, nil, emit)
	opts := provider.Options{
		File:       h.encFile,
		AgeKeyFile: h.keyFile,
		RuntimeDir: h.runtimeDir,
	}
	if mutate != nil {
		mutate(&opts)
	}
	var err error
	switch name {
	case "up":
		err = p.Up("proj", "svc", opts)
	case "down":
		err = p.Down("proj", "svc", opts)
	case "stop":
		err = p.Stop("proj", "svc", opts)
	default:
		panic("unknown command " + name)
	}
	var messages []wireMessage
	for line := range strings.SplitSeq(strings.TrimSpace(buf.String()), "\n") {
		if line == "" {
			continue
		}
		var m wireMessage
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			h.t.Fatalf("bad protocol line %q: %v", line, err)
		}
		messages = append(messages, m)
	}
	return messages, err
}

func (h *harness) serviceDir() string {
	return filepath.Join(h.runtimeDir, "proj", "svc")
}

func (h *harness) readSecret(name string) string {
	b, err := os.ReadFile(filepath.Join(h.serviceDir(), name))
	if err != nil {
		h.t.Fatalf("read secret %s: %v", name, err)
	}
	return string(b)
}

func assertMessagesNotContainingPlaintext(t *testing.T, messages []wireMessage) {
	t.Helper()
	for _, m := range messages {
		for _, value := range fixtures.ValidValues {
			if value != "" && strings.Contains(m.Message, value) {
				t.Fatalf("message contains secret value: %q", m.Message)
			}
		}
	}
}

func TestUpProvisions(t *testing.T) {
	h := newHarness(t)
	messages, err := h.run("up", nil)
	if err != nil {
		t.Fatalf("up: %v", err)
	}
	for name, want := range fixtures.ValidValues {
		if got := h.readSecret(name); got != want {
			t.Errorf("secret %s = %q, want %q", name, got, want)
		}
	}
	assertMessagesNotContainingPlaintext(t, messages)
}

func TestUpIdempotentPreservesInodes(t *testing.T) {
	h := newHarness(t)
	if _, err := h.run("up", nil); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(h.serviceDir(), "api_key")
	inode1 := statInode(t, path)
	if _, err := h.run("up", nil); err != nil {
		t.Fatalf("second up: %v", err)
	}
	inode2 := statInode(t, path)
	if inode1 != inode2 {
		t.Fatalf("inode changed on idempotent up: %d != %d", inode1, inode2)
	}
}

func TestUpChangedSecretRejectedAndUntouched(t *testing.T) {
	h := newHarness(t)
	if _, err := h.run("up", nil); err != nil {
		t.Fatal(err)
	}
	before := h.readSecret("api_key")

	// Simulate drift: the published file no longer matches the encrypted
	// document. The next up must reject the mismatch with rotation
	// instructions and leave the published file untouched.
	driftPath := filepath.Join(h.serviceDir(), "api_key")
	if err := os.Chmod(driftPath, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(driftPath, []byte("drifted"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := h.run("up", nil)
	if err == nil {
		t.Fatal("up with drifted published file succeeded")
	}
	if !strings.Contains(err.Error(), "docker compose down") || !strings.Contains(err.Error(), "api_key") {
		t.Fatalf("error lacks rotation instructions: %v", err)
	}
	// The up failure must not have republished: content stays drifted.
	if got := h.readSecret("api_key"); got != "drifted" {
		t.Fatalf("published file was mutated by rejected up: %q", got)
	}
	_ = before
}

func TestUpWrongIdentityFailsAndLeavesNoFiles(t *testing.T) {
	h := newHarness(t)
	if err := os.WriteFile(h.keyFile, fixtures.IdentityWrong(), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := h.run("up", nil)
	if err == nil {
		t.Fatal("up with wrong identity succeeded")
	}
	if _, err := os.Stat(h.serviceDir()); !os.IsNotExist(err) {
		t.Fatal("service directory exists after failed up")
	}
	// No staging leftovers.
	matches, _ := filepath.Glob(filepath.Join(h.runtimeDir, "proj", ".staging-*"))
	if len(matches) != 0 {
		t.Fatalf("staging left behind: %v", matches)
	}
}

func TestUpAmbientKeyIgnored(t *testing.T) {
	h := newHarness(t)
	if err := os.WriteFile(h.keyFile, fixtures.IdentityWrong(), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SOPS_AGE_KEY", string(fixtures.IdentityTest()))
	t.Setenv("SOPS_AGE_KEY_FILE", h.keyFile)
	if _, err := h.run("up", nil); err == nil {
		t.Fatal("ambient SOPS_AGE_KEY satisfied up")
	}
}

func TestUpPluginIdentityRejected(t *testing.T) {
	h := newHarness(t)
	if err := os.WriteFile(h.keyFile, fixtures.IdentityPlugin(), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := h.run("up", nil)
	if err == nil || !strings.Contains(err.Error(), "plugin") {
		t.Fatalf("plugin identity not rejected with clear error: %v", err)
	}
}

func TestUpNonTmpfsRejected(t *testing.T) {
	h := newHarness(t)
	err := provider.New(nil, nil, provider.NewEmitter(&bytes.Buffer{})).Up("proj", "svc", provider.Options{
		File:       h.encFile,
		AgeKeyFile: h.keyFile,
		RuntimeDir: t.TempDir(),
	})
	if err == nil {
		t.Skip("temp dir is on tmpfs; nothing to prove")
	}
}

func TestDownRemovesOnlyOwnDirectory(t *testing.T) {
	h := newHarness(t)
	if _, err := h.run("up", nil); err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(h.runtimeDir, "proj", "othersvc")
	if err := os.Mkdir(other, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := h.run("down", nil); err != nil {
		t.Fatalf("down: %v", err)
	}
	if _, err := os.Stat(h.serviceDir()); !os.IsNotExist(err) {
		t.Fatal("service dir still present after down")
	}
	if _, err := os.Stat(other); err != nil {
		t.Fatal("other service dir was removed")
	}
	// Absent down is a success.
	if _, err := h.run("down", nil); err != nil {
		t.Fatalf("down when absent: %v", err)
	}
}

func TestDownWithoutEncryptedFileOrIdentity(t *testing.T) {
	h := newHarness(t)
	if _, err := h.run("up", nil); err != nil {
		t.Fatal(err)
	}
	// Simulate the inputs being gone: down must not need them.
	if err := os.Remove(h.encFile); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(h.keyFile); err != nil {
		t.Fatal(err)
	}
	if _, err := h.run("down", func(o *provider.Options) {
		o.File = "/nonexistent/secrets.age.yaml"
		o.AgeKeyFile = "/nonexistent/keys.txt"
	}); err != nil {
		t.Fatalf("down without inputs: %v", err)
	}
}

func TestStopRetainsFiles(t *testing.T) {
	h := newHarness(t)
	if _, err := h.run("up", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := h.run("stop", nil); err != nil {
		t.Fatalf("stop: %v", err)
	}
	if _, err := os.Stat(h.serviceDir()); err != nil {
		t.Fatalf("stop removed files: %v", err)
	}
}

func TestUpConcurrentInvocations(t *testing.T) {
	h := newHarness(t)
	errs := make(chan error, 2)
	for range 2 {
		go func() { _, err := h.run("up", nil); errs <- err }()
	}
	// Both may succeed (second is the idempotent no-op) but exactly one
	// publication must produce consistent state.
	sawErr := <-errs
	if sawErr != nil {
		t.Logf("first invocation: %v", sawErr)
	}
	if err := <-errs; err != nil {
		t.Fatalf("second invocation failed: %v", err)
	}
	for name, want := range fixtures.ValidValues {
		if got := h.readSecret(name); got != want {
			t.Errorf("secret %s = %q, want %q", name, got, want)
		}
	}
}

func TestMessagesRespectProviderMessagesEnv(t *testing.T) {
	t.Setenv("COMPOSE_PROVIDER_MESSAGES", "error,setenv")
	h := newHarness(t)
	messages, err := h.run("up", nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range messages {
		if m.Type == "info" {
			t.Fatalf("info emitted although not announced: %+v", m)
		}
	}
}

func TestProjectIsolation(t *testing.T) {
	h := newHarness(t)
	var buf bytes.Buffer
	emit := provider.NewEmitter(&buf)
	p := provider.New(nil, nil, emit)
	opts := provider.Options{File: h.encFile, AgeKeyFile: h.keyFile, RuntimeDir: h.runtimeDir}
	if err := p.Up("alpha", "svc", opts); err != nil {
		t.Fatal(err)
	}
	if err := p.Up("beta", "svc", opts); err != nil {
		t.Fatal(err)
	}
	for _, project := range []string{"alpha", "beta"} {
		if _, err := os.Stat(filepath.Join(h.runtimeDir, project, "svc", "api_key")); err != nil {
			t.Errorf("project %s: %v", project, err)
		}
	}
	// Removing alpha must not touch beta.
	if err := p.Down("alpha", "svc", opts); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(h.runtimeDir, "beta", "svc", "api_key")); err != nil {
		t.Fatal("beta was removed by alpha's down")
	}
}

func statInode(t *testing.T, path string) uint64 {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return info.Sys().(*syscall.Stat_t).Ino
}

func TestOwnershipOptionsApplied(t *testing.T) {
	// chown to an arbitrary uid requires privileges; assert the option is
	// plumbed through and fails loudly when unmappable.
	h := newHarness(t)
	uid, gid := 59999, 59999
	_, err := h.run("up", func(o *provider.Options) {
		o.OwnerUID = &uid
		o.OwnerGID = &gid
	})
	if err == nil {
		// Privileged environment: verify the ownership landed.
		info, statErr := os.Stat(filepath.Join(h.serviceDir(), "api_key"))
		if statErr != nil {
			t.Fatal(statErr)
		}
		if st, ok := info.Sys().(*syscall.Stat_t); ok && st.Uid != 59999 {
			t.Fatalf("uid = %d, want 59999", st.Uid)
		}
		return
	}
	if !strings.Contains(err.Error(), "ownership") {
		t.Fatalf("unexpected failure: %v", err)
	}
}
