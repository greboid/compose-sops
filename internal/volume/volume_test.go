package volume

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/greboid/compose-sops/internal/fixtures"
	"github.com/greboid/compose-sops/internal/sops"
)

// fakeMounter tracks mounts in memory; unmounting empties the directory as
// a tmpfs unmount would.
type fakeMounter struct {
	mounted map[string]bool
	sealed  map[string]bool
	failErr error
}

func newFake() *fakeMounter {
	return &fakeMounter{mounted: map[string]bool{}, sealed: map[string]bool{}}
}

func (f *fakeMounter) Mount(dir string, size, inodes int) error {
	if f.failErr != nil {
		return f.failErr
	}
	f.mounted[dir] = true
	return nil
}

func (f *fakeMounter) Seal(dir string) error { f.sealed[dir] = true; return nil }

func (f *fakeMounter) Unmount(dir string) error {
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		os.RemoveAll(filepath.Join(dir, e.Name()))
	}
	delete(f.mounted, dir)
	delete(f.sealed, dir)
	return nil
}

func (f *fakeMounter) Mounted(dir string) (bool, error) { return f.mounted[dir], nil }

type env struct {
	t   *testing.T
	cfg Config
	m   *fakeMounter
}

func newEnv(t *testing.T) *env {
	t.Helper()
	base := t.TempDir()
	e := &env{t: t, m: newFake(), cfg: Config{
		Documents: filepath.Join(base, "docs"),
		KeyFile:   filepath.Join(base, "key.txt"),
		StateDir:  filepath.Join(base, "state"),
		MountRoot: filepath.Join(base, "mnt"),
	}}
	e.cfg.Mounter = e.m
	for _, d := range []string{e.cfg.Documents, e.cfg.StateDir} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	e.write("app/secrets.yaml", fixtures.ValidDocument())
	if err := os.WriteFile(e.cfg.KeyFile, fixtures.IdentityTest(), 0o600); err != nil {
		t.Fatal(err)
	}
	return e
}

func (e *env) write(rel string, data []byte) {
	e.t.Helper()
	path := filepath.Join(e.cfg.Documents, rel)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		e.t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		e.t.Fatal(err)
	}
}

func (e *env) driver() *Driver {
	e.t.Helper()
	d, err := New(e.cfg)
	if err != nil {
		e.t.Fatal(err)
	}
	return d
}

func readDir(t *testing.T, dir string) map[string]string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o400 {
			t.Errorf("%s mode %v, want 0400", entry.Name(), info.Mode().Perm())
		}
		b, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		out[entry.Name()] = string(b)
	}
	return out
}

func TestParseOptionsRejects(t *testing.T) {
	for name, opts := range map[string]map[string]string{
		"missing file":  {},
		"absolute":      {"file": "/etc/passwd"},
		"traversal":     {"file": "../x.yaml"},
		"inner dotdot":  {"file": "a/../../x.yaml"},
		"unknown":       {"file": "a.yaml", "mode": "0444"},
		"uid only":      {"file": "a.yaml", "uid": "1"},
		"negative uid":  {"file": "a.yaml", "uid": "-1", "gid": "1"},
		"bad gid":       {"file": "a.yaml", "uid": "1", "gid": "x"},
		"duplicate key": {"file": "a.yaml", "keys": "a,a"},
		"empty keys":    {"file": "a.yaml", "keys": " , "},
	} {
		if _, err := parseOptions(opts); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	rec, err := parseOptions(map[string]string{"file": "a/./b.yaml", "keys": "x, y", "uid": "10", "gid": "20"})
	if err != nil {
		t.Fatal(err)
	}
	if rec.File != "a/b.yaml" || strings.Join(rec.Keys, "|") != "x|y" || *rec.UID != 10 || *rec.GID != 20 {
		t.Fatalf("parsed %+v", rec)
	}
}

func TestValidateName(t *testing.T) {
	for _, ok := range []string{"a", "proj_secrets", "a.b-c"} {
		if err := ValidateName(ok); err != nil {
			t.Errorf("%s: %v", ok, err)
		}
	}
	for _, bad := range []string{"", ".", "..", "-a", "_a", "a/b", strings.Repeat("a", 129)} {
		if err := ValidateName(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestCreateValidatesDocument(t *testing.T) {
	e := newEnv(t)
	d := e.driver()
	e.write("wrong.yaml", fixtures.WrongKeyDocument())
	for name, opts := range map[string]map[string]string{
		"missing document": {"file": "nope.yaml"},
		"wrong key":        {"file": "wrong.yaml"},
		"missing secret":   {"file": "app/secrets.yaml", "keys": "db_password,nope"},
		"directory":        {"file": "app"},
	} {
		if err := d.Create("v", opts); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if len(d.List()) != 0 {
		t.Fatal("failed create left a volume")
	}
	opts := map[string]string{"file": "app/secrets.yaml", "keys": "api_key"}
	if err := d.Create("v", opts); err != nil {
		t.Fatal(err)
	}
	if err := d.Create("v", opts); err != nil {
		t.Fatalf("identical re-create: %v", err)
	}
	if err := d.Create("v", map[string]string{"file": "app/secrets.yaml"}); err == nil {
		t.Fatal("re-create with different options accepted")
	}
}

func TestSymlinksMustStayInsideRoot(t *testing.T) {
	e := newEnv(t)
	outside := filepath.Join(t.TempDir(), "outside.yaml")
	if err := os.WriteFile(outside, fixtures.ValidDocument(), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(e.cfg.Documents, "escape.yaml")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("app/secrets.yaml", filepath.Join(e.cfg.Documents, "inside.yaml")); err != nil {
		t.Fatal(err)
	}
	d := e.driver()
	if err := d.Create("escape", map[string]string{"file": "escape.yaml"}); err == nil {
		t.Fatal("followed a symlink out of the documents root")
	}
	if err := d.Create("inside", map[string]string{"file": "inside.yaml"}); err != nil {
		t.Fatalf("symlink inside the root: %v", err)
	}
}

func TestMountLifecycle(t *testing.T) {
	e := newEnv(t)
	d := e.driver()
	uid, gid := os.Getuid(), os.Getgid()
	if err := d.Create("v", map[string]string{"file": "app/secrets.yaml", "keys": "db_password,multiline",
		"uid": strconv.Itoa(uid), "gid": strconv.Itoa(gid)}); err != nil {
		t.Fatal(err)
	}
	if p, _ := d.Path("v"); p != "" {
		t.Fatalf("path before mount = %q", p)
	}
	mp, err := d.Mount("v", "c1")
	if err != nil {
		t.Fatal(err)
	}
	if mp != filepath.Join(e.cfg.MountRoot, "v") || !e.m.mounted[mp] || !e.m.sealed[mp] {
		t.Fatalf("mountpoint %s mounted=%v sealed=%v", mp, e.m.mounted[mp], e.m.sealed[mp])
	}
	got := readDir(t, mp)
	if len(got) != 2 || got["db_password"] != fixtures.ValidValues["db_password"] || got["multiline"] != fixtures.ValidValues["multiline"] {
		t.Fatalf("published %q", got)
	}

	// A changed document is not applied while the volume is in use.
	e.write("app/secrets.yaml", rotated(t, e))
	if _, err := d.Mount("v", "c2"); err != nil {
		t.Fatal(err)
	}
	if readDir(t, mp)["db_password"] != fixtures.ValidValues["db_password"] {
		t.Fatal("republished underneath an active mount")
	}
	if err := d.Remove("v"); err == nil {
		t.Fatal("removed a volume in use")
	}
	if err := d.Unmount("v", "c1"); err != nil || !e.m.mounted[mp] {
		t.Fatalf("first unmount: %v mounted=%v", err, e.m.mounted[mp])
	}
	if err := d.Unmount("v", "unknown"); err != nil {
		t.Fatalf("unknown ID: %v", err)
	}
	if err := d.Unmount("v", "c2"); err != nil || e.m.mounted[mp] {
		t.Fatalf("last unmount: %v mounted=%v", err, e.m.mounted[mp])
	}
	if _, err := os.Stat(mp); !os.IsNotExist(err) {
		t.Fatalf("mount point left behind: %v", err)
	}

	// The next first mount publishes the current document.
	if _, err := d.Mount("v", "c3"); err != nil {
		t.Fatal(err)
	}
	if readDir(t, mp)["db_password"] != "rotated" {
		t.Fatal("rotation not applied on the next first mount")
	}
}

// rotated returns ValidDocument re-encrypted with db_password changed.
func rotated(t *testing.T, e *env) []byte {
	t.Helper()
	ids, err := sops.LoadIdentities(e.cfg.KeyFile)
	if err != nil {
		t.Fatal(err)
	}
	all, err := sops.NewDecryptor(ids, sops.DefaultLimits).DecryptYAML(fixtures.ValidDocument())
	if err != nil {
		t.Fatal(err)
	}
	var plain bytes.Buffer
	for _, s := range all {
		if s.Name == "db_password" {
			s.Value = "rotated"
		}
		b, _ := json.Marshal(s.Value)
		plain.WriteString(s.Name + ": " + string(b) + "\n")
	}
	recipients, err := sops.Recipients(e.cfg.KeyFile)
	if err != nil {
		t.Fatal(err)
	}
	out, err := sops.Encrypt(plain.Bytes(), recipients, sops.DefaultLimits)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestMountFailsClosed(t *testing.T) {
	e := newEnv(t)
	d := e.driver()
	if err := d.Create("v", map[string]string{"file": "app/secrets.yaml"}); err != nil {
		t.Fatal(err)
	}
	mp := filepath.Join(e.cfg.MountRoot, "v")
	if err := os.Remove(e.cfg.KeyFile); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Mount("v", "c1"); err == nil {
		t.Fatal("mounted without the key")
	}
	if err := os.WriteFile(e.cfg.KeyFile, fixtures.IdentityTest(), 0o600); err != nil {
		t.Fatal(err)
	}
	e.write("app/secrets.yaml", fixtures.TamperedMACDocument())
	if _, err := d.Mount("v", "c1"); err == nil {
		t.Fatal("mounted a tampered document")
	}
	if err := os.Remove(filepath.Join(e.cfg.Documents, "app/secrets.yaml")); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Mount("v", "c1"); err == nil {
		t.Fatal("mounted a missing document")
	}
	if e.m.mounted[mp] {
		t.Fatal("left a mount behind")
	}
	if v, _ := d.Get("v"); v.Mountpoint != "" {
		t.Fatal("failed mount recorded as active")
	}
}

func TestRestartReconciles(t *testing.T) {
	e := newEnv(t)
	d := e.driver()
	for _, name := range []string{"a", "b"} {
		if err := d.Create(name, map[string]string{"file": "app/secrets.yaml"}); err != nil {
			t.Fatal(err)
		}
		if _, err := d.Mount(name, "c1"); err != nil {
			t.Fatal(err)
		}
	}

	// Plugin restart with mounts intact keeps the active IDs.
	d = e.driver()
	if v, _ := d.Get("a"); v.Mountpoint == "" {
		t.Fatal("lost an active mount across a plugin restart")
	}

	// Reboot: nothing is mounted any more.
	for dir := range e.m.mounted {
		_ = e.m.Unmount(dir)
	}
	e.m = newFake()
	e.cfg.Mounter = e.m
	d = e.driver()
	for _, v := range d.List() {
		if v.Mountpoint != "" {
			t.Fatalf("%s still active after reboot", v.Name)
		}
	}
	mp, err := d.Mount("a", "c1")
	if err != nil {
		t.Fatal(err)
	}
	if len(readDir(t, mp)) != len(fixtures.ValidValues) {
		t.Fatal("secrets not regenerated after reboot")
	}
	if err := d.Unmount("a", "c1"); err != nil || e.m.mounted[mp] {
		t.Fatalf("unmount after reboot: %v", err)
	}
	if err := d.Remove("a"); err != nil {
		t.Fatal(err)
	}
	if names := d.List(); len(names) != 1 || names[0].Name != "b" {
		t.Fatalf("list = %+v", names)
	}
	if len(e.driver().List()) != 1 {
		t.Fatal("removal not persisted")
	}
}

func TestStateHasNoSecrets(t *testing.T) {
	e := newEnv(t)
	d := e.driver()
	if err := d.Create("v", map[string]string{"file": "app/secrets.yaml"}); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Mount("v", "c1"); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(e.cfg.StateDir, stateFile))
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range fixtures.ValidValues {
		if len(v) > 3 && bytes.Contains(raw, []byte(v)) {
			t.Fatal("state contains a secret value")
		}
	}
}

func TestHandler(t *testing.T) {
	e := newEnv(t)
	srv := httptest.NewServer(Handler(e.driver()))
	defer srv.Close()
	call := func(op string, body any) (int, map[string]any) {
		t.Helper()
		b, _ := json.Marshal(body)
		resp, err := http.Post(srv.URL+"/"+op, contentType, bytes.NewReader(b))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var out map[string]any
		if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
			t.Fatal(err)
		}
		return resp.StatusCode, out
	}
	if _, out := call("Plugin.Activate", nil); out["Implements"].([]any)[0] != "VolumeDriver" {
		t.Fatalf("activate = %v", out)
	}
	if _, out := call("VolumeDriver.Capabilities", nil); out["Capabilities"].(map[string]any)["Scope"] != "local" {
		t.Fatalf("capabilities = %v", out)
	}
	if code, out := call("VolumeDriver.Create", map[string]any{"Name": "v", "Opts": map[string]string{"file": "app/secrets.yaml", "keys": "api_key"}}); code != 200 {
		t.Fatalf("create = %d %v", code, out)
	}
	if code, out := call("VolumeDriver.Create", map[string]any{"Name": "w", "Opts": map[string]string{}}); code != 500 || out["Err"] == "" {
		t.Fatalf("bad create = %d %v", code, out)
	}
	code, out := call("VolumeDriver.Mount", map[string]any{"Name": "v", "ID": "c1"})
	if code != 200 || out["Mountpoint"] != filepath.Join(e.cfg.MountRoot, "v") {
		t.Fatalf("mount = %d %v", code, out)
	}
	if _, out := call("VolumeDriver.Path", map[string]any{"Name": "v"}); out["Mountpoint"] == "" {
		t.Fatalf("path = %v", out)
	}
	_, out = call("VolumeDriver.Get", map[string]any{"Name": "v"})
	if vol := out["Volume"].(map[string]any); vol["Name"] != "v" || vol["Status"].(map[string]any)["file"] != "app/secrets.yaml" {
		t.Fatalf("get = %v", out)
	}
	if code, _ := call("VolumeDriver.Get", map[string]any{"Name": "nope"}); code != 500 {
		t.Fatal("get of a missing volume succeeded")
	}
	if _, out := call("VolumeDriver.List", nil); len(out["Volumes"].([]any)) != 1 {
		t.Fatalf("list = %v", out)
	}
	if code, out := call("VolumeDriver.Unmount", map[string]any{"Name": "v", "ID": "c1"}); code != 200 {
		t.Fatalf("unmount = %d %v", code, out)
	}
	if code, out := call("VolumeDriver.Remove", map[string]any{"Name": "v"}); code != 200 {
		t.Fatalf("remove = %d %v", code, out)
	}
}

func TestUnescapeMountPath(t *testing.T) {
	if got := unescapeMountPath(`/mnt/a\040b\\`); got != `/mnt/a b\\` {
		t.Fatalf("got %q", got)
	}
}
