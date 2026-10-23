package cli_test

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/greboid/compose-sops/internal/cli"
	"github.com/greboid/compose-sops/internal/sops"
	"github.com/greboid/compose-sops/internal/system"
)

// fakeCreds serves io.systemd.Credentials.Encrypt replies on a unix socket
// and records the plaintext it was asked to seal.
type fakeCreds struct {
	listener  net.Listener
	sealed    []byte
	gotMethod string
}

func newFakeCreds(t *testing.T) *fakeCreds {
	t.Helper()
	dir, err := os.MkdirTemp("", "wizard-creds")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	path := filepath.Join(dir, "creds.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	f := &fakeCreds{listener: ln}
	go f.serve()
	return f
}

func (f *fakeCreds) serve() {
	for {
		conn, err := f.listener.Accept()
		if err != nil {
			return
		}
		go func() {
			defer conn.Close()
			line, err := bufio.NewReader(conn).ReadBytes('\x00')
			if err != nil {
				return
			}
			var call struct {
				Method     string          `json:"method"`
				Parameters json.RawMessage `json:"parameters"`
			}
			if err := json.Unmarshal(line[:len(line)-1], &call); err != nil {
				return
			}
			f.gotMethod = call.Method
			if call.Method != "io.systemd.Credentials.Encrypt" {
				fmt.Fprintf(conn, `{"error":"org.varlink.service.MethodNotFound","parameters":{"method":%q}}`+"\x00", call.Method)
				return
			}
			var params struct {
				Data string `json:"data"`
			}
			if err := json.Unmarshal(call.Parameters, &params); err != nil {
				return
			}
			plain, err := base64.StdEncoding.DecodeString(params.Data)
			if err != nil {
				return
			}
			f.sealed = plain
			fmt.Fprintf(conn, `{"parameters":{"blob":%q}}`+"\x00", base64.StdEncoding.EncodeToString([]byte("cred-blob")))
		}()
	}
}

// recordingRunner records host commands; the enable step simulates the unit
// by materializing a copy of the generated key at the runtime key path.
type recordingRunner struct {
	calls      [][2]string
	runtimeKey string
	keyPath    string
}

func (r *recordingRunner) run(ctx context.Context, name string, args ...string) error {
	r.calls = append(r.calls, [2]string{name, strings.Join(args, " ")})
	if name == "systemctl" && len(args) >= 3 && args[0] == "enable" && args[1] == "--now" {
		data, err := os.ReadFile(r.keyPath)
		if err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Dir(r.runtimeKey), 0o700); err != nil {
			return err
		}
		return os.WriteFile(r.runtimeKey, data, 0o400)
	}
	return nil
}

type wizardPaths struct {
	dir         string
	installPath string
	keyPath     string
	credPath    string
	unitPath    string
	runtimeKey  string
	plaintext   string
	encrypted   string
}

func newWizardPaths(t *testing.T) wizardPaths {
	t.Helper()
	dir := t.TempDir()
	return wizardPaths{
		dir:         dir,
		installPath: filepath.Join(dir, "bin", "compose-sops"),
		keyPath:     filepath.Join(dir, "key.txt"),
		credPath:    filepath.Join(dir, "key.cred"),
		unitPath:    filepath.Join(dir, "compose-sops-key.service"),
		runtimeKey:  filepath.Join(dir, "run", "age-key.txt"),
		plaintext:   filepath.Join(dir, "secrets.yaml"),
		encrypted:   filepath.Join(dir, "secrets.sops.yaml"),
	}
}

func runWizard(t *testing.T, extraAnswers func(wizardPaths) []string) (wizardPaths, *fakeCreds, *recordingRunner, string, error) {
	t.Helper()
	paths := newWizardPaths(t)
	if err := os.WriteFile(paths.plaintext, []byte("db_password: hunter2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	fake := newFakeCreds(t)
	runner := &recordingRunner{runtimeKey: paths.runtimeKey, keyPath: paths.keyPath}

	script := strings.Join(append([]string{
		paths.installPath, // global binary path
		paths.keyPath,     // age key output
		paths.credPath,    // credential path
		"host",            // with-key choice
		paths.unitPath,    // unit path
	}, extraAnswers(paths)...), "\n")

	var out strings.Builder
	err := cli.RunSetup(cli.SetupOptions{
		In:          strings.NewReader(script),
		Out:         &out,
		Err:         &strings.Builder{},
		Runner:      runner.run,
		CheckSocket: func() bool { return true },
		NewClient: func() (*system.CredsClient, error) {
			return system.NewCredsClientAt("unix:" + fake.listener.Addr().String()), nil
		},
		RuntimeKey: paths.runtimeKey,
	})
	return paths, fake, runner, out.String(), err
}

func enableAndEncryptAnswers(paths wizardPaths) []string {
	// The last empty entry terminates the final empty line with a newline.
	return []string{
		"y",             // enable and start now
		paths.plaintext, // secrets file to encrypt
		"",              // encrypted output default (<input>.sops.yaml)
		"",
	}
}

func TestWizardFullRun(t *testing.T) {
	paths, fake, runner, out, err := runWizard(t, enableAndEncryptAnswers)
	if err != nil {
		t.Fatalf("wizard failed: %v\n%s", err, out)
	}

	if fake.gotMethod != "io.systemd.Credentials.Encrypt" {
		t.Fatalf("varlink method = %q", fake.gotMethod)
	}

	// Binary installed 0755.
	info, err := os.Stat(paths.installPath)
	if err != nil {
		t.Fatalf("binary not installed: %v", err)
	}
	if info.Mode().Perm() != 0o755 {
		t.Fatalf("binary mode = %v", info.Mode().Perm())
	}

	// Key written 0600 and parseable.
	keyInfo, err := os.Stat(paths.keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if keyInfo.Mode().Perm() != 0o600 {
		t.Fatalf("key mode = %v", keyInfo.Mode().Perm())
	}
	identities, err := sops.LoadIdentities(paths.keyPath)
	if err != nil {
		t.Fatalf("generated key invalid: %v", err)
	}

	// The wizard sealed exactly the generated key material.
	if string(fake.sealed) != string(mustRead(t, paths.keyPath)) {
		t.Fatalf("wizard did not seal the generated key")
	}

	// Credential written 0600, base64 text of the fake blob with newline.
	if got := mustRead(t, paths.credPath); string(got) != base64.StdEncoding.EncodeToString([]byte("cred-blob"))+"\n" {
		t.Fatalf("cred = %q", got)
	}
	if credInfo, err := os.Stat(paths.credPath); err != nil || credInfo.Mode().Perm() != 0o600 {
		t.Fatalf("cred mode: %v (%v)", credInfo, err)
	}

	// Unit installed referencing the injected paths.
	unit := string(mustRead(t, paths.unitPath))
	if !strings.Contains(unit, paths.credPath) || !strings.Contains(unit, paths.runtimeKey) {
		t.Fatalf("unit does not reference the injected paths:\n%s", unit)
	}

	// systemctl was driven; enable happened after daemon-reload.
	if len(runner.calls) != 2 ||
		runner.calls[0] != [2]string{"systemctl", "daemon-reload"} ||
		runner.calls[1][0] != "systemctl" || !strings.HasPrefix(runner.calls[1][1], "enable --now ") {
		t.Fatalf("runner calls = %v", runner.calls)
	}

	// The runtime key materialized by the "unit" is a valid key file.
	if _, err := sops.LoadIdentities(paths.runtimeKey); err != nil {
		t.Fatalf("runtime key invalid: %v", err)
	}

	// The encrypted secrets file decrypts with the generated key.
	secrets, err := sops.NewDecryptor(identities, sops.DefaultLimits).DecryptYAML(mustRead(t, paths.encrypted))
	if err != nil {
		t.Fatal(err)
	}
	if len(secrets) != 1 || secrets[0].Name != "db_password" || secrets[0].Value != "hunter2" {
		t.Fatalf("secrets = %+v", secrets)
	}

	// No backup key was ever offered.
	if strings.Contains(strings.ToLower(out), "backup") {
		t.Fatalf("wizard transcript offers a backup key:\n%s", out)
	}
}

func TestWizardDeclinesEnableAndEncrypt(t *testing.T) {
	paths, _, runner, out, err := runWizard(t, func(wizardPaths) []string {
		// The last empty entry terminates the final empty line with a newline.
		return []string{"n", "", ""}
	})
	if err != nil {
		t.Fatalf("wizard failed: %v\n%s", err, out)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("systemctl should not run when enable is declined: %v", runner.calls)
	}
	if _, err := os.Stat(paths.encrypted); !os.IsNotExist(err) {
		t.Fatalf("encrypted file should not exist: %v", err)
	}
	if !strings.Contains(out, "systemctl daemon-reload") {
		t.Fatalf("transcript should print manual enable instructions:\n%s", out)
	}
}

func TestWizardFailsWithoutSocket(t *testing.T) {
	var out strings.Builder
	err := cli.RunSetup(cli.SetupOptions{
		In:  strings.NewReader(""),
		Out: &out,
		CheckSocket: func() bool {
			return false
		},
		NewClient: func() (*system.CredsClient, error) {
			t.Fatal("client must not be built when the socket preflight fails")
			return nil, nil
		},
	})
	if err == nil {
		t.Fatal("expected preflight failure without a systemd-creds socket")
	}
	if !strings.Contains(err.Error(), "systemd-creds.socket") {
		t.Fatalf("error = %v", err)
	}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
