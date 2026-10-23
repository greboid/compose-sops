package cli_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/greboid/compose-sops/internal/cli"
	"github.com/greboid/compose-sops/internal/sops"
)

func TestRunKeygenPromptsForOutputPath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "key.txt")
	var stdout, stderr strings.Builder
	cmd, err := cli.Parse([]string{"keygen"})
	if err != nil {
		t.Fatal(err)
	}
	if err := cli.RunKeygen(cmd, &stdout, &stderr, strings.NewReader(path+"\n")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("key not written: %v", err)
	}
	if !strings.Contains(stdout.String(), "recipient: age1") {
		t.Fatalf("stdout = %q", stdout.String())
	}
	if !strings.Contains(stderr.String(), "Output path for the new age key") {
		t.Fatalf("prompt did not show on stderr: %q", stderr.String())
	}
}

func TestRunKeygenFailsWithoutInteractiveInput(t *testing.T) {
	var stdout, stderr strings.Builder
	cmd, err := cli.Parse([]string{"keygen"})
	if err != nil {
		t.Fatal(err)
	}
	err = cli.RunKeygen(cmd, &stdout, &stderr, strings.NewReader(""))
	if err == nil {
		t.Fatal("expected error when stdin cannot answer the prompt")
	}
	if !strings.Contains(err.Error(), "--output") {
		t.Fatalf("error should mention --output: %v", err)
	}
}

func TestRunUnitPrintsToStdoutAndWritesOutput(t *testing.T) {
	var stdout strings.Builder
	cmd, err := cli.Parse([]string{"unit", "/etc/compose-sops/key.cred"})
	if err != nil {
		t.Fatal(err)
	}
	if err := cli.RunUnit(cmd, &stdout); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout.String(), "systemd-creds decrypt") {
		t.Fatalf("stdout = %q", stdout.String())
	}

	outPath := filepath.Join(t.TempDir(), "unit.service")
	cmd, err = cli.Parse([]string{"unit", "--output", outPath, "/etc/compose-sops/key.cred"})
	if err != nil {
		t.Fatal(err)
	}
	if err := cli.RunUnit(cmd, &strings.Builder{}); err != nil {
		t.Fatal(err)
	}
	unit, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(unit) != stdout.String() {
		t.Fatal("--output file differs from stdout rendering")
	}
}

func TestRunEncryptRoundTripsThroughProviderDecrypt(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "key.txt")
	if _, err := sops.GenerateKey(keyPath); err != nil {
		t.Fatal(err)
	}
	input := filepath.Join(dir, "secrets.yaml")
	if err := os.WriteFile(input, []byte("db_password: hunter2\ntoken: \"multi\\nline\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(dir, "secrets.sops.yaml")

	cmd, err := cli.Parse([]string{"encrypt", "--key-file", keyPath, "--output", output, input})
	if err != nil {
		t.Fatal(err)
	}
	var stdout strings.Builder
	if err := cli.RunEncrypt(cmd, &stdout); err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(output)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("output mode = %v, want 0600", info.Mode().Perm())
	}
	encrypted, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encrypted), "hunter2") {
		t.Fatal("ciphertext contains plaintext value")
	}

	identities, err := sops.LoadIdentities(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	secrets, err := sops.NewDecryptor(identities, sops.DefaultLimits).DecryptYAML(encrypted)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"db_password": "hunter2", "token": "multi\nline"}
	if len(secrets) != len(want) {
		t.Fatalf("got %d secrets, want %d", len(secrets), len(want))
	}
	for _, secret := range secrets {
		if want[secret.Name] != secret.Value {
			t.Fatalf("secret %q = %q", secret.Name, secret.Value)
		}
	}
}

func TestRunEncryptRejectsMissingKeyFile(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "in.yaml")
	if err := os.WriteFile(input, []byte("a: b\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd, err := cli.Parse([]string{"encrypt", "--output", filepath.Join(dir, "out.yaml"), input})
	if err != nil {
		t.Fatal(err)
	}
	if err := cli.RunEncrypt(cmd, &strings.Builder{}); err == nil {
		t.Fatal("expected error for missing default key file")
	}
}
