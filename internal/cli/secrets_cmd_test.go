package cli_test

import (
	"bytes"
	"encoding/json"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/greboid/compose-sops/internal/cli"
	"github.com/greboid/compose-sops/internal/fixtures"
)

func keyFile(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "key.txt")
	if err := os.WriteFile(path, fixtures.IdentityTest(), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestParseSecretCommands(t *testing.T) {
	for _, args := range [][]string{
		{"check"},
		{"check", "--project", "p", "-"},
		{"rekey"},
		{"recipient", "extra"},
		{"encrypt", "--add", "age1x", "--output", "o", "in"},
		{"rekey", "--state", "/r", "-"},
		{"decrypt"},
		{"decrypt", "--add", "age1x", "-"},
	} {
		if _, err := cli.Parse(args); err == nil {
			t.Errorf("%v: expected error", args)
		}
	}
	cmd, err := cli.Parse([]string{"rekey", "--add", "a, b", "--remove", "c", "-"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(cmd.Add, "|") != "a|b" || strings.Join(cmd.Remove, "|") != "c" || cmd.Input != "-" {
		t.Fatalf("parsed = %+v", cmd)
	}
}

func run(t *testing.T, args []string, stdin []byte) (string, error) {
	t.Helper()
	cmd, err := cli.Parse(args)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	switch cmd.Name {
	case "recipient":
		err = cli.RunRecipient(cmd, &out)
	case "check":
		err = cli.RunCheck(cmd, &out, bytes.NewReader(stdin))
	case "rekey":
		err = cli.RunRekey(cmd, &out, bytes.NewReader(stdin))
	case "decrypt":
		err = cli.RunDecrypt(cmd, &out, bytes.NewReader(stdin))
	}
	return out.String(), err
}

func TestSecretCommands(t *testing.T) {
	key := keyFile(t)
	recipient, err := run(t, []string{"recipient", "--key-file", key}, nil)
	if err != nil || !strings.HasPrefix(recipient, "age1") {
		t.Fatalf("recipient = %q, %v", recipient, err)
	}
	doc := fixtures.ValidDocument()
	if out, err := run(t, []string{"check", "--key-file", key, "-"}, doc); err != nil || out != "valid\n" {
		t.Fatalf("check = %q, %v", out, err)
	}
	if _, err := run(t, []string{"check", "--key-file", key, "-"}, fixtures.WrongKeyDocument()); err == nil {
		t.Fatal("check accepted a document for another key")
	}
	if out, err := run(t, []string{"rekey", "--add", strings.TrimSpace(recipient), "-"}, doc); err != nil || out != string(doc) {
		t.Fatalf("unchanged rekey altered the document: %v", err)
	}
	other := filepath.Join(t.TempDir(), "other.txt")
	if err := os.WriteFile(other, fixtures.IdentityWrong(), 0o600); err != nil {
		t.Fatal(err)
	}
	otherRecipient, err := run(t, []string{"recipient", "--key-file", other}, nil)
	if err != nil {
		t.Fatal(err)
	}
	out, err := run(t, []string{"rekey", "--key-file", key, "--add", strings.TrimSpace(otherRecipient), "-"}, doc)
	if err != nil {
		t.Fatal(err)
	}
	if res, err := run(t, []string{"check", "--key-file", other, "-"}, []byte(out)); err != nil || res != "valid\n" {
		t.Fatalf("added recipient cannot decrypt: %q, %v", res, err)
	}
}

func TestDecrypt(t *testing.T) {
	key := keyFile(t)
	out, err := run(t, []string{"decrypt", "--key-file", key, "-"}, fixtures.ValidDocument())
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]string
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatal(err)
	}
	if !maps.Equal(got, fixtures.ValidValues) {
		t.Fatal("decrypted values differ from the fixture")
	}
	if out, err := run(t, []string{"decrypt", "--key-file", key, "-"}, fixtures.WrongKeyDocument()); err == nil || out != "" {
		t.Fatalf("decrypt accepted a document for another key: %q", out)
	}
	if out, err := run(t, []string{"decrypt", "--key-file", key, "-"}, fixtures.Get("tampered-mac.age.yaml")); err == nil || out != "" {
		t.Fatalf("decrypt accepted a tampered document: %q", out)
	}
}
