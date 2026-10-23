package sops_test

import (
	"os"
	"path/filepath"
	"testing"

	"filippo.io/age"

	"github.com/greboid/compose-sops/internal/sops"
)

func testKeyPath(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "key.txt")
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(id.String()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	keyPath := testKeyPath(t)
	recipients, err := sops.Recipients(keyPath)
	if err != nil {
		t.Fatal(err)
	}

	plaintext := "db_password: hunter2\ntoken: \"line1\\nline2\"\n"
	encrypted, err := sops.Encrypt([]byte(plaintext), "secrets.yaml", recipients, sops.DefaultLimits)
	if err != nil {
		t.Fatal(err)
	}
	if bytesContains(encrypted, []byte("hunter2")) {
		t.Fatalf("ciphertext contains plaintext value")
	}

	identities, err := sops.LoadIdentities(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	secrets, err := sops.NewDecryptor(identities, sops.DefaultLimits).DecryptYAML(encrypted)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"db_password": "hunter2", "token": "line1\nline2"}
	if len(secrets) != len(want) {
		t.Fatalf("got %d secrets, want %d", len(secrets), len(want))
	}
	for _, secret := range secrets {
		if want[secret.Name] != secret.Value {
			t.Fatalf("secret %q = %q, want %q", secret.Name, secret.Value, want[secret.Name])
		}
	}
}

func TestEncryptRejectsAlreadyEncrypted(t *testing.T) {
	keyPath := testKeyPath(t)
	recipients, err := sops.Recipients(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	_, err = sops.Encrypt([]byte("sops:\n  version: 3\n"), "in.yaml", recipients, sops.DefaultLimits)
	if err == nil {
		t.Fatal("expected error for input containing sops metadata key")
	}
}

func TestEncryptRejectsNonFlatDocuments(t *testing.T) {
	keyPath := testKeyPath(t)
	recipients, err := sops.Recipients(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]string{
		"nested":   "outer:\n  inner: value\n",
		"sequence": "list:\n  - a\n",
		"empty":    "# only a comment\n",
		"integer":  "count: 5\n",
	}
	for name, doc := range cases {
		if _, err := sops.Encrypt([]byte(doc), "in.yaml", recipients, sops.DefaultLimits); err == nil {
			t.Fatalf("%s: expected rejection", name)
		}
	}
}

func bytesContains(haystack, needle []byte) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if string(haystack[i:i+len(needle)]) == string(needle) {
			return true
		}
	}
	return false
}
