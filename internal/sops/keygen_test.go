package sops_test

import (
	"os"
	"path/filepath"
	"testing"

	"filippo.io/age"

	"github.com/greboid/compose-sops/internal/sops"
)

func TestGenerateWritesValidIdentityFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "dir", "key.txt")
	recipient, err := sops.GenerateKey(path)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %v, want 0600", info.Mode().Perm())
	}
	dirInfo, err := os.Stat(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	if dirInfo.Mode().Perm() != 0o700 {
		t.Fatalf("parent mode = %v, want 0700", dirInfo.Mode().Perm())
	}

	// The file loads as an age identity file and its recipient matches.
	ids, err := sops.LoadIdentities(path)
	if err != nil {
		t.Fatalf("generated key does not load: %v", err)
	}
	if len(ids) != 1 {
		t.Fatalf("got %d identities", len(ids))
	}
	x25519, ok := ids[0].(*age.X25519Identity)
	if !ok {
		t.Fatalf("identity is %T", ids[0])
	}
	if x25519.Recipient().String() != recipient {
		t.Fatalf("recipient = %s, want %s", recipient, x25519.Recipient().String())
	}
}

func TestGenerateRefusesOverwrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "key.txt")
	if _, err := sops.GenerateKey(path); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sops.GenerateKey(path); err == nil {
		t.Fatal("expected error for existing file")
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("existing key was modified")
	}
}

func TestGenerateKeysDecryptEachOther(t *testing.T) {
	// Two independently generated keys have distinct recipients.
	first, err := sops.GenerateKey(filepath.Join(t.TempDir(), "a.txt"))
	if err != nil {
		t.Fatal(err)
	}
	second, err := sops.GenerateKey(filepath.Join(t.TempDir(), "b.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("two generations produced the same recipient")
	}
}
