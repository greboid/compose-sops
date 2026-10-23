package sops_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/greboid/compose-sops/internal/fixtures"
	"github.com/greboid/compose-sops/internal/sops"
)

func writeTemp(t *testing.T, name string, content []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadValidIdentity(t *testing.T) {
	ids, err := sops.LoadIdentities(writeTemp(t, "k.txt", fixtures.IdentityTest()))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(ids) != 1 {
		t.Fatalf("got %d identities, want 1", len(ids))
	}
}

func TestLoadRejectsPluginIdentity(t *testing.T) {
	_, err := sops.LoadIdentities(writeTemp(t, "k.txt", fixtures.IdentityPlugin()))
	if err == nil {
		t.Fatal("plugin identity accepted")
	}
	if !strings.Contains(err.Error(), "plugin identities are not supported") {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.Contains(err.Error(), "AGE-PLUGIN-YUBICO") {
		t.Fatalf("error leaks identity line contents: %v", err)
	}
}

func TestLoadRejectsSSHIdentity(t *testing.T) {
	_, err := sops.LoadIdentities(writeTemp(t, "k.txt", fixtures.IdentitySSH()))
	if err == nil {
		t.Fatal("SSH identity accepted")
	}
	if !strings.Contains(err.Error(), "SSH") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestLoadRejectsEmptyIdentity(t *testing.T) {
	_, err := sops.LoadIdentities(writeTemp(t, "k.txt", fixtures.IdentityEmpty()))
	if err == nil || !strings.Contains(err.Error(), "no identities") {
		t.Fatalf("empty identity file accepted: %v", err)
	}
}

func TestLoadRejectsGarbageLine(t *testing.T) {
	content := []byte("hello world\n")
	_, err := sops.LoadIdentities(writeTemp(t, "k.txt", content))
	if err == nil || !strings.Contains(err.Error(), "unsupported identity line") {
		t.Fatalf("garbage accepted: %v", err)
	}
}

func TestLoadRejectsMissingFile(t *testing.T) {
	_, err := sops.LoadIdentities(filepath.Join(t.TempDir(), "absent.txt"))
	if err == nil {
		t.Fatal("missing file accepted")
	}
	if !sops.IsSanitized(err) {
		t.Fatalf("error not marked sanitized: %v", err)
	}
}

func TestLoadRejectsSymlinkedFile(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "real.txt")
	if err := os.WriteFile(target, fixtures.IdentityTest(), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.txt")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	_, err := sops.LoadIdentities(link)
	// The kernel resolves the symlink on open; O_NOFOLLOW makes it fail.
	if err == nil {
		t.Fatal("symlinked identity file accepted")
	}
}

func TestLoadInvalidBech32Rejected(t *testing.T) {
	content := []byte("AGE-SECRET-KEY-1QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQSSSSSS\n")
	_, err := sops.LoadIdentities(writeTemp(t, "k.txt", content))
	if err == nil || !strings.Contains(err.Error(), "invalid identity") {
		t.Fatalf("invalid bech32 accepted: %v", err)
	}
	if strings.Contains(err.Error(), "QQQQ") {
		t.Fatalf("error leaks key contents: %v", err)
	}
}
