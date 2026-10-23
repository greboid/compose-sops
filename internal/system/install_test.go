package system_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/greboid/compose-sops/internal/system"
)

func TestInstallCopiesSelf(t *testing.T) {
	dest := filepath.Join(t.TempDir(), "nested", "dir", "compose-sops")
	src, err := system.InstallBinary(dest)
	if err != nil {
		t.Fatal(err)
	}
	if src != dest {
		// src is the running test binary; it must exist and be regular.
		info, err := os.Stat(src)
		if err != nil || !info.Mode().IsRegular() {
			t.Fatalf("source %s: %v", src, err)
		}
	}
	info, err := os.Stat(dest)
	if err != nil {
		t.Fatalf("binary not installed: %v", err)
	}
	if info.Mode().Perm() != 0o755 {
		t.Fatalf("mode = %v, want 0755", info.Mode().Perm())
	}

	// Same content as the source binary.
	want, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(dest)
	if err != nil {
		t.Fatal(err)
	}
	if string(want) != string(got) {
		t.Fatal("installed binary differs from the running binary")
	}
}

func TestInstallOverwritesExisting(t *testing.T) {
	dest := filepath.Join(t.TempDir(), "compose-sops")
	if err := os.WriteFile(dest, []byte("stale"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := system.InstallBinary(dest); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(dest)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) == "stale" {
		t.Fatal("existing binary was not replaced")
	}
}

func TestInstallRefusesSymlinkDestination(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := system.InstallBinary(link); err == nil {
		t.Fatal("expected refusal to replace a symlink destination")
	}
}
