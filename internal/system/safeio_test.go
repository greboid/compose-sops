package system_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/greboid/compose-sops/internal/system"
)

func TestReadFileBounded(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "f")
	if err := os.WriteFile(path, []byte("hello"), 0o600); err != nil {
		t.Fatal(err)
	}
	b, err := system.ReadFileBounded(path, 10)
	if err != nil || string(b) != "hello" {
		t.Fatalf("got %q, %v", b, err)
	}
	if _, err := system.ReadFileBounded(path, 2); err == nil || !strings.Contains(err.Error(), "limit") {
		t.Fatalf("oversized read accepted: %v", err)
	}
}

func TestReadFileBoundedRefusesSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "real")
	if err := os.WriteFile(target, []byte("hello"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := system.ReadFileBounded(link, 10); err == nil {
		t.Fatal("symlink accepted")
	}
}

func TestWriteNewFileExclusive(t *testing.T) {
	dir := t.TempDir()
	if err := system.WriteNewFile(dir, "secret", []byte("v"), nil, nil); err != nil {
		t.Fatal(err)
	}
	if err := system.WriteNewFile(dir, "secret", []byte("v2"), nil, nil); err == nil {
		t.Fatal("overwriting write accepted")
	}
	info, err := os.Stat(filepath.Join(dir, "secret"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o400 {
		t.Fatalf("mode = %o, want 400", info.Mode().Perm())
	}
}

func TestCleanNoSymlinks(t *testing.T) {
	dir := t.TempDir()
	clean, err := system.CleanNoSymlinks(dir)
	if err != nil || clean != filepath.Clean(dir) {
		t.Fatalf("got %q, %v", clean, err)
	}
	sub := filepath.Join(dir, "missing")
	if _, err := system.CleanNoSymlinks(sub); err == nil {
		t.Fatal("missing path accepted")
	}
}

func TestCreateNewFileExclusiveAndNoSymlink(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "file")

	f, err := system.CreateNewFile(path, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Write([]byte("data")); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := system.CreateNewFile(path, 0o600); !errors.Is(err, os.ErrExist) {
		t.Fatalf("second create = %v, want ErrExist", err)
	}

	link := filepath.Join(dir, "link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := system.CreateNewFile(link, 0o600); err == nil {
		t.Fatal("symlink final component accepted")
	}
}

func TestCreateNewFileRemoveCleansUp(t *testing.T) {
	path := filepath.Join(t.TempDir(), "file")
	f, err := system.CreateNewFile(path, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	f.Write([]byte("x"))
	f.Close()
	f.Remove()
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("Remove did not delete the file: %v", err)
	}
}

func TestWriteNewPathedCreatesParents(t *testing.T) {
	path := filepath.Join(t.TempDir(), "a", "b", "file")
	if err := system.WriteNewPathed(path, []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "data" {
		t.Fatalf("content = %q", got)
	}
	info, _ := os.Stat(filepath.Dir(path))
	if info.Mode().Perm() != 0o700 {
		t.Fatalf("parent mode = %v, want 0700", info.Mode().Perm())
	}
	if err := system.WriteNewPathed(path, []byte("more"), 0o600); err == nil {
		t.Fatal("expected refusal to overwrite")
	}
}

func TestReplaceFileAtomicallyReplaces(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "file")
	if err := os.WriteFile(path, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := system.ReplaceFile(path, []byte("new"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "new" {
		t.Fatalf("content = %q", got)
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %v, want 0600", info.Mode().Perm())
	}

	link := filepath.Join(dir, "link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if err := system.ReplaceFile(link, []byte("x"), 0o600); err == nil {
		t.Fatal("symlink destination accepted")
	}
}
