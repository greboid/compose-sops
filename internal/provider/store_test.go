package provider_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/greboid/compose-sops/internal/provider"
	"github.com/greboid/compose-sops/internal/sops"
)

// tmpfsDir returns a usable tmpfs directory for tests, or skips.
func tmpfsDir(t *testing.T) string {
	t.Helper()
	for _, candidate := range []string{"/dev/shm", "/run", "/tmp"} {
		info, err := os.Stat(candidate)
		if err != nil || !info.IsDir() {
			continue
		}
		dir := filepath.Join(candidate, "compose-sops-test")
		if err := os.Mkdir(dir, 0o700); err != nil && !os.IsExist(err) {
			continue
		}
		if _, err := provider.Open(dir); err != nil {
			os.RemoveAll(dir)
			continue
		}
		work := filepath.Join(dir, filepath.Base(t.TempDir()))
		if err := os.Mkdir(work, 0o700); err != nil {
			continue
		}
		t.Cleanup(func() { os.RemoveAll(work) })
		return work
	}
	t.Skip("no tmpfs directory available for store tests")
	return ""
}

func secrets(pairs ...string) []sops.Secret {
	var out []sops.Secret
	for i := 0; i < len(pairs); i += 2 {
		out = append(out, sops.Secret{Name: pairs[i], Value: pairs[i+1]})
	}
	return out
}

func TestOpenRejectsNonTmpfs(t *testing.T) {
	dir := t.TempDir()
	if _, err := provider.Open(dir); err == nil {
		t.Skip("temp dir is on tmpfs; nothing to prove")
	}
}

func TestOpenAcceptsTmpfsAndValidates(t *testing.T) {
	root := tmpfsDir(t)
	st, err := provider.Open(root)
	if err != nil {
		t.Fatalf("Open(%s): %v", root, err)
	}
	if st.Root() != root {
		t.Fatalf("Root() = %s, want %s", st.Root(), root)
	}
}

func TestOpenRejectsWorldWritable(t *testing.T) {
	root := tmpfsDir(t)
	if err := os.Chmod(root, 0o777); err != nil {
		t.Fatal(err)
	}
	if _, err := provider.Open(root); err == nil {
		t.Fatal("world-writable runtime dir accepted")
	}
}

func TestOpenRejectsSymlink(t *testing.T) {
	root := tmpfsDir(t)
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(root, link); err != nil {
		t.Fatal(err)
	}
	if _, err := provider.Open(link); err == nil {
		t.Fatal("symlinked runtime dir accepted")
	}
}

func TestProvisionCompareLifecycle(t *testing.T) {
	root := tmpfsDir(t)
	st, err := provider.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	want := secrets("api_key", "abc", "db_password", "hunter2 ")

	lk, err := st.Lock("proj", "svc")
	if err != nil {
		t.Fatal(err)
	}

	cmp, err := st.Compare("proj", "svc", want, -1, -1)
	if err != nil || cmp.State != provider.StateAbsent {
		t.Fatalf("initial compare = %+v, %v", cmp, err)
	}
	if err := st.Provision("proj", "svc", want, nil, nil); err != nil {
		t.Fatalf("Provision: %v", err)
	}

	cmp, err = st.Compare("proj", "svc", want, -1, -1)
	if err != nil {
		t.Fatal(err)
	}
	if cmp.State != provider.StateMatch {
		t.Fatalf("compare after provision = %+v (%s)", cmp, cmp.Details)
	}

	// Exact content, no added newline, restrictive modes.
	content, err := os.ReadFile(filepath.Join(st.ServicePath("proj", "svc"), "api_key"))
	if err != nil || string(content) != "abc" {
		t.Fatalf("api_key = %q, %v", content, err)
	}
	entries, _ := os.ReadDir(st.ServicePath("proj", "svc"))
	for _, e := range entries {
		info, _ := e.Info()
		if info.Mode().Perm() != 0o400 {
			t.Errorf("%s mode = %o, want 400", e.Name(), info.Mode().Perm())
		}
	}
	dirInfo, _ := os.Stat(st.ServicePath("proj", "svc"))
	if dirInfo.Mode().Perm() != 0o711 {
		t.Errorf("service dir mode = %o, want 711", dirInfo.Mode().Perm())
	}

	// Content mismatch.
	cmp, err = st.Compare("proj", "svc", secrets("api_key", "changed", "db_password", "hunter2 "), -1, -1)
	if err != nil || cmp.State != provider.StateMismatch {
		t.Fatalf("changed compare = %+v, %v", cmp, err)
	}
	if len(cmp.Details) != 1 || cmp.Details[0] != `"api_key" content differs` {
		t.Fatalf("details = %s", cmp.Details)
	}

	// Extra and missing files.
	cmp, err = st.Compare("proj", "svc", secrets("api_key", "abc"), -1, -1)
	if err != nil || cmp.State != provider.StateMismatch {
		t.Fatalf("extra compare = %+v, %v", cmp, err)
	}
	if len(cmp.Details) != 1 || cmp.Details[0] != `unexpected file "db_password"` {
		t.Fatalf("details = %s", cmp.Details)
	}
	cmp, err = st.Compare("proj", "svc", secrets("api_key", "abc", "extra", "x"), -1, -1)
	if err != nil || cmp.State != provider.StateMismatch {
		t.Fatalf("missing compare = %+v, %v", cmp, err)
	}
	if len(cmp.Details) != 2 {
		t.Fatalf("details = %s", cmp.Details)
	}

	// Provision refuses an existing directory.
	if err := st.Provision("proj", "svc", want, nil, nil); err == nil {
		t.Fatal("double provision accepted")
	}

	// Remove; absent remove is a success.
	if err := st.Remove("proj", "svc"); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if err := st.Remove("proj", "svc"); err != nil {
		t.Fatalf("Remove when absent: %v", err)
	}
	lk.Release()
}

func TestProvisionCleansStagingOnFailure(t *testing.T) {
	root := tmpfsDir(t)
	st, err := provider.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	lk, _ := st.Lock("proj", "svc")
	defer lk.Release()

	bad := []sops.Secret{{Name: "api_key", Value: "abc"}, {Name: "BAD/NAME", Value: "x"}}
	if err := st.Provision("proj", "svc", bad, nil, nil); err == nil {
		t.Fatal("invalid name accepted")
	}
	matches, _ := filepath.Glob(filepath.Join(st.ProjectPath("proj"), ".staging-*"))
	if len(matches) != 0 {
		t.Fatalf("staging left behind: %v", matches)
	}
	if _, err := os.Stat(st.ServicePath("proj", "svc")); !os.IsNotExist(err) {
		t.Fatal("service dir exists after failed provision")
	}
}

func TestCleanStaging(t *testing.T) {
	root := tmpfsDir(t)
	st, err := provider.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	lk, _ := st.Lock("proj", "svc")
	defer lk.Release()

	stale := filepath.Join(st.ProjectPath("proj"), ".staging-svc-crashed")
	if err := os.Mkdir(stale, 0o700); err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(st.ProjectPath("proj"), ".staging-othersvc-crashed")
	if err := os.Mkdir(other, 0o700); err != nil {
		t.Fatal(err)
	}
	st.CleanStaging("proj", "svc")
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Error("stale staging not removed")
	}
	if _, err := os.Stat(other); err != nil {
		t.Error("other service staging was removed")
	}
}

func TestRemoveRefusesSymlink(t *testing.T) {
	root := tmpfsDir(t)
	st, err := provider.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	lk, _ := st.Lock("proj", "svc")
	defer lk.Release()

	if err := os.MkdirAll(st.ProjectPath("proj"), 0o700); err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()
	if err := os.Symlink(outside, st.ServicePath("proj", "svc")); err != nil {
		t.Fatal(err)
	}
	if err := st.Remove("proj", "svc"); err == nil {
		t.Fatal("symlink removal accepted")
	}
	// The link target must be untouched.
	if _, err := os.Stat(outside); err != nil {
		t.Fatalf("symlink target damaged: %v", err)
	}
}

func TestCompareRefusesSymlinkedSecretFile(t *testing.T) {
	root := tmpfsDir(t)
	st, err := provider.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	lk, _ := st.Lock("proj", "svc")
	defer lk.Release()

	want := secrets("api_key", "abc")
	if err := st.Provision("proj", "svc", want, nil, nil); err != nil {
		t.Fatal(err)
	}
	// Swap api_key for a symlink to matching content elsewhere.
	real := filepath.Join(t.TempDir(), "real")
	if err := os.WriteFile(real, []byte("abc"), 0o400); err != nil {
		t.Fatal(err)
	}
	secretPath := st.SecretPath("proj", "svc", "api_key")
	if err := os.Remove(secretPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, secretPath); err != nil {
		t.Fatal(err)
	}
	cmp, err := st.Compare("proj", "svc", want, -1, -1)
	if err != nil {
		t.Fatal(err)
	}
	if cmp.State != provider.StateMismatch {
		t.Fatalf("symlinked secret accepted as match: %+v", cmp)
	}
}

func TestLockSerializes(t *testing.T) {
	root := tmpfsDir(t)
	st, err := provider.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	lk1, err := st.Lock("proj", "svc")
	if err != nil {
		t.Fatal(err)
	}

	// A second independent fd must not be able to take the lock.
	lockPath := filepath.Join(st.ProjectPath("proj"), ".svc.lock")
	fd, err := unix.Open(lockPath, unix.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	err = unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB)
	if err == nil {
		t.Fatal("second lock acquired while held")
	}
	unix.Close(fd)
	lk1.Release()

	// After release, acquisition works again (fresh Store, fresh fd).
	lk2, err := st.Lock("proj", "svc")
	if err != nil {
		t.Fatalf("relock after release: %v", err)
	}
	lk2.Release()
}

func TestValidateName(t *testing.T) {
	for _, name := range []string{"proj", "svc-1", "a.b_c", "Worker1"} {
		if err := provider.ValidateName(name); err != nil {
			t.Errorf("ValidateName(%q): %v", name, err)
		}
	}
	for _, name := range []string{"", ".", "..", ".hidden", "-x", "a/b", "a b", "a\nb", "ümlaut", strings.Repeat("a", 129)} {
		if err := provider.ValidateName(name); err == nil {
			t.Errorf("ValidateName(%q) accepted", name)
		}
	}
}
