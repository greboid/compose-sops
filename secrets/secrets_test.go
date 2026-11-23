package secrets

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/greboid/compose-sops/internal/fixtures"
	"github.com/greboid/compose-sops/internal/provider"
	"github.com/greboid/compose-sops/internal/sops"
)

func writeKey(t *testing.T, identity []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "key.txt")
	if err := os.WriteFile(path, identity, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func recipient(t *testing.T, key string) string {
	t.Helper()
	r, err := Recipients(key)
	if err != nil || len(r) != 1 {
		t.Fatal(r, err)
	}
	return r[0]
}

func TestCheck(t *testing.T) {
	key := writeKey(t, fixtures.IdentityTest())
	if err := Check(key, fixtures.ValidDocument()); err != nil {
		t.Fatal(err)
	}
	for name, doc := range map[string][]byte{
		"wrong key": fixtures.WrongKeyDocument(),
		"tampered":  fixtures.TamperedMACDocument(),
		"nested":    fixtures.NestedDocument(),
		"oversized": bytes.Repeat([]byte("x"), MaxDocumentSize+1),
	} {
		if err := Check(key, doc); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if err := Check(writeKey(t, fixtures.IdentityWrong()), fixtures.ValidDocument()); err == nil {
		t.Fatal("decrypted with the wrong key")
	}
}

func TestCompare(t *testing.T) {
	key := writeKey(t, fixtures.IdentityTest())
	doc := fixtures.ValidDocument()
	if state, err := Compare(key, doc, filepath.Join(t.TempDir(), "missing"), "p", "s", -1, -1); err != nil || state != Absent {
		t.Fatal(state, err)
	}
	if _, err := Compare(key, doc, t.TempDir(), "../p", "s", -1, -1); err == nil {
		t.Fatal("accepted an invalid project name")
	}
	dir := tmpfsDir(t)
	if state, err := Compare(key, doc, dir, "p", "s", -1, -1); err != nil || state != Absent {
		t.Fatal(state, err)
	}
	ids, err := sops.LoadIdentities(key)
	if err != nil {
		t.Fatal(err)
	}
	published, err := sops.NewDecryptor(ids, sops.DefaultLimits).DecryptYAML(doc)
	if err != nil {
		t.Fatal(err)
	}
	st, err := provider.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	lk, err := st.Lock("p", "s")
	if err != nil {
		t.Fatal(err)
	}
	err = st.Provision("p", "s", published, nil, nil)
	lk.Release()
	if err != nil {
		t.Fatal(err)
	}
	if state, err := Compare(key, doc, dir, "p", "s", -1, -1); err != nil || state != Unchanged {
		t.Fatal(state, err)
	}
	if err := os.Chmod(st.SecretPath("p", "s", "api_key"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(st.SecretPath("p", "s", "api_key"), []byte("other"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(st.SecretPath("p", "s", "api_key"), 0o400); err != nil {
		t.Fatal(err)
	}
	if state, err := Compare(key, doc, dir, "p", "s", -1, -1); err != nil || state != Changed {
		t.Fatal(state, err)
	}
	for state, want := range map[State]string{Absent: "absent", Unchanged: "unchanged", Changed: "changed"} {
		if state.String() != want {
			t.Errorf("%d: %s", state, state)
		}
	}
}

func TestRekey(t *testing.T) {
	key := writeKey(t, fixtures.IdentityTest())
	other := writeKey(t, fixtures.IdentityWrong())
	doc := fixtures.ValidDocument()
	same, err := Rekey(key, doc, []string{recipient(t, key)}, nil)
	if err != nil || !bytes.Equal(same, doc) {
		t.Fatal("rewrote an unchanged document", err)
	}
	// Adding needs the data key, so the identity must decrypt the document.
	if _, err := Rekey(other, doc, []string{recipient(t, other)}, nil); err == nil {
		t.Fatal("rekeyed without a usable identity")
	}
	added, err := Rekey(key, doc, []string{recipient(t, other)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := Check(other, added); err != nil {
		t.Fatal("added recipient cannot decrypt", err)
	}
	removed, err := Rekey(other, added, nil, []string{recipient(t, key)})
	if err != nil {
		t.Fatal(err)
	}
	if Check(key, removed) == nil || Check(other, removed) != nil {
		t.Fatal("removal did not take effect")
	}
	if _, err := Rekey(key, bytes.Repeat([]byte("x"), MaxDocumentSize+1), nil, nil); err == nil {
		t.Fatal("accepted an oversized document")
	}
}

func TestRecipients(t *testing.T) {
	r := recipient(t, writeKey(t, fixtures.IdentityTest()))
	if !strings.HasPrefix(r, "age1") {
		t.Fatal(r)
	}
	if _, err := Recipients(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("read a missing key file")
	}
}

// tmpfsDir returns a tmpfs directory the provider store accepts, or skips.
func tmpfsDir(t *testing.T) string {
	t.Helper()
	for _, candidate := range []string{"/dev/shm", "/run", "/tmp"} {
		dir, err := os.MkdirTemp(candidate, "compose-sops-secrets-")
		if err != nil {
			continue
		}
		t.Cleanup(func() { os.RemoveAll(dir) })
		if _, err := provider.Open(dir); err == nil {
			return dir
		}
	}
	t.Skip("no tmpfs directory available")
	return ""
}

func TestEncryptDecrypt(t *testing.T) {
	key := writeKey(t, fixtures.IdentityTest())
	got, err := Decrypt(key, fixtures.ValidDocument())
	if err != nil || len(got) != len(fixtures.ValidValues) {
		t.Fatal(got, err)
	}
	for k, v := range fixtures.ValidValues {
		if got[k] != v {
			t.Errorf("%s = %q, want %q", k, got[k], v)
		}
	}
	// A key file of recipient lines encrypts without being able to decrypt.
	recipients := writeKey(t, []byte(recipient(t, key)+"\n"))
	doc, err := Encrypt(recipients, []byte("a: one\nb: \"two \"\n"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Decrypt(recipients, doc); err == nil {
		t.Fatal("decrypted with recipients only")
	}
	if got, err := Decrypt(key, doc); err != nil || len(got) != 2 || got["a"] != "one" || got["b"] != "two " {
		t.Fatal(got, err)
	}
	for name, plain := range map[string][]byte{
		"nested":    []byte("a: {b: c}\n"),
		"oversized": bytes.Repeat([]byte("x"), sops.DefaultLimits.MaxTotalSize+1),
	} {
		if _, err := Encrypt(key, plain); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := Decrypt(writeKey(t, fixtures.IdentityWrong()), fixtures.ValidDocument()); err == nil {
		t.Fatal("decrypted with the wrong key")
	}
}
