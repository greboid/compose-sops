package sops_test

// Interop tests against the upstream SOPS library, which is a test-only
// dependency: documents written by either side must be read by the other.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
	sopsv3 "github.com/getsops/sops/v3"
	"github.com/getsops/sops/v3/aes"
	sopsage "github.com/getsops/sops/v3/age"
	"github.com/getsops/sops/v3/config"
	sopsdecrypt "github.com/getsops/sops/v3/decrypt"
	sopsyaml "github.com/getsops/sops/v3/stores/yaml"
	sopsversion "github.com/getsops/sops/v3/version"
	"go.yaml.in/yaml/v4"

	"github.com/greboid/compose-sops/internal/sops"
)

type keyPair struct {
	id   *age.X25519Identity
	file string
}

func newKeyPair(tb testing.TB) keyPair {
	tb.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		tb.Fatal(err)
	}
	file := filepath.Join(tb.TempDir(), "key.txt")
	if err := os.WriteFile(file, []byte(id.String()+"\n"), 0o600); err != nil {
		tb.Fatal(err)
	}
	return keyPair{id: id, file: file}
}

func (k keyPair) recipient() string { return k.id.Recipient().String() }

func (k keyPair) identities() []age.Identity { return []age.Identity{k.id} }

// useUpstreamKey points the upstream library's ambient key discovery at
// file and nowhere else.
func useUpstreamKey(tb testing.TB, file string) {
	tb.Helper()
	dir := tb.TempDir()
	for k, v := range map[string]string{
		"SOPS_AGE_KEY_FILE": file, "SOPS_AGE_KEY": "", "SOPS_AGE_KEY_CMD": "",
		"SOPS_AGE_SSH_PRIVATE_KEY_FILE": "", "HOME": dir, "XDG_CONFIG_HOME": dir,
	} {
		old, had := os.LookupEnv(k)
		// Upstream panics on SOPS_AGE_KEY_CMD set but empty, so unset instead.
		set := func() error { return os.Setenv(k, v) }
		if v == "" {
			set = func() error { return os.Unsetenv(k) }
		}
		if err := set(); err != nil {
			tb.Fatal(err)
		}
		tb.Cleanup(func() {
			if had {
				os.Setenv(k, old)
			} else {
				os.Unsetenv(k)
			}
		})
	}
}

// upstreamEncrypt encrypts plaintext the way the sops CLI does by default.
func upstreamEncrypt(tb testing.TB, plaintext string, recipients ...string) []byte {
	tb.Helper()
	store := sopsyaml.NewStore(&config.YAMLStoreConfig{})
	branches, err := store.LoadPlainFile([]byte(plaintext))
	if err != nil {
		tb.Fatal(err)
	}
	var group sopsv3.KeyGroup
	for _, r := range recipients {
		group = append(group, &sopsage.MasterKey{Recipient: r})
	}
	tree := sopsv3.Tree{
		Branches: branches,
		Metadata: sopsv3.Metadata{
			Version:           sopsversion.Version,
			KeyGroups:         []sopsv3.KeyGroup{group},
			UnencryptedSuffix: sopsv3.DefaultUnencryptedSuffix,
		},
	}
	dataKey, errs := tree.GenerateDataKey()
	if len(errs) > 0 {
		tb.Fatal(errs)
	}
	cipher := aes.NewCipher()
	mac, err := tree.Encrypt(dataKey, cipher)
	if err != nil {
		tb.Fatal(err)
	}
	tree.Metadata.LastModified = time.Now().UTC()
	tree.Metadata.MessageAuthenticationCode, err = cipher.Encrypt(mac, dataKey, tree.Metadata.LastModified.Format(time.RFC3339))
	if err != nil {
		tb.Fatal(err)
	}
	out, err := store.EmitEncryptedFile(tree)
	if err != nil {
		tb.Fatal(err)
	}
	return out
}

// upstreamAddRecipient is the upstream equivalent of adding a recipient.
func upstreamAddRecipient(tb testing.TB, doc []byte, keyFile, recipient string) []byte {
	tb.Helper()
	useUpstreamKey(tb, keyFile)
	store := sopsyaml.NewStore(&config.YAMLStoreConfig{})
	tree, err := store.LoadEncryptedFile(doc)
	if err != nil {
		tb.Fatal(err)
	}
	dataKey, err := tree.Metadata.GetDataKey()
	if err != nil {
		tb.Fatal(err)
	}
	tree.Metadata.KeyGroups[0] = append(tree.Metadata.KeyGroups[0], &sopsage.MasterKey{Recipient: recipient})
	if errs := tree.Metadata.UpdateMasterKeys(dataKey); len(errs) > 0 {
		tb.Fatal(errs)
	}
	out, err := store.EmitEncryptedFile(tree)
	if err != nil {
		tb.Fatal(err)
	}
	return out
}

// upstreamDecrypt returns the cleartext YAML upstream SOPS produces.
func upstreamDecrypt(tb testing.TB, doc []byte, keyFile string) (string, error) {
	tb.Helper()
	useUpstreamKey(tb, keyFile)
	out, err := sopsdecrypt.Data(doc, "yaml")
	return string(out), err
}

func upstreamValues(tb testing.TB, doc []byte, keyFile string) map[string]string {
	tb.Helper()
	out, err := upstreamDecrypt(tb, doc, keyFile)
	if err != nil {
		tb.Fatalf("upstream decrypt: %v", err)
	}
	var values map[string]string
	if err := yaml.Unmarshal([]byte(out), &values); err != nil {
		tb.Fatal(err)
	}
	return values
}

func ourValues(tb testing.TB, doc []byte, ids []age.Identity) map[string]string {
	tb.Helper()
	secrets, err := sops.NewDecryptor(ids, sops.DefaultLimits).DecryptYAML(doc)
	if err != nil {
		tb.Fatalf("decrypt: %v", err)
	}
	values := map[string]string{}
	for _, s := range secrets {
		values[s.Name] = s.Value
	}
	return values
}

func assertValues(tb testing.TB, got, want map[string]string) {
	tb.Helper()
	if len(got) != len(want) {
		tb.Fatalf("got %d values %v, want %d", len(got), got, len(want))
	}
	for k, v := range want {
		if got[k] != v {
			tb.Fatalf("%s = %q, want %q", k, got[k], v)
		}
	}
}

const interopPlaintext = `# leading comment
api_key: abc123
db_password: "hunter2 "
empty: ""
quoted_number: "0042"
unicode: pässwörd-ключ-密钥
multiline: |
    line one
    line two
spaces: "  padded  "
colon: "a: b # not a comment"
note_unencrypted: visible
# trailing comment
`

var interopValues = map[string]string{
	"api_key":          "abc123",
	"db_password":      "hunter2 ",
	"empty":            "",
	"quoted_number":    "0042",
	"unicode":          "pässwörd-ключ-密钥",
	"multiline":        "line one\nline two\n",
	"spaces":           "  padded  ",
	"colon":            "a: b # not a comment",
	"note_unencrypted": "visible",
}

func withoutUnencrypted(in map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range in {
		if !strings.HasSuffix(k, "_unencrypted") {
			out[k] = v
		}
	}
	return out
}

func TestInteropUpstreamEncryptedDecrypts(t *testing.T) {
	k := newKeyPair(t)
	doc := upstreamEncrypt(t, interopPlaintext, k.recipient())
	if !strings.Contains(string(doc), "note_unencrypted: visible") {
		t.Fatalf("upstream did not leave the suffixed value in plaintext:\n%s", doc)
	}
	assertValues(t, ourValues(t, doc, k.identities()), interopValues)
}

func TestInteropEncryptedReadsUpstream(t *testing.T) {
	k := newKeyPair(t)
	plain := strings.ReplaceAll(interopPlaintext, "note_unencrypted: visible\n", "")
	want := withoutUnencrypted(interopValues)
	recipients := []*age.X25519Recipient{k.id.Recipient()}
	doc, err := sops.Encrypt([]byte(plain), recipients, sops.DefaultLimits)
	if err != nil {
		t.Fatal(err)
	}
	assertValues(t, upstreamValues(t, doc, k.file), want)
	assertValues(t, ourValues(t, doc, k.identities()), want)
}

func TestInteropRekeyAddReadsUpstream(t *testing.T) {
	a, b := newKeyPair(t), newKeyPair(t)
	doc := upstreamEncrypt(t, interopPlaintext, a.recipient())
	added, changed, err := sops.Rekey(doc, a.identities(), []string{b.recipient()}, nil, sops.DefaultLimits)
	if err != nil || !changed {
		t.Fatalf("rekey: changed=%v err=%v", changed, err)
	}
	assertValues(t, upstreamValues(t, added, a.file), interopValues)
	assertValues(t, upstreamValues(t, added, b.file), interopValues)
	assertValues(t, ourValues(t, added, b.identities()), interopValues)
}

func TestInteropRekeyRemoveReadsUpstream(t *testing.T) {
	a, b := newKeyPair(t), newKeyPair(t)
	doc := upstreamEncrypt(t, interopPlaintext, a.recipient(), b.recipient())
	removed, changed, err := sops.Rekey(doc, a.identities(), nil, []string{a.recipient()}, sops.DefaultLimits)
	if err != nil || !changed {
		t.Fatalf("rekey: changed=%v err=%v", changed, err)
	}
	if strings.Contains(string(removed), "leading comment") {
		t.Fatal("encrypted comment written in plaintext")
	}
	assertValues(t, upstreamValues(t, removed, b.file), interopValues)
	assertValues(t, ourValues(t, removed, b.identities()), interopValues)
	out, err := upstreamDecrypt(t, removed, b.file)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []string{"# leading comment", "# trailing comment"} {
		if !strings.Contains(out, c) {
			t.Fatalf("comment %q lost or not re-encrypted under the new data key:\n%s", c, out)
		}
	}
	if _, err := upstreamDecrypt(t, removed, a.file); err == nil {
		t.Fatal("removed recipient can still decrypt with upstream")
	}
}

func TestInteropUpstreamAddedRecipientDecrypts(t *testing.T) {
	a, b := newKeyPair(t), newKeyPair(t)
	plain := strings.ReplaceAll(interopPlaintext, "note_unencrypted: visible\n", "")
	doc, err := sops.Encrypt([]byte(plain), []*age.X25519Recipient{a.id.Recipient()}, sops.DefaultLimits)
	if err != nil {
		t.Fatal(err)
	}
	added := upstreamAddRecipient(t, doc, a.file, b.recipient())
	assertValues(t, ourValues(t, added, b.identities()), withoutUnencrypted(interopValues))
}

func TestInteropUpstreamRejectsSameNonStringValues(t *testing.T) {
	k := newKeyPair(t)
	doc := upstreamEncrypt(t, "port: 8080\n", k.recipient())
	_, err := sops.NewDecryptor(k.identities(), sops.DefaultLimits).DecryptYAML(doc)
	if err == nil || !strings.Contains(err.Error(), "must be YAML strings") {
		t.Fatalf("err = %v", err)
	}
}
