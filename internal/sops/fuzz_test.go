package sops_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
	"go.yaml.in/yaml/v3"

	"github.com/greboid/compose-sops/internal/fixtures"
	"github.com/greboid/compose-sops/internal/sops"
)

func fixtureIdentities(tb testing.TB) []age.Identity {
	tb.Helper()
	id, err := age.ParseIdentities(strings.NewReader(string(fixtures.IdentityTest())))
	if err != nil {
		tb.Fatal(err)
	}
	return id
}

func FuzzDecryptYAML(f *testing.F) {
	for _, doc := range [][]byte{
		fixtures.ValidDocument(), fixtures.TamperedMACDocument(), fixtures.CorruptedDocument(),
		fixtures.NestedDocument(), fixtures.NonStringDocument(), fixtures.NULDocument(),
	} {
		f.Add(doc)
	}
	ids := fixtureIdentities(f)
	recipient := ids[0].(*age.X25519Identity).Recipient()
	if doc, err := sops.Encrypt([]byte("a: x\nb: \"\"\n"), []*age.X25519Recipient{recipient}, sops.DefaultLimits); err == nil {
		f.Add(doc)
	}
	valid := string(fixtures.ValidDocument())
	f.Fuzz(func(t *testing.T, doc []byte) {
		secrets, err := sops.NewDecryptor(ids, sops.DefaultLimits).DecryptYAML(doc)
		if err != nil {
			if strings.Contains(err.Error(), "hunter2") || strings.Contains(err.Error(), "abc123") {
				t.Fatalf("error leaks a fixture value: %v", err)
			}
			return
		}
		if err := sops.ValidateFlat(secrets, sops.DefaultLimits); err != nil {
			t.Fatalf("accepted secrets fail validation: %v", err)
		}
		// Anything accepted must also be accepted by upstream SOPS with the
		// same values; skip the common case of the unmodified fixture.
		if string(doc) != valid {
			got := map[string]string{}
			for _, s := range secrets {
				got[s.Name] = s.Value
			}
			keyFile := writeTempTB(t, fixtures.IdentityTest())
			assertValues(t, upstreamValues(t, doc, keyFile), got)
		}
	})
}

func FuzzEncryptRoundTrip(f *testing.F) {
	f.Add("api_key", "abc123", "other", "")
	f.Add("a.b-c_d", "line one\nline two\n", "x", "  padded  ")
	f.Add("unicode", "pässwörd-ключ-密钥", "n", "#not a comment: really")
	f.Add("k", "\t\r\n", "k2", "ENC[AES256_GCM,data:,iv:,tag:,type:str]")
	k := newKeyPair(f)
	recipients := []*age.X25519Recipient{k.id.Recipient()}
	f.Fuzz(func(t *testing.T, n1, v1, n2, v2 string) {
		doc := &yaml.Node{Kind: yaml.MappingNode}
		for _, s := range []string{n1, v1, n2, v2} {
			doc.Content = append(doc.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: s})
		}
		plain, err := yaml.Marshal(doc)
		if err != nil {
			return
		}
		encrypted, err := sops.Encrypt(plain, recipients, sops.DefaultLimits)
		if err != nil {
			return
		}
		want := map[string]string{n1: v1, n2: v2}
		assertValues(t, ourValues(t, encrypted, k.identities()), want)
		assertValues(t, upstreamValues(t, encrypted, k.file), want)
		var stored map[string]any
		if err := yaml.Unmarshal(encrypted, &stored); err != nil {
			t.Fatal(err)
		}
		for name, v := range want {
			s, _ := stored[name].(string)
			if (v == "") != (s == "") || (s != "" && !strings.HasPrefix(s, "ENC[AES256_GCM,data:")) {
				t.Fatalf("%q stored as %q", name, s)
			}
		}

		other := newKeyPair(t)
		removed, _, err := sops.Rekey(encrypted, k.identities(), []string{other.recipient()}, []string{k.recipient()}, sops.DefaultLimits)
		if err != nil {
			t.Fatalf("rekey: %v", err)
		}
		assertValues(t, upstreamValues(t, removed, other.file), want)
		if _, err := sops.NewDecryptor(k.identities(), sops.DefaultLimits).DecryptYAML(removed); err == nil {
			t.Fatal("removed recipient still decrypts")
		}
	})
}

func writeTempTB(tb testing.TB, content []byte) string {
	tb.Helper()
	path := filepath.Join(tb.TempDir(), "key.txt")
	if err := os.WriteFile(path, content, 0o600); err != nil {
		tb.Fatal(err)
	}
	return path
}
