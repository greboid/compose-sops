package sops_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/greboid/compose-sops/internal/fixtures"
	"github.com/greboid/compose-sops/internal/sops"
)

func service(t *testing.T, identityFile string) *sops.Decryptor {
	t.Helper()
	ids, err := sops.LoadIdentities(identityFile)
	if err != nil {
		t.Fatalf("identity.Load: %v", err)
	}
	return sops.NewDecryptor(ids, sops.DefaultLimits)
}

func writeIdentity(t *testing.T, content []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "keys.txt")
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestDecryptCLIEncryptedFixture(t *testing.T) {
	svc := service(t, writeIdentity(t, fixtures.IdentityTest()))
	secrets, err := svc.DecryptYAML(fixtures.ValidDocument())
	if err != nil {
		t.Fatalf("DecryptYAML: %v", err)
	}
	if len(secrets) != len(fixtures.ValidValues) {
		t.Fatalf("got %d secrets, want %d", len(secrets), len(fixtures.ValidValues))
	}
	for i, s := range secrets {
		if fixtures.ValidOrder[i] != s.Name {
			t.Errorf("order mismatch at %d: got %q want %q", i, s.Name, fixtures.ValidOrder[i])
		}
		if fixtures.ValidValues[s.Name] != s.Value {
			t.Errorf("secret %q = %q, want %q", s.Name, s.Value, fixtures.ValidValues[s.Name])
		}
	}
}

func TestDecryptMatchesLibraryDecryption(t *testing.T) {
	// The fixture was encrypted by the sops CLI; its exact plaintexts are
	// asserted above. This test pins that both the CLI-produced document and
	// our validation of it agree on all six values, byte for byte.
	svc := service(t, writeIdentity(t, fixtures.IdentityTest()))
	secrets, err := svc.DecryptYAML(fixtures.ValidDocument())
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]string{}
	for _, s := range secrets {
		byName[s.Name] = s.Value
	}
	for name, want := range fixtures.ValidValues {
		if byName[name] != want {
			t.Errorf("%s: library decryption %q != CLI plaintext %q", name, byName[name], want)
		}
	}
}

func TestDecryptWrongIdentityFails(t *testing.T) {
	svc := service(t, writeIdentity(t, fixtures.IdentityWrong()))
	_, err := svc.DecryptYAML(fixtures.ValidDocument())
	if err == nil {
		t.Fatal("decrypted with wrong identity")
	}
}

func TestDecryptIgnoresAmbientEnvironment(t *testing.T) {
	// The correct key is present in every ambient SOPS location; decryption
	// must still fail because only the explicit identity file is used.
	t.Setenv("SOPS_AGE_KEY", string(fixtures.IdentityTest()))
	t.Setenv("SOPS_AGE_KEY_FILE", writeIdentity(t, fixtures.IdentityTest()))
	t.Setenv("SOPS_AGE_KEY_CMD", "cat "+writeIdentity(t, fixtures.IdentityTest()))
	svc := service(t, writeIdentity(t, fixtures.IdentityWrong()))
	_, err := svc.DecryptYAML(fixtures.ValidDocument())
	if err == nil {
		t.Fatal("ambient SOPS_AGE_KEY satisfied decryption")
	}
	if !strings.Contains(err.Error(), "ambient key sources") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDecryptTamperedMACFails(t *testing.T) {
	svc := service(t, writeIdentity(t, fixtures.IdentityTest()))
	_, err := svc.DecryptYAML(fixtures.TamperedMACDocument())
	if err == nil {
		t.Fatal("tampered MAC accepted")
	}
}

func TestDecryptCorruptedCiphertextFails(t *testing.T) {
	svc := service(t, writeIdentity(t, fixtures.IdentityTest()))
	_, err := svc.DecryptYAML(fixtures.CorruptedDocument())
	if err == nil {
		t.Fatal("corrupted ciphertext accepted")
	}
}

func TestDecryptRejectsNonYAML(t *testing.T) {
	svc := service(t, writeIdentity(t, fixtures.IdentityTest()))
	_, err := svc.DecryptYAML([]byte("this is not a sops file"))
	if err == nil {
		t.Fatal("garbage accepted")
	}
}

func TestDecryptErrorsDoNotLeakPlaintext(t *testing.T) {
	svc := service(t, writeIdentity(t, fixtures.IdentityTest()))
	_, err := svc.DecryptYAML(fixtures.NestedDocument())
	if err == nil {
		t.Fatal("nested document accepted")
	}
	if strings.Contains(err.Error(), "nested-secret") {
		t.Fatalf("error leaks decrypted value: %v", err)
	}
}

func TestDecryptRejectsNonAgeMasterKeys(t *testing.T) {
	// Hand-built SOPS document with a PGP key group: the key service must
	// refuse before any key material is touched.
	doc := `unencrypted_value: ENC[AES256_GCM,data:E5cPQzE=,iv:Qg6RXc2oSCVLbfBjRBKgig==,tag:8MILHaYh2ofHKbacD/vecQ==,type:str]
sops:
    pgp:
        - created_at: "2024-01-01T00:00:00Z"
          enc: |
            -----BEGIN PGP MESSAGE-----

            fake
            -----END PGP MESSAGE-----
          fp: ABCDEF0123456789ABCDEF0123456789ABCDEF01
    lastmodified: "2024-01-01T00:00:00Z"
    mac: ENC[AES256_GCM,data:xK5z9P4=,iv:Qg6RXc2oSCVLbfBjRBKgig==,tag:8MILHaYh2ofHKbacD/vecQ==,type:str]
    version: 3.9.0
`
	svc := service(t, writeIdentity(t, fixtures.IdentityTest()))
	_, err := svc.DecryptYAML([]byte(doc))
	if err == nil {
		t.Fatal("PGP key group accepted")
	}
	if !strings.Contains(err.Error(), "only age") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDecryptValidationRejections(t *testing.T) {
	cases := []struct {
		name     string
		document []byte
		wantErr  string
	}{
		{"nested", fixtures.NestedDocument(), "nested"},
		{"nonstring", fixtures.NonStringDocument(), "must be YAML strings"},
		{"nul", fixtures.NULDocument(), "NUL"},
		{"big", fixtures.BigDocument(), "byte limit"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc := service(t, writeIdentity(t, fixtures.IdentityTest()))
			_, err := svc.DecryptYAML(tc.document)
			if err == nil {
				t.Fatalf("%s document accepted", tc.name)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error %q does not mention %q", err, tc.wantErr)
			}
		})
	}
}
