package sops_test

import (
	"bytes"
	"errors"
	"testing"

	"filippo.io/age"

	"github.com/greboid/compose-sops/internal/fixtures"
	"github.com/greboid/compose-sops/internal/sops"
)

func decrypts(t *testing.T, doc []byte, ids []age.Identity) bool {
	t.Helper()
	secrets, err := sops.NewDecryptor(ids, sops.DefaultLimits).DecryptYAML(doc)
	if err != nil {
		return false
	}
	for _, s := range secrets {
		if fixtures.ValidValues[s.Name] != s.Value {
			t.Fatalf("secret %q changed", s.Name)
		}
	}
	return len(secrets) == len(fixtures.ValidValues)
}

func TestRekeyAddAndRemove(t *testing.T) {
	ids, err := sops.LoadIdentities(writeTemp(t, "key.txt", fixtures.IdentityTest()))
	if err != nil {
		t.Fatal(err)
	}
	other, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	r := other.Recipient().String()
	doc := fixtures.ValidDocument()

	if out, changed, err := sops.Rekey(doc, nil, sops.IdentityRecipients(ids), nil, sops.DefaultLimits); err != nil || changed || !bytes.Equal(out, doc) {
		t.Fatalf("unchanged rekey: changed=%v err=%v", changed, err)
	}
	if _, _, err := sops.Rekey(doc, nil, []string{r}, nil, sops.DefaultLimits); !errors.Is(err, sops.ErrIdentityRequired) {
		t.Fatalf("err = %v, want ErrIdentityRequired", err)
	}
	added, changed, err := sops.Rekey(doc, ids, []string{r}, nil, sops.DefaultLimits)
	if err != nil || !changed {
		t.Fatalf("add: changed=%v err=%v", changed, err)
	}
	if !decrypts(t, added, ids) || !decrypts(t, added, []age.Identity{other}) {
		t.Fatal("both identities must decrypt after adding")
	}
	removed, changed, err := sops.Rekey(added, []age.Identity{other}, nil, sops.IdentityRecipients(ids), sops.DefaultLimits)
	if err != nil || !changed {
		t.Fatalf("remove: changed=%v err=%v", changed, err)
	}
	if decrypts(t, removed, ids) || !decrypts(t, removed, []age.Identity{other}) {
		t.Fatal("removed identity must no longer decrypt")
	}
	if _, _, err := sops.Rekey(removed, []age.Identity{other}, nil, []string{r}, sops.DefaultLimits); err == nil {
		t.Fatal("removing the last recipient must fail")
	}
	if _, _, err := sops.Rekey(doc, ids, []string{"age1bogus"}, nil, sops.DefaultLimits); err == nil {
		t.Fatal("invalid recipient accepted")
	}
}
