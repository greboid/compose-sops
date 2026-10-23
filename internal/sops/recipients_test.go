package sops_test

import (
	"testing"

	"filippo.io/age"

	"github.com/greboid/compose-sops/internal/fixtures"
	"github.com/greboid/compose-sops/internal/sops"
)

// recipientsToStrings returns the bech32 forms of parsed recipients.
func recipientsToStrings(t *testing.T, path string) []string {
	t.Helper()
	recipients, err := sops.Recipients(path)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, r := range recipients {
		out = append(out, r.String())
	}
	return out
}

// fixtureRecipient derives the public recipient of the test identity file.
func fixtureRecipient(t *testing.T) string {
	t.Helper()
	ids, err := sops.LoadIdentities(writeTemp(t, "k.txt", fixtures.IdentityTest()))
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 1 {
		t.Fatalf("fixture has %d identities", len(ids))
	}
	x25519, ok := ids[0].(*age.X25519Identity)
	if !ok {
		t.Fatalf("fixture identity is %T", ids[0])
	}
	return x25519.Recipient().String()
}

func TestRecipientsFromIdentityFile(t *testing.T) {
	want := fixtureRecipient(t)
	got := recipientsToStrings(t, writeTemp(t, "k.txt", fixtures.IdentityTest()))
	if len(got) != 1 || got[0] != want {
		t.Fatalf("recipients = %v, want [%s]", got, want)
	}
}

func TestRecipientsFromRecipientLine(t *testing.T) {
	recipient := fixtureRecipient(t)
	got := recipientsToStrings(t, writeTemp(t, "r.txt", []byte(recipient+"\n")))
	if len(got) != 1 || got[0] != recipient {
		t.Fatalf("recipients = %v, want [%s]", got, recipient)
	}
}

func TestRecipientsDeduplicates(t *testing.T) {
	recipient := fixtureRecipient(t)
	got := recipientsToStrings(t, writeTemp(t, "r.txt", []byte(recipient+"\n"+recipient+"\n")))
	if len(got) != 1 {
		t.Fatalf("recipients = %v, want 1 after dedup", got)
	}
}

func TestRecipientsMixedLines(t *testing.T) {
	recipient := fixtureRecipient(t)
	content := []byte("# comment\n\n" + recipient + "\n")
	got := recipientsToStrings(t, writeTemp(t, "r.txt", content))
	if len(got) != 1 || got[0] != recipient {
		t.Fatalf("recipients = %v, want [%s]", got, recipient)
	}
}

func TestRecipientsRejectsPluginAndSSH(t *testing.T) {
	for name, content := range map[string][]byte{
		"plugin":  fixtures.IdentityPlugin(),
		"ssh":     fixtures.IdentitySSH(),
		"empty":   fixtures.IdentityEmpty(),
		"garbage": []byte("not an age line\n"),
	} {
		if _, err := sops.Recipients(writeTemp(t, "k.txt", content)); err == nil {
			t.Fatalf("%s: expected rejection", name)
		}
	}
}

func TestRecipientsRejectsMissingFile(t *testing.T) {
	if _, err := sops.Recipients("/nonexistent/compose-sops-test-key"); err == nil {
		t.Fatal("expected error for missing file")
	}
}
