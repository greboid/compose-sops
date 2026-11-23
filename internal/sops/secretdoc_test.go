package sops_test

import (
	"strings"
	"testing"

	"filippo.io/age"

	"github.com/greboid/compose-sops/internal/sops"
)

func flat(pairs ...string) []sops.Secret {
	var out []sops.Secret
	for i := 0; i < len(pairs); i += 2 {
		out = append(out, sops.Secret{Name: pairs[i], Value: pairs[i+1]})
	}
	return out
}

func TestValidateFlatAcceptsStrings(t *testing.T) {
	if err := sops.ValidateFlat(flat("api_key", "abc", "db_password", "hunter2 "), sops.DefaultLimits); err != nil {
		t.Fatal(err)
	}
}

func TestValidateFlatRejectsDuplicates(t *testing.T) {
	err := sops.ValidateFlat(flat("api_key", "one", "api_key", "two"), sops.DefaultLimits)
	if err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("duplicate accepted: %v", err)
	}
}

func TestValidateFlatRejectsInvalidNames(t *testing.T) {
	for _, name := range []string{"", "..", ".", ".hidden", "-dash", "with space", "with/slash", "with\nnewline", strings.Repeat("a", 129)} {
		if err := sops.ValidateFlat(flat(name, "v"), sops.DefaultLimits); err == nil {
			t.Fatalf("name %q accepted", name)
		}
	}
	for _, name := range []string{"a", "A_9", "a.b-c_d", strings.Repeat("a", 128)} {
		if err := sops.ValidateFlat(flat(name, "v"), sops.DefaultLimits); err != nil {
			t.Fatalf("name %q rejected: %v", name, err)
		}
	}
}

func TestValidateFlatRejectsNUL(t *testing.T) {
	err := sops.ValidateFlat(flat("key", "a\x00b"), sops.DefaultLimits)
	if err == nil || !strings.Contains(err.Error(), "NUL") {
		t.Fatalf("NUL accepted: %v", err)
	}
}

func TestValidateFlatEnforcesSizeLimits(t *testing.T) {
	err := sops.ValidateFlat(flat("key", strings.Repeat("x", 64<<10+1)), sops.DefaultLimits)
	if err == nil || !strings.Contains(err.Error(), "byte limit") {
		t.Fatalf("oversized value accepted: %v", err)
	}
	err = sops.ValidateFlat(flat("a", "xx", "b", "xx"), sops.Limits{MaxValueSize: 10, MaxTotalSize: 5})
	if err == nil || !strings.Contains(err.Error(), "total size") {
		t.Fatalf("oversized document accepted: %v", err)
	}
}

func TestValidateFlatRejectsEmpty(t *testing.T) {
	err := sops.ValidateFlat(nil, sops.DefaultLimits)
	if err == nil || !strings.Contains(err.Error(), "no secrets") {
		t.Fatalf("empty document accepted: %v", err)
	}
}

func encryptPlain(t *testing.T, doc string) error {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	_, err = sops.Encrypt([]byte(doc), []*age.X25519Recipient{id.Recipient()}, sops.DefaultLimits)
	return err
}

func TestDocumentShapeRejections(t *testing.T) {
	cases := []struct{ name, doc, want string }{
		{"nested", "db:\n  pw: x\n", "nested mapping"},
		{"sequence", "list:\n  - a\n", "sequence"},
		{"integer", "key: 8080\n", "must be YAML strings"},
		{"float", "key: 1.5\n", "must be YAML strings"},
		{"bool", "key: true\n", "must be YAML strings"},
		{"null", "key:\n", "must be YAML strings"},
		{"binary tag", "key: !!binary aGk=\n", "must be YAML strings"},
		{"custom tag", "key: !custom x\n", "must be YAML strings"},
		{"alias", "a: &x v\nb: *x\n", "alias"},
		{"non-string key", "1: v\n", "names must be strings"},
		{"multi document", "a: '1'\n---\nb: '2'\n", "one YAML document"},
		{"empty", "# only a comment\n", "no secrets"},
		{"empty mapping", "{}\n", "no secrets"},
		{"top-level list", "- a\n", "not a YAML mapping"},
		{"duplicate", "a: x\na: y\n", "duplicate"},
		{"invalid name", "'.hidden': x\n", "invalid secret name"},
		{"unencrypted suffix", "token_unencrypted: x\n", "leaves unencrypted"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := encryptPlain(t, tc.doc)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestDocumentShapeErrorsNeverQuoteValues(t *testing.T) {
	for _, doc := range []string{"key: 4242424242\n", "key:\n  nested: TOPSECRETVALUE\n", "key: [TOPSECRETVALUE]\n", "key: \"a\\0TOPSECRETVALUE\"\n"} {
		err := encryptPlain(t, doc)
		if err == nil {
			t.Fatalf("%q accepted", doc)
		}
		if strings.Contains(err.Error(), "TOPSECRETVALUE") || strings.Contains(err.Error(), "4242424242") {
			t.Fatalf("error contains value: %v", err)
		}
	}
}
