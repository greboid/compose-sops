package sops_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"filippo.io/age"

	"github.com/greboid/compose-sops/internal/fixtures"
	"github.com/greboid/compose-sops/internal/sops"
)

type tamperCase struct {
	name   string
	mutate func(doc, other string) string
	// want is a substring of the expected error; empty means the mutated
	// document must still decrypt.
	want string
	// upstream reports that upstream SOPS also rejects the mutation.
	upstream bool
}

func line(doc, key string) string {
	m := regexp.MustCompile(`(?m)^` + regexp.QuoteMeta(key) + `: .*$`).FindString(doc)
	if m == "" {
		panic("no line for " + key)
	}
	return m
}

func replaceLine(doc, key, with string) string {
	return strings.Replace(doc, line(doc, key), with, 1)
}

func insertMeta(field string) func(string, string) string {
	return func(doc, _ string) string {
		return strings.Replace(doc, "\n    lastmodified:", "\n    "+field+"\n    lastmodified:", 1)
	}
}

func insertBody(text string) func(string, string) string {
	return func(doc, _ string) string { return strings.Replace(doc, "\nsops:\n", "\n"+text+"\nsops:\n", 1) }
}

var tamperCases = []tamperCase{
	{"unmodified", func(d, _ string) string { return d }, "", false},
	{"delete an entry", func(d, _ string) string { return strings.Replace(d, line(d, "db_password")+"\n", "", 1) }, "integrity check failed", true},
	{"value emptied", func(d, _ string) string { return replaceLine(d, "api_key", `api_key: ""`) }, "integrity check failed", true},
	{"values swapped", func(d, _ string) string {
		a, b := line(d, "api_key"), line(d, "db_password")
		d = strings.Replace(d, a, "api_key: "+strings.SplitN(b, ": ", 2)[1], 1)
		return strings.Replace(d, b, "db_password: "+strings.SplitN(a, ": ", 2)[1], 1)
	}, "decryption failed", true},
	{"key renamed", func(d, _ string) string {
		return replaceLine(d, "api_key", "api_key2"+strings.TrimPrefix(line(d, "api_key"), "api_key"))
	}, "decryption failed", true},
	{"value from another document", func(d, o string) string { return replaceLine(d, "api_key", line(o, "api_key")) }, "decryption failed", true},
	{"duplicated entry", func(d, _ string) string {
		return strings.Replace(d, line(d, "api_key"), line(d, "api_key")+"\n"+line(d, "api_key"), 1)
	}, "integrity check failed", true},
	{"plaintext entry added", insertBody("extra_unencrypted: injected"), "integrity check failed", true},
	{"plaintext value", func(d, _ string) string { return replaceLine(d, "api_key", "api_key: abc123") }, "not a SOPS-encrypted value", true},
	{"value type flipped", func(d, _ string) string {
		return strings.Replace(d, line(d, "api_key"), strings.Replace(line(d, "api_key"), "type:str]", "type:int]", 1), 1)
	}, "must be YAML strings", true},
	{"value nonce truncated", func(d, _ string) string {
		return strings.Replace(d, line(d, "api_key"), regexp.MustCompile(`iv:[^,]{8}`).ReplaceAllString(line(d, "api_key"), "iv:"), 1)
	}, "not a SOPS-encrypted value", true},
	{"value nested", func(d, _ string) string { return replaceLine(d, "api_key", "api_key: {a: b}") }, "nested mapping", true},
	{"lastmodified changed", func(d, _ string) string {
		return regexp.MustCompile(`lastmodified: ".*"`).ReplaceAllString(d, `lastmodified: "2001-02-03T04:05:06Z"`)
	}, "integrity check failed", true},
	{"lastmodified invalid", func(d, _ string) string {
		return regexp.MustCompile(`lastmodified: ".*"`).ReplaceAllString(d, `lastmodified: "yesterday"`)
	}, "RFC 3339", true},
	{"mac removed", func(d, _ string) string { return strings.Replace(d, line(d, "    mac")+"\n", "", 1) }, "no MAC", true},
	{"mac emptied", func(d, _ string) string { return replaceLine(d, "    mac", `    mac: ""`) }, "no MAC", true},
	{"mac from another document", func(d, o string) string { return replaceLine(d, "    mac", line(o, "    mac")) }, "integrity check failed", true},
	{"mac in plaintext", func(d, _ string) string { return replaceLine(d, "    mac", `    mac: "00"`) }, "integrity check failed", true},
	{"unencrypted suffix widened", func(d, _ string) string {
		return replaceLine(d, "    unencrypted_suffix", "    unencrypted_suffix: _key")
	}, "integrity check failed", true},
	{"unencrypted suffix removed", func(d, _ string) string { return strings.Replace(d, line(d, "    unencrypted_suffix")+"\n", "", 1) }, "", false},
	{"empty provider lists", insertMeta("kms: []\n    pgp: []\n    gcp_kms: []\n    azure_kv: []\n    hc_vault: []"), "", false},
	{"zero option values", insertMeta("mac_only_encrypted: false\n    shamir_threshold: 0\n    encrypted_regex: \"\""), "", false},
	{"unknown metadata field", insertMeta("future_field: x"), "unsupported SOPS metadata field", false},
	{"encrypted_regex", insertMeta("encrypted_regex: ^db"), "unsupported SOPS option", false},
	{"unencrypted_regex", insertMeta("unencrypted_regex: ^api"), "unsupported SOPS option", true},
	{"encrypted_suffix", insertMeta("encrypted_suffix: _secret"), "unsupported SOPS option", false},
	{"unencrypted_comment_regex", insertMeta("unencrypted_comment_regex: x"), "unsupported SOPS option", false},
	{"encrypted_comment_regex", insertMeta("encrypted_comment_regex: x"), "unsupported SOPS option", false},
	{"mac_only_encrypted", insertMeta("mac_only_encrypted: true"), "unsupported SOPS option", true},
	{"shamir_threshold", insertMeta("shamir_threshold: 2"), "unsupported SOPS option", false},
	{"key_groups", insertMeta("key_groups:\n        - age:\n            - recipient: age1x\n              enc: x"), "unsupported SOPS option", false},
	{"non-age key", insertMeta("kms:\n        - arn: arn:aws:kms:us-east-1:0:key/x\n          enc: x\n          created_at: \"2024-01-01T00:00:00Z\""), "only age recipients", false},
	{"age entry extra field", func(d, _ string) string {
		return strings.Replace(d, "\n          recipient:", "\n          extra: x\n          recipient:", 1)
	}, "unsupported or repeated field", false},
	{"no age recipients", func(d, _ string) string {
		return regexp.MustCompile(`(?s)    age:\n.*?\n    lastmodified`).ReplaceAllString(d, "    age: []\n    lastmodified")
	}, "no age recipients", true},
	{"metadata not a mapping", func(d, _ string) string { return d[:strings.Index(d, "\nsops:\n")] + "\nsops: x\n" }, "not a mapping", true},
	{"metadata missing", func(d, _ string) string { return d[:strings.Index(d, "\nsops:\n")+1] }, "no \"sops\" metadata", true},
	{"second sops key", func(d, _ string) string { return d + "sops: {}\n" }, "more than one", false},
	{"second document", func(d, _ string) string { return d + "---\nfoo: bar\n" }, "one YAML document", false},
}

func tamperDocuments(t *testing.T) map[string]struct {
	doc, other string
	ids        []age.Identity
	keyFile    string
} {
	t.Helper()
	ids, err := sops.LoadIdentities(writeTemp(t, "key.txt", fixtures.IdentityTest()))
	if err != nil {
		t.Fatal(err)
	}
	keyFile := filepath.Join(t.TempDir(), "fixture-key.txt")
	if err := os.WriteFile(keyFile, fixtures.IdentityTest(), 0o600); err != nil {
		t.Fatal(err)
	}
	recipient := ids[0].(*age.X25519Identity).Recipient()
	encrypt := func() string {
		out, err := sops.Encrypt([]byte("api_key: abc123\ndb_password: hunter2\nempty: \"\"\n"), []*age.X25519Recipient{recipient}, sops.DefaultLimits)
		if err != nil {
			t.Fatal(err)
		}
		return string(out)
	}
	type set = struct {
		doc, other string
		ids        []age.Identity
		keyFile    string
	}
	return map[string]set{
		"ours":    {encrypt(), encrypt(), ids, keyFile},
		"sopscli": {string(fixtures.ValidDocument()), encrypt(), ids, keyFile},
	}
}

func TestTamperedDocumentsRejected(t *testing.T) {
	for source, s := range tamperDocuments(t) {
		for _, tc := range tamperCases {
			t.Run(source+"/"+tc.name, func(t *testing.T) {
				mutated := tc.mutate(s.doc, s.other)
				if tc.name != "unmodified" && mutated == s.doc {
					t.Fatal("mutation did not change the document")
				}
				_, err := sops.NewDecryptor(s.ids, sops.DefaultLimits).DecryptYAML([]byte(mutated))
				switch {
				case tc.want == "" && err != nil:
					t.Fatalf("rejected: %v", err)
				case tc.want != "" && err == nil:
					t.Fatalf("accepted:\n%s", mutated)
				case tc.want != "" && !strings.Contains(err.Error(), tc.want):
					t.Fatalf("err = %v, want %q", err, tc.want)
				}
				if tc.want != "" {
					if _, _, err := sops.Rekey([]byte(mutated), s.ids, []string{newKeyPair(t).recipient()}, nil, sops.DefaultLimits); err == nil {
						t.Fatal("rekey accepted the tampered document")
					}
				}
				if tc.upstream {
					if _, err := upstreamDecrypt(t, []byte(mutated), s.keyFile); err == nil {
						t.Fatal("upstream accepted the mutation, so the case does not test what it claims")
					}
				}
				if tc.want == "" {
					if _, err := upstreamDecrypt(t, []byte(mutated), s.keyFile); err != nil {
						t.Fatalf("upstream rejected a document accepted here: %v", err)
					}
				}
			})
		}
	}
}

func TestUnencryptedSuffixValueIsAuthenticated(t *testing.T) {
	k := newKeyPair(t)
	doc := string(upstreamEncrypt(t, "api_key: abc\nnote_unencrypted: visible\n", k.recipient()))
	changed := strings.Replace(doc, "note_unencrypted: visible", "note_unencrypted: changed", 1)
	if changed == doc {
		t.Fatal("mutation did not apply")
	}
	_, err := sops.NewDecryptor(k.identities(), sops.DefaultLimits).DecryptYAML([]byte(changed))
	if err == nil || !strings.Contains(err.Error(), "integrity check failed") {
		t.Fatalf("err = %v", err)
	}
}
