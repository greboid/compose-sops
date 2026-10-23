// Package fixtures embeds the committed SOPS test fixtures: documents
// encrypted by the real sops CLI (never by this repository's library code)
// and the test-only age identity files they were encrypted for. Tests in any
// internal package import these instead of re-encrypting at test time.
package fixtures

import (
	"embed"
	"fmt"
)

//go:embed all:files
var files embed.FS

// Get returns the contents of the named fixture file under files/.
func Get(name string) []byte {
	b, err := files.ReadFile("files/" + name)
	if err != nil {
		panic(fmt.Sprintf("fixture %s missing: %v", name, err))
	}
	return b
}

// ValidDocument is a SOPS CLI-encrypted YAML document with values
// exercising exact preservation (trailing space, embedded newline, empty
// string, number lookalike, non-ASCII).
var ValidDocument = func() []byte { return Get("valid.age.yaml") }

// ValidValues are the exact expected plaintexts of ValidDocument.
var ValidValues = map[string]string{
	"db_password":   "hunter2 ",
	"api_key":       "abc123",
	"multiline":     "line one\nline two\n",
	"empty":         "",
	"quoted_number": "0042",
	"unicode":       "pässwörd-ключ-密钥",
}

// ValidOrder is the document order of ValidDocument's keys.
var ValidOrder = []string{"db_password", "api_key", "multiline", "empty", "quoted_number", "unicode"}

// Identity files.
var (
	// IdentityTest decrypts ValidDocument (and nested/nonstring/nul/big).
	IdentityTest = func() []byte { return Get("identity-test.txt") }
	// IdentityWrong is a different key: cannot decrypt ValidDocument.
	IdentityWrong = func() []byte { return Get("identity-wrong.txt") }
	// IdentityPlugin contains a native identity plus a rejected plugin line.
	IdentityPlugin = func() []byte { return Get("identity-plugin.txt") }
	// IdentitySSH contains a native identity plus a rejected SSH line.
	IdentitySSH = func() []byte { return Get("identity-ssh.txt") }
	// IdentityEmpty has only comments and blank lines.
	IdentityEmpty = func() []byte { return Get("identity-empty.txt") }
)

// Negative documents, all encrypted by the SOPS CLI for IdentityTest.
var (
	// WrongKeyDocument is encrypted for a different identity.
	WrongKeyDocument = func() []byte { return Get("wrong-key.age.yaml") }
	// TamperedMACDocument has a modified encrypted MAC.
	TamperedMACDocument = func() []byte { return Get("tampered-mac.age.yaml") }
	// CorruptedDocument has a modified encrypted value payload.
	CorruptedDocument = func() []byte { return Get("corrupted.age.yaml") }
	// NestedDocument contains a nested mapping.
	NestedDocument = func() []byte { return Get("nested.age.yaml") }
	// NonStringDocument contains integer/bool/float/null values.
	NonStringDocument = func() []byte { return Get("nonstring.age.yaml") }
	// NULDocument contains a NUL byte in a value.
	NULDocument = func() []byte { return Get("nulbyte.age.yaml") }
	// BigDocument has one value exceeding the 64 KiB limit.
	BigDocument = func() []byte { return Get("big.age.yaml") }
)
