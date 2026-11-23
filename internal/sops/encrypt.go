package sops

import (
	"fmt"
	"strings"

	"filippo.io/age"
	"go.yaml.in/yaml/v3"
)

// Encrypt validates the plaintext flat YAML document, encrypts every value
// with a fresh random data key, and wraps the data key for each given
// recipient. The returned bytes are standard SOPS YAML, decryptable by the
// sops CLI and by the compose-sops provider.
//
// The input must be exactly one flat mapping of secret names to string
// values; anything else is rejected before encryption. Comments are dropped.
func Encrypt(plaintext []byte, recipients []*age.X25519Recipient, limits Limits) ([]byte, error) {
	if len(recipients) == 0 {
		return nil, fmt.Errorf("no age recipients given")
	}
	root, err := parseYAML(plaintext)
	if err != nil {
		return nil, fmt.Errorf("plaintext rejected: %s", err)
	}
	entries, _, err := flatEntries(root.Content[0], false, "")
	if err != nil {
		return nil, fmt.Errorf("plaintext rejected: %s", err)
	}
	secrets := make([]Secret, len(entries))
	values := make([]string, len(entries))
	body := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	d := &document{
		root:   &yaml.Node{Kind: yaml.DocumentNode, Content: []*yaml.Node{body}},
		body:   body,
		sopsAt: -1,
		meta:   metadata{suffix: defaultUnencryptedSuffix},
	}
	for i, e := range entries {
		if strings.HasSuffix(e.name, defaultUnencryptedSuffix) {
			return nil, fmt.Errorf("plaintext rejected: secret %q ends with %q, which SOPS leaves unencrypted", e.name, defaultUnencryptedSuffix)
		}
		secrets[i] = Secret{Name: e.name, Value: e.value.Value}
		values[i] = e.value.Value
		key := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: e.name}
		value := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str"}
		body.Content = append(body.Content, key, value)
		d.entries = append(d.entries, entry{name: e.name, value: value})
	}
	if err := ValidateFlat(secrets, limits); err != nil {
		return nil, fmt.Errorf("plaintext rejected: %s", err)
	}

	dataKey, err := newDataKey()
	if err != nil {
		return nil, err
	}
	names := make([]string, len(recipients))
	for i, r := range recipients {
		names[i] = r.String()
	}
	if d.meta.age, err = wrapDataKeyFor(dataKey, names); err != nil {
		return nil, err
	}
	if err := d.seal(dataKey, values); err != nil {
		return nil, err
	}
	return d.emit()
}
