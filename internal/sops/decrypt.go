package sops

import (
	"fmt"

	"filippo.io/age"
)

// Decryptor decrypts SOPS documents on behalf of the provider, which
// consumes it through its own interface.
type Decryptor struct {
	identities []age.Identity
	limits     Limits
}

// NewDecryptor builds a Decryptor around already-parsed age identities.
func NewDecryptor(identities []age.Identity, limits Limits) *Decryptor {
	return &Decryptor{identities: identities, limits: limits}
}

// DecryptYAML decrypts a SOPS-encrypted YAML document, verifies its
// integrity, and returns the validated flat secret mapping in document
// order. No plaintext is logged or echoed in errors.
func (s *Decryptor) DecryptYAML(encrypted []byte) ([]Secret, error) {
	d, err := parseEncrypted(encrypted)
	if err != nil {
		return nil, err
	}
	dataKey, err := d.unwrap(s.identities)
	if err != nil {
		return nil, fmt.Errorf("data key recovery failed: no identity in age-key-file could decrypt this document (ambient key sources such as SOPS_AGE_KEY are intentionally ignored)")
	}
	values, err := d.open(dataKey)
	if err != nil {
		return nil, err
	}
	secrets := d.secrets(values)
	if err := ValidateFlat(secrets, s.limits); err != nil {
		return nil, fmt.Errorf("decrypted document rejected: %s", err)
	}
	return secrets, nil
}
