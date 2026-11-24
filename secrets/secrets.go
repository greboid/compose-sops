// Package secrets exposes the compose-sops document operations that do not
// publish anything, so other programs can run them in process. Publishing
// stays with the volume plugin.
package secrets

import (
	"errors"
	"fmt"

	"github.com/greboid/compose-sops/internal/sops"
)

// MaxDocumentSize is the largest encrypted document accepted.
const MaxDocumentSize = 1 << 20

// Recipients returns the age recipient of each identity in keyFile.
func Recipients(keyFile string) ([]string, error) {
	ids, err := sops.LoadIdentities(keyFile)
	if err != nil {
		return nil, err
	}
	return sops.IdentityRecipients(ids), nil
}

// Check decrypts encrypted with the identities in keyFile and validates it.
func Check(keyFile string, encrypted []byte) error {
	_, err := decrypt(keyFile, encrypted)
	return err
}

// Rekey returns encrypted with the add recipients added and the remove
// recipients removed. keyFile is read only when the recipients change. An
// unchanged document is returned as given.
func Rekey(keyFile string, encrypted []byte, add, remove []string) ([]byte, error) {
	if err := checkSize(encrypted); err != nil {
		return nil, err
	}
	out, _, err := sops.Rekey(encrypted, nil, add, remove, sops.DefaultLimits)
	if errors.Is(err, sops.ErrIdentityRequired) {
		ids, loadErr := sops.LoadIdentities(keyFile)
		if loadErr != nil {
			return nil, loadErr
		}
		out, _, err = sops.Rekey(encrypted, ids, add, remove, sops.DefaultLimits)
	}
	return out, err
}

// Decrypt returns the secrets in encrypted, by name.
func Decrypt(keyFile string, encrypted []byte) (map[string]string, error) {
	secrets, err := decrypt(keyFile, encrypted)
	if err != nil {
		return nil, err
	}
	out := make(map[string]string, len(secrets))
	for _, s := range secrets {
		out[s.Name] = s.Value
	}
	return out, nil
}

// Encrypt encrypts the flat plaintext YAML document to the recipients of the
// identities and recipient lines in keyFile.
func Encrypt(keyFile string, plaintext []byte) ([]byte, error) {
	if max := sops.DefaultLimits.MaxTotalSize; len(plaintext) > max {
		return nil, fmt.Errorf("plaintext exceeds the %d byte limit", max)
	}
	recipients, err := sops.Recipients(keyFile)
	if err != nil {
		return nil, err
	}
	return sops.Encrypt(plaintext, recipients, sops.DefaultLimits)
}

func decrypt(keyFile string, encrypted []byte) ([]sops.Secret, error) {
	if err := checkSize(encrypted); err != nil {
		return nil, err
	}
	ids, err := sops.LoadIdentities(keyFile)
	if err != nil {
		return nil, err
	}
	return sops.NewDecryptor(ids, sops.DefaultLimits).DecryptYAML(encrypted)
}

func checkSize(encrypted []byte) error {
	if len(encrypted) > MaxDocumentSize {
		return fmt.Errorf("encrypted document exceeds the %d byte limit", MaxDocumentSize)
	}
	return nil
}
