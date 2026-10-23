// Encrypt produces SOPS-encrypted YAML documents for the compose-sops
// document model from the same flat name→string mapping the provider
// decrypts. Encryption happens in-process with the SOPS and age libraries:
// no external executables, no ambient key discovery.

package sops

import (
	"crypto/rand"
	"fmt"
	"time"

	"filippo.io/age"
	"github.com/getsops/sops/v3"
	"github.com/getsops/sops/v3/aes"
	sopsage "github.com/getsops/sops/v3/age"
	"github.com/getsops/sops/v3/config"
	"github.com/getsops/sops/v3/stores/yaml"
	sopsversion "github.com/getsops/sops/v3/version"
)

// sopsMetadataKey is the top-level key SOPS uses in emitted documents; its
// presence in input marks an already-encrypted file.
const sopsMetadataKey = "sops"

// Encrypt validates the plaintext flat YAML document, encrypts every value
// with a fresh random data key, and wraps the data key for each given
// recipient. The returned bytes are standard SOPS YAML, decryptable by the
// sops CLI and by the compose-sops provider.
//
// The input must be exactly one flat mapping of secret names to string
// values; anything else is rejected before encryption.
func Encrypt(plaintext []byte, filePath string, recipients []*age.X25519Recipient, limits Limits) ([]byte, error) {
	if len(recipients) == 0 {
		return nil, fmt.Errorf("no age recipients given")
	}
	store := yaml.NewStore(&config.YAMLStoreConfig{})
	branches, err := store.LoadPlainFile(plaintext)
	if err != nil {
		return nil, fmt.Errorf("not a valid YAML document")
	}
	if len(branches) == 1 && hasSopsTopLevelKey(branches[0]) {
		return nil, fmt.Errorf("input already contains a %q top-level key and appears to be SOPS-encrypted", sopsMetadataKey)
	}
	secrets, err := ValidateFlat(branches, limits)
	if err != nil {
		return nil, fmt.Errorf("plaintext rejected: %s", err)
	}

	// Rebuild the branch from validated secrets so output is normalized
	// regardless of YAML input quirks, preserving document order.
	branch := make(sops.TreeBranch, 0, len(secrets))
	for _, secret := range secrets {
		branch = append(branch, sops.TreeItem{Key: secret.Name, Value: secret.Value})
	}

	group := make(sops.KeyGroup, 0, len(recipients))
	for _, recipient := range recipients {
		group = append(group, &sopsage.MasterKey{Recipient: recipient.String()})
	}
	tree := sops.Tree{
		Branches: sops.TreeBranches{branch},
		Metadata: sops.Metadata{
			Version:   sopsversion.Version,
			KeyGroups: []sops.KeyGroup{group},
		},
		FilePath: filePath,
	}

	// A single key group means every master key wraps the whole data key;
	// master keys for age encrypt in-process without key services.
	dataKey := make([]byte, 32)
	if _, err := rand.Read(dataKey); err != nil {
		return nil, fmt.Errorf("cannot generate data key: %w", err)
	}
	for _, key := range group {
		if err := key.(*sopsage.MasterKey).Encrypt(dataKey); err != nil {
			return nil, fmt.Errorf("cannot encrypt data key for an age recipient: %w", err)
		}
	}

	// Mirror the sops CLI flow: encrypt values in place, compute the MAC
	// over the plaintext, then store the MAC encrypted alongside the
	// document.
	cipher := aes.NewCipher()
	mac, err := tree.Encrypt(dataKey, cipher)
	if err != nil {
		return nil, fmt.Errorf("cannot encrypt document values: %w", err)
	}
	tree.Metadata.LastModified = time.Now().UTC()
	tree.Metadata.MessageAuthenticationCode, err = cipher.Encrypt(mac, dataKey, tree.Metadata.LastModified.Format(time.RFC3339))
	if err != nil {
		return nil, fmt.Errorf("cannot encrypt document MAC: %w", err)
	}

	encrypted, err := store.EmitEncryptedFile(tree)
	if err != nil {
		return nil, fmt.Errorf("cannot serialize encrypted document: %w", err)
	}
	return encrypted, nil
}

func hasSopsTopLevelKey(branch sops.TreeBranch) bool {
	for _, item := range branch {
		if key, ok := item.Key.(string); ok && key == sopsMetadataKey {
			return true
		}
	}
	return false
}
