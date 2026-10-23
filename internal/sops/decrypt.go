// Decrypt isolates all SOPS library API usage behind the Decryptor type.
// It decrypts a SOPS-encrypted YAML document using exclusively an explicitly
// configured age identity.

package sops

import (
	"context"
	"fmt"
	"time"

	"github.com/getsops/sops/v3"
	"github.com/getsops/sops/v3/aes"
	sopsage "github.com/getsops/sops/v3/age"
	"github.com/getsops/sops/v3/config"
	"github.com/getsops/sops/v3/keyservice"
	"github.com/getsops/sops/v3/stores/yaml"
)

// Decryptor decrypts SOPS documents on behalf of the provider, which
// consumes it through its own interface.
type Decryptor struct {
	identities sopsage.ParsedIdentities
	limits     Limits
}

// NewDecryptor builds a Decryptor around already-parsed age identities.
func NewDecryptor(identities sopsage.ParsedIdentities, limits Limits) *Decryptor {
	return &Decryptor{identities: identities, limits: limits}
}

// DecryptYAML decrypts a SOPS-encrypted YAML document, verifies its
// integrity, and returns the validated flat secret mapping in document
// order. No plaintext is logged or echoed in errors.
func (s *Decryptor) DecryptYAML(encrypted []byte) ([]Secret, error) {
	store := yaml.NewStore(&config.YAMLStoreConfig{})
	tree, err := store.LoadEncryptedFile(encrypted)
	if err != nil {
		// Parse errors can quote document content; sanitize.
		return nil, fmt.Errorf("not a valid SOPS-encrypted YAML document (%d bytes)", len(encrypted))
	}
	if len(tree.Metadata.KeyGroups) == 0 {
		return nil, fmt.Errorf("document has no SOPS metadata key groups")
	}
	if !onlyAgeKeys(tree.Metadata.KeyGroups) {
		return nil, fmt.Errorf("document uses non-age master keys; only age recipients are supported")
	}

	dataKey, err := tree.Metadata.GetDataKeyWithKeyServices(
		[]keyservice.KeyServiceClient{keyservice.NewCustomLocalClient(identityKeyService{identities: s.identities})},
		nil,
	)
	if err != nil {
		return nil, fmt.Errorf("data key recovery failed: no identity in age-key-file could decrypt this document (ambient key sources such as SOPS_AGE_KEY are intentionally ignored)")
	}

	cipher := aes.NewCipher()
	mac, err := tree.Decrypt(dataKey, cipher)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: an encrypted value could not be decrypted with the recovered data key")
	}

	// Verify the document MAC before any plaintext is used.
	originalMac, err := cipher.Decrypt(
		tree.Metadata.MessageAuthenticationCode,
		dataKey,
		tree.Metadata.LastModified.Format(time.RFC3339),
	)
	if err != nil {
		return nil, fmt.Errorf("integrity check failed: the stored MAC could not be decrypted")
	}
	if originalMac != mac {
		return nil, fmt.Errorf("integrity check failed: MAC mismatch, the document was modified after encryption or is corrupted")
	}

	secrets, err := ValidateFlat(tree.Branches, s.limits)
	if err != nil {
		return nil, fmt.Errorf("decrypted document rejected: %s", err)
	}
	return secrets, nil
}

func onlyAgeKeys(groups []sops.KeyGroup) bool {
	for _, group := range groups {
		for _, mk := range group {
			if _, ok := mk.(*sopsage.MasterKey); !ok {
				return false
			}
		}
	}
	return true
}

// identityKeyService is a keyservice.KeyServiceServer that unwraps SOPS data
// keys with identities parsed up-front. Because identities are pre-applied
// with ApplyToMasterKey, sops/age MasterKey.Decrypt skips all ambient
// discovery (SOPS_AGE_KEY, SOPS_AGE_KEY_CMD, SOPS_AGE_SSH_*, default SSH
// paths, ~/.config/sops/age/keys.txt) entirely.
type identityKeyService struct {
	identities sopsage.ParsedIdentities
}

var _ keyservice.KeyServiceServer = identityKeyService{}

func (s identityKeyService) Decrypt(_ context.Context, req *keyservice.DecryptRequest) (*keyservice.DecryptResponse, error) {
	key := req.Key.GetKeyType()
	ageKey, ok := key.(*keyservice.Key_AgeKey)
	if !ok {
		return nil, fmt.Errorf("only age master keys are supported")
	}
	mk := sopsage.MasterKey{
		Recipient:    ageKey.AgeKey.Recipient,
		EncryptedKey: string(req.Ciphertext),
	}
	s.identities.ApplyToMasterKey(&mk)
	plaintext, err := mk.Decrypt()
	if err != nil {
		// age reports "no identity matched any of the recipients"; do not
		// forward possible library internals.
		return nil, fmt.Errorf("age unwrap failed: no configured identity matches this recipient")
	}
	return &keyservice.DecryptResponse{Plaintext: plaintext}, nil
}

func (s identityKeyService) Encrypt(_ context.Context, _ *keyservice.EncryptRequest) (*keyservice.EncryptResponse, error) {
	return nil, fmt.Errorf("compose-sops never encrypts; use the sops CLI to encrypt secret files")
}
