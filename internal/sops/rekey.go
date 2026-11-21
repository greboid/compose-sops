package sops

import (
	"crypto/rand"
	"errors"
	"fmt"
	"slices"
	"time"

	"filippo.io/age"
	"github.com/getsops/sops/v3"
	"github.com/getsops/sops/v3/aes"
	sopsage "github.com/getsops/sops/v3/age"
	"github.com/getsops/sops/v3/config"
	"github.com/getsops/sops/v3/keyservice"
	"github.com/getsops/sops/v3/stores/yaml"
)

// ErrIdentityRequired is returned by Rekey without identities when the
// recipients would change.
var ErrIdentityRequired = errors.New("an age identity is required to change recipients")

// Rekey adds the recipients in add and removes those in remove. Adding
// wraps the existing data key for the new recipients; removing rotates the
// data key and re-encrypts every value so removed keys cannot read later
// revisions. It returns the input unchanged, and false, when the recipient
// set already matches.
func Rekey(encrypted []byte, identities sopsage.ParsedIdentities, add, remove []string, limits Limits) ([]byte, bool, error) {
	for _, r := range slices.Concat(add, remove) {
		if _, err := age.ParseX25519Recipient(r); err != nil {
			return nil, false, fmt.Errorf("invalid age recipient %q", r)
		}
	}
	store := yaml.NewStore(&config.YAMLStoreConfig{})
	tree, err := store.LoadEncryptedFile(encrypted)
	if err != nil {
		return nil, false, fmt.Errorf("not a valid SOPS-encrypted YAML document (%d bytes)", len(encrypted))
	}
	if len(tree.Metadata.KeyGroups) != 1 || !onlyAgeKeys(tree.Metadata.KeyGroups) {
		return nil, false, fmt.Errorf("rekey supports documents with one key group of age recipients only")
	}
	var have []string
	for _, k := range tree.Metadata.KeyGroups[0] {
		have = append(have, k.(*sopsage.MasterKey).Recipient)
	}
	var missing []string
	for _, r := range add {
		if !slices.Contains(have, r) && !slices.Contains(missing, r) && !slices.Contains(remove, r) {
			missing = append(missing, r)
		}
	}
	drop := slices.ContainsFunc(have, func(r string) bool { return slices.Contains(remove, r) })
	if len(missing) == 0 && !drop {
		return encrypted, false, nil
	}
	if identities == nil {
		return nil, false, ErrIdentityRequired
	}

	dataKey, err := tree.Metadata.GetDataKeyWithKeyServices(
		[]keyservice.KeyServiceClient{keyservice.NewCustomLocalClient(identityKeyService{identities: identities})},
		nil,
	)
	if err != nil {
		return nil, false, fmt.Errorf("data key recovery failed: no identity in the key file can decrypt this document")
	}

	if !drop {
		for _, r := range missing {
			k := &sopsage.MasterKey{Recipient: r}
			if err := k.Encrypt(dataKey); err != nil {
				return nil, false, fmt.Errorf("cannot encrypt data key for an age recipient: %w", err)
			}
			tree.Metadata.KeyGroups[0] = append(tree.Metadata.KeyGroups[0], k)
		}
	} else {
		cipher := aes.NewCipher()
		mac, err := tree.Decrypt(dataKey, cipher)
		if err != nil {
			return nil, false, fmt.Errorf("decryption failed: an encrypted value could not be decrypted with the recovered data key")
		}
		stored, err := cipher.Decrypt(tree.Metadata.MessageAuthenticationCode, dataKey, tree.Metadata.LastModified.Format(time.RFC3339))
		if err != nil || stored != mac {
			return nil, false, fmt.Errorf("integrity check failed: MAC mismatch, the document was modified after encryption or is corrupted")
		}
		if _, err := ValidateFlat(tree.Branches, limits); err != nil {
			return nil, false, fmt.Errorf("decrypted document rejected: %s", err)
		}
		keep := slices.DeleteFunc(slices.Concat(have, missing), func(r string) bool { return slices.Contains(remove, r) })
		if len(keep) == 0 {
			return nil, false, fmt.Errorf("removing every recipient would leave the document undecryptable")
		}
		if err := reencrypt(&tree, keep); err != nil {
			return nil, false, err
		}
	}
	out, err := store.EmitEncryptedFile(tree)
	if err != nil {
		return nil, false, fmt.Errorf("cannot serialize encrypted document: %w", err)
	}
	return out, true, nil
}

// reencrypt encrypts a decrypted tree with a new data key for recipients.
func reencrypt(tree *sops.Tree, recipients []string) error {
	group := make(sops.KeyGroup, 0, len(recipients))
	dataKey := make([]byte, 32)
	if _, err := rand.Read(dataKey); err != nil {
		return fmt.Errorf("cannot generate data key: %w", err)
	}
	for _, r := range recipients {
		k := &sopsage.MasterKey{Recipient: r}
		if err := k.Encrypt(dataKey); err != nil {
			return fmt.Errorf("cannot encrypt data key for an age recipient: %w", err)
		}
		group = append(group, k)
	}
	tree.Metadata.KeyGroups = []sops.KeyGroup{group}
	cipher := aes.NewCipher()
	mac, err := tree.Encrypt(dataKey, cipher)
	if err != nil {
		return fmt.Errorf("cannot encrypt document values: %w", err)
	}
	tree.Metadata.LastModified = time.Now().UTC()
	tree.Metadata.MessageAuthenticationCode, err = cipher.Encrypt(mac, dataKey, tree.Metadata.LastModified.Format(time.RFC3339))
	if err != nil {
		return fmt.Errorf("cannot encrypt document MAC: %w", err)
	}
	return nil
}

// IdentityRecipients returns the public key of each identity.
func IdentityRecipients(identities sopsage.ParsedIdentities) []string {
	var out []string
	for _, id := range identities {
		if x, ok := id.(*age.X25519Identity); ok {
			out = append(out, x.Recipient().String())
		}
	}
	return out
}
