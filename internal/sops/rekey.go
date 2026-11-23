package sops

import (
	"errors"
	"fmt"
	"slices"

	"filippo.io/age"
)

// ErrIdentityRequired is returned by Rekey without identities when the
// recipients would change.
var ErrIdentityRequired = errors.New("an age identity is required to change recipients")

// Rekey adds the recipients in add and removes those in remove. Adding
// wraps the existing data key for the new recipients; removing rotates the
// data key and re-encrypts every value so removed keys cannot read later
// revisions. The document is decrypted and its MAC verified before either.
// It returns the input unchanged, and false, when the recipient set already
// matches.
func Rekey(encrypted []byte, identities []age.Identity, add, remove []string, limits Limits) ([]byte, bool, error) {
	for _, r := range slices.Concat(add, remove) {
		if _, err := age.ParseX25519Recipient(r); err != nil {
			return nil, false, fmt.Errorf("invalid age recipient %q", r)
		}
	}
	d, err := parseEncrypted(encrypted)
	if err != nil {
		return nil, false, err
	}
	have := d.meta.recipients()
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

	dataKey, err := d.unwrap(identities)
	if err != nil {
		return nil, false, fmt.Errorf("data key recovery failed: no identity in the key file can decrypt this document")
	}
	values, err := d.open(dataKey)
	if err != nil {
		return nil, false, err
	}
	if err := ValidateFlat(d.secrets(values), limits); err != nil {
		return nil, false, fmt.Errorf("decrypted document rejected: %s", err)
	}

	if !drop {
		stanzas, err := wrapDataKeyFor(dataKey, missing)
		if err != nil {
			return nil, false, err
		}
		d.meta.age = append(d.meta.age, stanzas...)
	} else {
		keep := slices.DeleteFunc(slices.Concat(have, missing), func(r string) bool { return slices.Contains(remove, r) })
		if len(keep) == 0 {
			return nil, false, fmt.Errorf("removing every recipient would leave the document undecryptable")
		}
		newKey, err := newDataKey()
		if err != nil {
			return nil, false, err
		}
		stanzas, err := wrapDataKeyFor(newKey, keep)
		if err != nil {
			return nil, false, err
		}
		if err := reencryptComments(d.root, dataKey, newKey); err != nil {
			return nil, false, err
		}
		if err := d.seal(newKey, values); err != nil {
			return nil, false, err
		}
		d.meta.age = stanzas
	}
	out, err := d.emit()
	if err != nil {
		return nil, false, err
	}
	return out, true, nil
}

// IdentityRecipients returns the public key of each identity.
func IdentityRecipients(identities []age.Identity) []string {
	var out []string
	for _, id := range identities {
		if x, ok := id.(*age.X25519Identity); ok {
			out = append(out, x.Recipient().String())
		}
	}
	return out
}
