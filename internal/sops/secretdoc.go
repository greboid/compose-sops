// Package sops contains the SOPS/age domain of compose-sops: the flat
// name→string document model, in-process decryption and encryption of
// SOPS-encrypted YAML, and age identity file handling (loading, recipient
// derivation, key generation). Only explicitly configured identity files are
// consulted: no environment variables, no SOPS user config, no default SSH
// paths, no remote key services, and no external executables.
package sops

import (
	"bytes"
	"fmt"
	"regexp"

	"github.com/getsops/sops/v3"
)

// Limits bound the decrypted document.
type Limits struct {
	// MaxValueSize is the maximum length of one secret value in bytes.
	MaxValueSize int
	// MaxTotalSize is the maximum sum of all names and values in bytes.
	MaxTotalSize int
}

// DefaultLimits are the enforced size bounds.
var DefaultLimits = Limits{
	MaxValueSize: 64 << 10, // 64 KiB per secret value
	MaxTotalSize: 1 << 20,  // 1 MiB across the document
}

// Secret is one validated flat mapping entry, in document order.
type Secret struct {
	Name  string
	Value string
}

// namePattern allows letters, digits, underscore, dot and dash, starting with
// a letter, digit or underscore. Because a leading dot is impossible, the
// names "." and ".." and any hidden file are rejected by construction, and
// the name is always a single safe path component.
var namePattern = regexp.MustCompile(`^[a-zA-Z0-9_][a-zA-Z0-9._-]{0,127}$`)

// ValidateFlat converts decrypted SOPS tree branches into an ordered flat
// secret list. It rejects multi-document input, nested values, non-string
// scalars, duplicate keys, invalid names, NUL bytes, and size overruns.
//
// Error messages are safe to surface: they may name secret keys (which are
// already visible in the encrypted file) but never quote values.
func ValidateFlat(branches sops.TreeBranches, limits Limits) ([]Secret, error) {
	if len(branches) != 1 {
		return nil, fmt.Errorf("expected exactly one YAML document, got %d", len(branches))
	}
	branch := branches[0]
	if len(branch) == 0 {
		return nil, fmt.Errorf("document contains no secrets")
	}

	seen := make(map[string]struct{}, len(branch))
	secrets := make([]Secret, 0, len(branch))
	total := 0

	for _, item := range branch {
		if _, ok := item.Key.(sops.Comment); ok {
			// Comments carry no secret material; skip them.
			continue
		}
		key, ok := item.Key.(string)
		if !ok {
			return nil, fmt.Errorf("secret name must be a string, got %T", item.Key)
		}
		if !namePattern.MatchString(key) {
			return nil, fmt.Errorf("invalid secret name %q: must match [a-zA-Z0-9_][a-zA-Z0-9._-]* and be at most 128 characters", key)
		}
		if _, dup := seen[key]; dup {
			return nil, fmt.Errorf("duplicate secret name %q", key)
		}
		seen[key] = struct{}{}

		if _, isComment := item.Value.(sops.Comment); isComment {
			return nil, fmt.Errorf("secret %q has a comment where a string value was expected", key)
		}
		value, ok := item.Value.(string)
		if !ok {
			return nil, fmt.Errorf("secret %q has a %s value; all values must be YAML strings (quote the value)", key, typeName(item.Value))
		}
		if bytes.ContainsRune([]byte(value), 0) {
			return nil, fmt.Errorf("secret %q contains a NUL byte", key)
		}
		if len(value) > limits.MaxValueSize {
			return nil, fmt.Errorf("secret %q is %d bytes, exceeding the %d byte limit", key, len(value), limits.MaxValueSize)
		}
		total += len(key) + len(value)
		if total > limits.MaxTotalSize {
			return nil, fmt.Errorf("document exceeds the %d byte total size limit", limits.MaxTotalSize)
		}
		secrets = append(secrets, Secret{Name: key, Value: value})
	}
	if len(secrets) == 0 {
		return nil, fmt.Errorf("document contains no secrets")
	}
	return secrets, nil
}

func typeName(v any) string {
	switch v.(type) {
	case nil:
		return "null"
	case int:
		return "integer"
	case float64:
		return "float"
	case bool:
		return "boolean"
	case sops.TreeBranch:
		return "nested mapping"
	case []any:
		return "sequence"
	default:
		return fmt.Sprintf("%T", v)
	}
}
