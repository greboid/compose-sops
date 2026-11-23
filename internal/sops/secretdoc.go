// Package sops contains the SOPS/age domain of compose-sops: the flat
// name→string document model, in-process decryption and encryption of
// SOPS-encrypted YAML, and age identity file handling (loading, recipient
// derivation, key generation). Only explicitly configured identity files are
// consulted: no environment variables, no SOPS user config, no default SSH
// paths, no remote key services, and no external executables.
package sops

import (
	"fmt"
	"regexp"
	"strings"
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

// ValidateFlat checks an ordered flat secret list: at least one entry,
// valid and unique names, no NUL bytes, and size limits.
//
// Error messages are safe to surface: they may name secret keys (which are
// already visible in the encrypted file) but never quote values.
func ValidateFlat(secrets []Secret, limits Limits) error {
	if len(secrets) == 0 {
		return fmt.Errorf("document contains no secrets")
	}
	seen := make(map[string]struct{}, len(secrets))
	total := 0
	for _, s := range secrets {
		if !namePattern.MatchString(s.Name) {
			return invalidName(s.Name)
		}
		if _, dup := seen[s.Name]; dup {
			return fmt.Errorf("duplicate secret name %q", s.Name)
		}
		seen[s.Name] = struct{}{}
		if strings.ContainsRune(s.Value, 0) {
			return fmt.Errorf("secret %q contains a NUL byte", s.Name)
		}
		if len(s.Value) > limits.MaxValueSize {
			return fmt.Errorf("secret %q is %d bytes, exceeding the %d byte limit", s.Name, len(s.Value), limits.MaxValueSize)
		}
		total += len(s.Name) + len(s.Value)
		if total > limits.MaxTotalSize {
			return fmt.Errorf("document exceeds the %d byte total size limit", limits.MaxTotalSize)
		}
	}
	return nil
}

func invalidName(name string) error {
	return fmt.Errorf("invalid secret name %q: must match [a-zA-Z0-9_][a-zA-Z0-9._-]* and be at most 128 characters", name)
}
