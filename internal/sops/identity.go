// Identity file handling: age identities are loaded from an explicitly
// configured host key file without any ambient key discovery. Plugin and SSH
// identity lines are rejected before parsing so that decryption can never
// fall back to executing external binaries: age plugin identities parse fine
// in-process but would exec an external age-plugin-* binary when unwrapping.

package sops

import (
	"errors"
	"fmt"
	"io/fs"
	"strings"

	"filippo.io/age"

	sopsage "github.com/getsops/sops/v3/age"

	"github.com/greboid/compose-sops/internal/system"
	"os"
)

// maxIdentityFileSize bounds the identity file read.
const maxIdentityFileSize = 1 << 20 // 1 MiB

// errSensor marks errors that were constructed in this package and are
// therefore safe to surface verbatim.
type sanitizedError struct{ msg string }

func (e *sanitizedError) Error() string { return e.msg }

func sanitized(msg string) error { return &sanitizedError{msg: msg} }

// IsSanitized reports whether the error was produced by this package and
// contains no content read from the identity file.
func IsSanitized(err error) bool {
	var s *sanitizedError
	return errors.As(err, &s)
}

// LoadIdentities parses the age identity file at path and returns SOPS age
// identities
// suitable for ApplyToMasterKey injection.
//
// Rejected before parsing:
//   - lines beginning with AGE-PLUGIN- (would require an external plugin)
//   - OpenSSH private key blocks (-----BEGIN ... PRIVATE KEY-----)
//   - SSH public key lines (ssh-ed25519, ssh-rsa, ecdsa-sha2-*)
//
// Blank lines and # comments are ignored. At least one X25519 identity
// (AGE-SECRET-KEY-...) must remain.
func LoadIdentities(path string) (sopsage.ParsedIdentities, error) {
	raw, err := system.ReadFileBounded(path, maxIdentityFileSize)
	if err != nil {
		return nil, sanitized("cannot read age key file: " + readMessage(path, err))
	}

	// Filter the raw lines ourselves; age.ParseIdentities would happily
	// accept plugin and SSH identities.
	filtered, err := filterLines(raw)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(filtered) == "" {
		return nil, sanitized("age key file contains no identities")
	}

	ids, err := age.ParseIdentities(strings.NewReader(filtered))
	if err != nil {
		// Parse errors can quote the offending line (key material).
		return nil, sanitized("age key file contains an invalid identity (only native AGE-SECRET-KEY-1... identities are supported)")
	}
	if len(ids) == 0 {
		return nil, sanitized("age key file contains no identities")
	}
	return sopsage.ParsedIdentities(ids), nil
}

// Recipients parses the age key file at path and returns the age public keys
// to encrypt to. Each line must be either a native identity
// (AGE-SECRET-KEY-1..., from which the matching recipient is derived) or an
// explicit X25519 recipient (age1...). This permits encrypting with a
// private key file or with a recipients-only copy. Plugin, SSH, and other
// line types are rejected with the same strictness as Load.
func Recipients(path string) ([]*age.X25519Recipient, error) {
	raw, err := system.ReadFileBounded(path, maxIdentityFileSize)
	if err != nil {
		return nil, sanitized("cannot read age key file: " + readMessage(path, err))
	}
	var recipients []*age.X25519Recipient
	lineNo := 0
	seen := map[string]struct{}{}
	for line := range strings.SplitSeq(string(raw), "\n") {
		lineNo++
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		upper := strings.ToUpper(trimmed)
		switch {
		case strings.HasPrefix(upper, "AGE-PLUGIN-"):
			return nil, sanitized(fmt.Sprintf("age key file line %d: plugin identities are not supported (would execute an external age-plugin binary)", lineNo))
		case strings.HasPrefix(trimmed, "-----BEGIN") && strings.HasSuffix(trimmed, "PRIVATE KEY-----"):
			return nil, sanitized(fmt.Sprintf("age key file line %d: SSH private keys are not supported", lineNo))
		case strings.HasPrefix(trimmed, "ssh-ed25519 "), strings.HasPrefix(trimmed, "ssh-rsa "),
			strings.HasPrefix(trimmed, "ecdsa-sha2-"):
			return nil, sanitized(fmt.Sprintf("age key file line %d: SSH public keys are not supported", lineNo))
		case strings.HasPrefix(upper, "AGE-SECRET-KEY-"):
			id, err := age.ParseX25519Identity(trimmed)
			if err != nil {
				return nil, sanitized(fmt.Sprintf("age key file line %d: invalid identity (only native AGE-SECRET-KEY-1... identities are supported)", lineNo))
			}
			recipient := id.Recipient().String()
			if _, dup := seen[recipient]; !dup {
				seen[recipient] = struct{}{}
				recipients = append(recipients, id.Recipient())
			}
		case strings.HasPrefix(trimmed, "age1"):
			r, err := age.ParseX25519Recipient(trimmed)
			if err != nil {
				return nil, sanitized(fmt.Sprintf("age key file line %d: invalid age recipient", lineNo))
			}
			if _, dup := seen[trimmed]; !dup {
				seen[trimmed] = struct{}{}
				recipients = append(recipients, r)
			}
		default:
			return nil, sanitized(fmt.Sprintf("age key file line %d: unsupported line (only AGE-SECRET-KEY-1... identities and age1... recipients are supported)", lineNo))
		}
	}
	if len(recipients) == 0 {
		return nil, sanitized("age key file contains no identities or recipients")
	}
	return recipients, nil
}

// filterLines removes comments and blank lines and rejects unsupported
// identity types, reporting only line numbers, never line contents.
func filterLines(raw []byte) (string, error) {
	var kept strings.Builder
	lineNo := 0
	for line := range strings.SplitSeq(string(raw), "\n") {
		lineNo++
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		upper := strings.ToUpper(trimmed)
		switch {
		case strings.HasPrefix(upper, "AGE-PLUGIN-"):
			return "", sanitized(fmt.Sprintf("age key file line %d: plugin identities are not supported (would execute an external age-plugin binary)", lineNo))
		case strings.HasPrefix(trimmed, "-----BEGIN") && strings.HasSuffix(trimmed, "PRIVATE KEY-----"):
			return "", sanitized(fmt.Sprintf("age key file line %d: SSH private keys are not supported", lineNo))
		case strings.HasPrefix(trimmed, "ssh-ed25519 "), strings.HasPrefix(trimmed, "ssh-rsa "),
			strings.HasPrefix(trimmed, "ecdsa-sha2-"):
			return "", sanitized(fmt.Sprintf("age key file line %d: SSH public keys are not supported", lineNo))
		case !strings.HasPrefix(upper, "AGE-SECRET-KEY-"):
			return "", sanitized(fmt.Sprintf("age key file line %d: unsupported identity line (only AGE-SECRET-KEY-1... identities are supported)", lineNo))
		}
		kept.WriteString(trimmed)
		kept.WriteByte('\n')
	}
	return kept.String(), nil
}

// readMessage strips the underlying error detail from read failures,
// keeping only the reason (path is operator-supplied and safe to include).
func readMessage(path string, err error) string {
	if perr, ok := errors.AsType[*fs.PathError](err); ok {
		return fmt.Sprintf("%s: %s", path, perr.Err.Error())
	}
	if errors.Is(err, os.ErrPermission) {
		return fmt.Sprintf("%s: permission denied", path)
	}
	return fmt.Sprintf("%s: unreadable", path)
}
