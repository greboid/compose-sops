// GenerateKey generates a fresh age X25519 identity file for use as a
// compose-sops host key.

package sops

import (
	"fmt"
	"os"
	"path/filepath"

	"filippo.io/age"

	"github.com/greboid/compose-sops/internal/system"
)

// GenerateKey creates a new age identity at path, refusing to overwrite, and
// returns the matching public recipient. The file is written 0600 with
// O_EXCL|O_NOFOLLOW; missing parent directories are created 0700.
func GenerateKey(path string) (string, error) {
	if _, err := os.Lstat(path); err == nil {
		return "", fmt.Errorf("%s already exists; choose another path or remove the old key deliberately", path)
	} else if !os.IsNotExist(err) {
		return "", fmt.Errorf("cannot inspect %s: %w", path, err)
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("cannot create %s: %w", dir, err)
	}
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		return "", fmt.Errorf("cannot generate age identity: %w", err)
	}
	file, err := system.CreateNewFile(path, 0o600)
	if err != nil {
		return "", fmt.Errorf("cannot create %s: %w", path, err)
	}
	if err := file.Write([]byte(identity.String() + "\n")); err != nil {
		file.Close()
		file.Remove()
		return "", fmt.Errorf("cannot write %s: %w", path, err)
	}
	if err := file.Close(); err != nil {
		file.Remove()
		return "", fmt.Errorf("cannot close %s: %w", path, err)
	}
	return identity.Recipient().String(), nil
}
