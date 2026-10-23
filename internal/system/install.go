// Self-installation: copies the running compose-sops binary to a global
// location so the Compose provider can reference it by absolute path.

package system

import (
	"fmt"
	"os"
	"path/filepath"
)

// InstallBinary copies the currently running executable to dest (0755, atomic
// replace). It reports the source binary that was copied.
func InstallBinary(dest string) (string, error) {
	src, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("cannot locate the running binary: %w", err)
	}
	src, err = filepath.EvalSymlinks(src)
	if err != nil {
		return "", fmt.Errorf("cannot resolve %s: %w", src, err)
	}
	srcInfo, err := os.Lstat(src)
	if err != nil {
		return "", fmt.Errorf("cannot stat %s: %w", src, err)
	}
	if !srcInfo.Mode().IsRegular() {
		return "", fmt.Errorf("%s is not a regular file", src)
	}
	if src == dest {
		return src, nil
	}
	data, err := os.ReadFile(src)
	if err != nil {
		return "", fmt.Errorf("cannot read %s: %w", src, err)
	}
	dir := filepath.Dir(dest)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("cannot create %s: %w", dir, err)
	}
	if err := ReplaceFile(dest, data, 0o755); err != nil {
		return "", fmt.Errorf("cannot install to %s: %w", dest, err)
	}
	return src, nil
}
