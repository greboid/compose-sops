// Package system contains the host-side primitives of compose-sops:
// hardened filesystem operations (symlink-refusing, bounded, atomic), the
// default filesystem locations shared by the host tooling commands, the
// io.systemd.Credentials varlink client, systemd unit rendering, and
// self-installation of the binary.
package system

import (
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// maxSymlinkDepth is not needed: O_NOFOLLOW rejects final-component symlinks,
// and validateNoSymlinks rejects symlinked path components up front.
const readChunk = 64 << 10

// CleanNoSymlinks returns the cleaned absolute path and verifies that no
// component of it is a symbolic link. The path must exist.
func CleanNoSymlinks(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("cannot resolve path %s: %w", path, err)
	}
	clean := filepath.Clean(abs)
	resolved, err := filepath.EvalSymlinks(clean)
	if err != nil {
		return "", fmt.Errorf("cannot access path %s: %w", clean, err)
	}
	if resolved != clean {
		return "", fmt.Errorf("path %s contains symbolic links", clean)
	}
	return clean, nil
}

// StatNoFollow lstats path and requires a regular file.
func StatNoFollow(path string) (fs.FileInfo, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	return info, nil
}

// ReadFileBounded reads at most max bytes from a regular file, refusing
// symlinks and files that exceed the bound.
func ReadFileBounded(path string, max int64) ([]byte, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("cannot open %s: %w", path, err)
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("cannot stat %s: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	if info.Size() > max {
		return nil, fmt.Errorf("%s is %d bytes, exceeding the %d byte limit", path, info.Size(), max)
	}

	buf := make([]byte, 0, info.Size()+1)
	chunk := make([]byte, readChunk)
	for {
		n, err := f.Read(chunk)
		buf = append(buf, chunk[:n]...)
		if int64(len(buf)) > max {
			return nil, fmt.Errorf("%s exceeds the %d byte read limit", path, max)
		}
		if err == io.EOF {
			return buf, nil
		}
		if err != nil {
			return nil, fmt.Errorf("cannot read %s: %w", path, err)
		}
	}
}

// WriteNewFile creates path inside an already-private directory with
// O_EXCL|O_NOFOLLOW, writes data, fsyncs, applies uid/gid ownership when
// non-nil, and closes. The file mode is 0400: readable by its owner only.
func WriteNewFile(dir, name string, data []byte, uid, gid *int) error {
	path := filepath.Join(dir, name)
	fd, err := unix.Open(path, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0400)
	if err != nil {
		return fmt.Errorf("cannot create %s: %w", name, err)
	}
	f := os.NewFile(uintptr(fd), path)

	if uid != nil || gid != nil {
		if err := f.Chown(deref(uid), deref(gid)); err != nil {
			f.Close()
			os.Remove(path)
			return fmt.Errorf("cannot set ownership on %s: %w", name, err)
		}
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(path)
		return fmt.Errorf("cannot write %s: %w", name, err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(path)
		return fmt.Errorf("cannot sync %s: %w", name, err)
	}
	if err := f.Close(); err != nil {
		os.Remove(path)
		return fmt.Errorf("cannot close %s: %w", name, err)
	}
	return nil
}

// NewFile is a file created exclusively and symlink-safely, under
// construction.
type NewFile struct {
	f    *os.File
	path string
}

// CreateNewFile opens path for writing with O_CREAT|O_EXCL|O_NOFOLLOW so
// existing files and symlinked final components are refused.
func CreateNewFile(path string, mode os.FileMode) (*NewFile, error) {
	fd, err := unix.Open(path, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, uint32(mode))
	if err != nil {
		return nil, &fs.PathError{Op: "create", Path: path, Err: err}
	}
	return &NewFile{f: os.NewFile(uintptr(fd), path), path: path}, nil
}

// Write writes data and fsyncs the file.
func (n *NewFile) Write(data []byte) error {
	if _, err := n.f.Write(data); err != nil {
		return err
	}
	return n.f.Sync()
}

// Close closes the file.
func (n *NewFile) Close() error { return n.f.Close() }

// Remove deletes the underlying file, for cleanup after failed writes.
func (n *NewFile) Remove() { os.Remove(n.path) }

// WriteNewPathed creates path with the given mode, exclusively and without
// following symlinks in the final component, creating missing parent
// directories 0700. It is for new files such as generated keys and
// credentials; existing files are an error.
func WriteNewPathed(path string, data []byte, mode os.FileMode) error {
	if dir := filepath.Dir(path); dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("cannot create %s: %w", dir, err)
		}
	}
	file, err := CreateNewFile(path, mode)
	if err != nil {
		return err
	}
	if err := file.Write(data); err != nil {
		file.Close()
		file.Remove()
		return fmt.Errorf("cannot write %s: %w", path, err)
	}
	if err := file.Close(); err != nil {
		file.Remove()
		return fmt.Errorf("cannot close %s: %w", path, err)
	}
	return nil
}

// ReplaceFile atomically writes data to path with the given mode: it writes
// a fresh file in the same directory and renames it over path. The final
// component must not be a symlink.
func ReplaceFile(path string, data []byte, mode os.FileMode) error {
	if info, err := os.Lstat(path); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s is a symbolic link", path)
	}
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".compose-sops-*")
	if err != nil {
		return fmt.Errorf("cannot create temporary file in %s: %w", dir, err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return fmt.Errorf("cannot set mode on %s: %w", tmpName, err)
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("cannot write %s: %w", tmpName, err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("cannot sync %s: %w", tmpName, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("cannot close %s: %w", tmpName, err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("cannot move %s to %s: %w", tmpName, path, err)
	}
	return nil
}

// SyncDir fsyncs a directory so that entry changes survive (as much as tmpfs
// allows).
func SyncDir(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}

func deref(p *int) int {
	if p == nil {
		return -1
	}
	return *p
}
