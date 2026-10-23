// The on-disk secret layout under the runtime directory, with lifecycle
// semantics required by the provider:
//
//	<runtime-dir>/<project>/<provider-service>/<secret-name>
//
// Publication is atomic (private staging directory renamed into place),
// protected by a per project/service flock, and refuses symlinks everywhere.

package provider

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"

	"golang.org/x/sys/unix"

	"github.com/greboid/compose-sops/internal/sops"
	"github.com/greboid/compose-sops/internal/system"
)

// ValidateName reports whether component is safe to use as a single path
// component under the runtime directory.
func ValidateName(component string) error {
	if component == "" || len(component) > 128 {
		return fmt.Errorf("invalid name %q: must be 1-128 characters", component)
	}
	for i, r := range component {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_', r == '.', r == '-':
		default:
			return fmt.Errorf("invalid name %q: character %q at position %d is not allowed", component, r, i)
		}
		if i == 0 {
			if r == '.' || r == '-' {
				return fmt.Errorf("invalid name %q: must start with a letter or digit", component)
			}
		}
	}
	return nil
}

// Store is a validated runtime directory root.
type Store struct {
	root string
}

// Open validates runtimeDir for use: it must exist, be a real (non-symlink)
// directory, not be group/world writable, be owned by the current user (or
// the process must be root), and live on a tmpfs filesystem.
func Open(runtimeDir string) (*Store, error) {
	clean, err := system.CleanNoSymlinks(runtimeDir)
	if err != nil {
		return nil, err
	}
	info, err := os.Lstat(clean)
	if err != nil {
		return nil, fmt.Errorf("runtime dir %s: %w", clean, err)
	}
	if !info.Mode().IsDir() {
		return nil, fmt.Errorf("runtime dir %s is not a directory", clean)
	}
	if info.Mode().Perm()&0o022 != 0 {
		return nil, fmt.Errorf("runtime dir %s must not be group or world writable", clean)
	}
	euid := os.Geteuid()
	if stat, ok := info.Sys().(*unix.Stat_t); ok && euid != 0 {
		if stat.Uid != uint32(euid) {
			return nil, fmt.Errorf("runtime dir %s is owned by uid %d, but compose-sops runs as uid %d", clean, stat.Uid, euid)
		}
	}
	if err := requireTmpfs(clean); err != nil {
		return nil, err
	}
	return &Store{root: clean}, nil
}

// Root returns the validated runtime directory.
func (s *Store) Root() string { return s.root }

// ProjectPath returns <runtime-dir>/<project>.
func (s *Store) ProjectPath(project string) string {
	return filepath.Join(s.root, project)
}

// ServicePath returns <runtime-dir>/<project>/<service>.
func (s *Store) ServicePath(project, service string) string {
	return filepath.Join(s.root, project, service)
}

// SecretPath returns <runtime-dir>/<project>/<service>/<name>.
func (s *Store) SecretPath(project, service, name string) string {
	return filepath.Join(s.root, project, service, name)
}

// lock guards one project/service pair. The lock file lives outside the
// service directory so that `down` can take it before removing the directory.
type lock struct {
	f *os.File
}

// Lock acquires the exclusive project/service lock, creating the project
// directory if needed.
func (s *Store) Lock(project, service string) (*lock, error) {
	if err := ValidateName(project); err != nil {
		return nil, fmt.Errorf("project name: %w", err)
	}
	if err := ValidateName(service); err != nil {
		return nil, fmt.Errorf("service name: %w", err)
	}
	projectDir := s.ProjectPath(project)
	if err := os.MkdirAll(projectDir, 0o711); err != nil {
		return nil, fmt.Errorf("cannot create project directory: %w", err)
	}
	lockPath := filepath.Join(projectDir, "."+service+".lock")
	fd, err := unix.Open(lockPath, unix.O_RDWR|unix.O_CREAT|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return nil, fmt.Errorf("cannot open lock file: %w", err)
	}
	f := os.NewFile(uintptr(fd), lockPath)
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX); err != nil {
		f.Close()
		return nil, fmt.Errorf("cannot acquire lock: %w", err)
	}
	return &lock{f: f}, nil
}

// Release drops the lock.
func (l *lock) Release() {
	if l == nil || l.f == nil {
		return
	}
	_ = unix.Flock(int(l.f.Fd()), unix.LOCK_UN)
	_ = l.f.Close()
	l.f = nil
}

// State describes how published contents relate to desired secrets.
type State int

const (
	// StateAbsent means the service directory does not exist.
	StateAbsent State = iota
	// StateMatch means the published files are byte-identical to the
	// desired secrets (including ownership).
	StateMatch
	// StateMismatch means something differs; Details lists what.
	StateMismatch
)

// Comparison reports the result of Compare.
type Comparison struct {
	State   State
	Details []string // reasons for StateMismatch, secret names only
}

// Compare inspects the published service directory against the desired
// secrets without modifying anything. Owner uid/gid of -1 means "any".
func (s *Store) Compare(project, service string, secrets []sops.Secret, uid, gid int) (Comparison, error) {
	serviceDir := s.ServicePath(project, service)
	info, err := os.Lstat(serviceDir)
	if errors.Is(err, fs.ErrNotExist) {
		return Comparison{State: StateAbsent}, nil
	}
	if err != nil {
		return Comparison{}, fmt.Errorf("cannot inspect %s: %w", serviceDir, err)
	}
	if !info.Mode().IsDir() {
		return Comparison{State: StateMismatch, Details: []string{"service path is not a directory"}}, nil
	}

	var details []string
	desired := make(map[string]string, len(secrets))
	for _, sec := range secrets {
		desired[sec.Name] = sec.Value
	}

	// Every published entry must be a regular, non-symlink file with
	// identical content.
	entries, err := os.ReadDir(serviceDir)
	if err != nil {
		return Comparison{}, fmt.Errorf("cannot list %s: %w", serviceDir, err)
	}
	published := make(map[string]struct{}, len(entries))
	for _, entry := range entries {
		published[entry.Name()] = struct{}{}
		if _, ok := desired[entry.Name()]; !ok {
			details = append(details, fmt.Sprintf("unexpected file %q", entry.Name()))
			continue
		}
		if !entry.Type().IsRegular() {
			details = append(details, fmt.Sprintf("%q is not a regular file", entry.Name()))
			continue
		}
		content, err := system.ReadFileBounded(filepath.Join(serviceDir, entry.Name()), int64(len(desired[entry.Name()]))+1)
		if err != nil {
			details = append(details, fmt.Sprintf("%q unreadable", entry.Name()))
			continue
		}
		if string(content) != desired[entry.Name()] {
			details = append(details, fmt.Sprintf("%q content differs", entry.Name()))
		}
		entryInfo, infoErr := entry.Info()
		if infoErr == nil {
			if st, ok := entryInfo.Sys().(*unix.Stat_t); ok {
				if uid >= 0 && st.Uid != uint32(uid) {
					details = append(details, fmt.Sprintf("%q owner differs", entry.Name()))
				}
				if gid >= 0 && st.Gid != uint32(gid) {
					details = append(details, fmt.Sprintf("%q group differs", entry.Name()))
				}
			}
		}
	}
	for name := range desired {
		if _, ok := published[name]; !ok {
			details = append(details, fmt.Sprintf("missing file %q", name))
		}
	}
	if len(details) > 0 {
		sort.Strings(details)
		return Comparison{State: StateMismatch, Details: details}, nil
	}
	return Comparison{State: StateMatch}, nil
}

// Provision publishes secrets atomically: a private staging directory is
// filled, fsynced, then renamed over the (absent) service directory. Fails
// without touching any published state if the service directory exists.
func (s *Store) Provision(project, service string, secrets []sops.Secret, uid, gid *int) error {
	projectDir := s.ProjectPath(project)
	serviceDir := s.ServicePath(project, service)

	if info, err := os.Lstat(serviceDir); err == nil {
		return fmt.Errorf("service directory %s already exists (%s); refusing to republish", serviceDir, describeMode(info.Mode()))
	} else if !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("cannot inspect service directory: %w", err)
	}

	staging, err := os.MkdirTemp(projectDir, ".staging-"+service+"-")
	if err != nil {
		return fmt.Errorf("cannot create staging directory: %w", err)
	}
	// MkdirTemp already used 0700. Remove it on any failure path.
	published := false
	defer func() {
		if !published {
			_ = os.RemoveAll(staging)
		}
	}()

	for _, sec := range secrets {
		if err := system.WriteNewFile(staging, sec.Name, []byte(sec.Value), uid, gid); err != nil {
			return fmt.Errorf("staging: %w", err)
		}
	}
	if err := system.SyncDir(staging); err != nil {
		return fmt.Errorf("cannot sync staging directory: %w", err)
	}
	// Allow traversal for the consumer uid; files stay 0400.
	if err := os.Chmod(staging, 0o711); err != nil {
		return fmt.Errorf("cannot finalize staging directory permissions: %w", err)
	}
	if err := os.Rename(staging, serviceDir); err != nil {
		return fmt.Errorf("cannot publish service directory: %w", err)
	}
	published = true
	if err := system.SyncDir(projectDir); err != nil {
		return fmt.Errorf("cannot sync project directory: %w", err)
	}
	return nil
}

// CleanStaging removes leftover staging directories for this service. Only
// safe while holding the service lock: no live provisioning can exist.
func (s *Store) CleanStaging(project, service string) {
	matches, _ := filepath.Glob(filepath.Join(s.ProjectPath(project), ".staging-"+service+"-*"))
	for _, m := range matches {
		_ = os.RemoveAll(m)
	}
}

// Remove deletes the service directory. It succeeds when the directory is
// already absent and refuses to follow a symlink planted in its place.
func (s *Store) Remove(project, service string) error {
	serviceDir := s.ServicePath(project, service)
	info, err := os.Lstat(serviceDir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("cannot inspect %s: %w", serviceDir, err)
	}
	if info.Mode()&fs.ModeSymlink != 0 {
		return fmt.Errorf("%s is a symbolic link; refusing to remove", serviceDir)
	}
	if !info.Mode().IsDir() {
		return fmt.Errorf("%s is not a directory; refusing to remove", serviceDir)
	}
	if err := os.RemoveAll(serviceDir); err != nil {
		return fmt.Errorf("cannot remove %s: %w", serviceDir, err)
	}
	if err := system.SyncDir(s.ProjectPath(project)); err != nil {
		return fmt.Errorf("cannot sync project directory: %w", err)
	}
	return nil
}

func describeMode(m fs.FileMode) string {
	switch {
	case m&fs.ModeSymlink != 0:
		return "symlink"
	case m.IsDir():
		return "directory"
	default:
		return "non-directory"
	}
}
