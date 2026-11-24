// Package volume implements a Docker volume driver that presents a subset of
// a SOPS-encrypted document as read-only 0400 files on a private tmpfs.
//
// Only volume options are persisted. The document is read and decrypted on
// the first active mount of a volume, and the tmpfs is removed on the last
// unmount, so a reboot (or a document change followed by restarting the
// consumers) always publishes the current document.
package volume

import (
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"

	"github.com/greboid/compose-sops/internal/sops"
	"github.com/greboid/compose-sops/internal/system"
	"github.com/greboid/compose-sops/secrets"
)

// Mounter manages the filesystem backing one volume.
type Mounter interface {
	// Mount mounts an empty private filesystem at dir with room for the
	// given number of bytes and inodes.
	Mount(dir string, size, inodes int) error
	// Seal makes the filesystem at dir read-only.
	Seal(dir string) error
	// Unmount removes the filesystem at dir.
	Unmount(dir string) error
	// Mounted reports whether dir is a mount point.
	Mounted(dir string) (bool, error)
}

// Config locates the driver's inputs and outputs.
type Config struct {
	// Documents is the root directory that volume "file" options are
	// resolved against.
	Documents string
	// KeyFile is the age identity file.
	KeyFile string
	// StateDir persists volume options and active mount IDs.
	StateDir string
	// MountRoot holds one mount point per volume.
	MountRoot string
	Mounter   Mounter
	Log       *log.Logger
}

// Volume is the public view of a volume.
type Volume struct {
	Name       string
	Mountpoint string
	File       string
	Keys       []string
}

// Driver serves volume operations. All methods are safe for concurrent use.
type Driver struct {
	mu    sync.Mutex
	cfg   Config
	state *state
}

// New loads the persisted volumes and reconciles them with the mount table:
// a volume whose mount point is gone (for example after a reboot) has its
// stale mount IDs dropped, and a mounted volume without users is unmounted.
func New(cfg Config) (*Driver, error) {
	if cfg.Log == nil {
		cfg.Log = log.New(io.Discard, "", 0)
	}
	if err := os.MkdirAll(cfg.MountRoot, 0o711); err != nil {
		return nil, fmt.Errorf("cannot create mount root: %w", err)
	}
	st, err := loadState(cfg.StateDir)
	if err != nil {
		return nil, err
	}
	d := &Driver{cfg: cfg, state: st}
	changed := false
	for name, rec := range st.Volumes {
		mp := d.mountpoint(name)
		mounted, err := cfg.Mounter.Mounted(mp)
		if err != nil {
			return nil, err
		}
		switch {
		case !mounted && len(rec.Refs) > 0:
			cfg.Log.Printf("volume %s: not mounted, dropping %d stale mount IDs", name, len(rec.Refs))
			rec.Refs = nil
			changed = true
		case mounted && len(rec.Refs) == 0:
			cfg.Log.Printf("volume %s: mounted without users, unmounting", name)
			if err := d.release(name); err != nil {
				return nil, err
			}
		}
		if !mounted {
			_ = os.Remove(mp)
		}
	}
	if changed {
		if err := st.save(); err != nil {
			return nil, err
		}
	}
	return d, nil
}

// ValidateName reports whether name is usable as a volume name. Docker
// accepts the same character set.
func ValidateName(name string) error {
	if name == "" || len(name) > 128 {
		return fmt.Errorf("invalid volume name %q: must be 1-128 characters", name)
	}
	for i, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case (r == '_' || r == '.' || r == '-') && i > 0:
		default:
			return fmt.Errorf("invalid volume name %q: character %q at position %d is not allowed", name, r, i)
		}
	}
	return nil
}

// parseOptions validates driver options into a record.
func parseOptions(opts map[string]string) (*record, error) {
	rec := &record{}
	for k, v := range opts {
		switch k {
		case "file":
			if v == "" || !filepath.IsLocal(v) {
				return nil, fmt.Errorf("option file %q must be a path relative to the documents root without '..' components", v)
			}
			rec.File = filepath.Clean(v)
		case "keys":
			for key := range strings.SplitSeq(v, ",") {
				key = strings.TrimSpace(key)
				if key == "" {
					continue
				}
				if slices.Contains(rec.Keys, key) {
					return nil, fmt.Errorf("option keys lists %q more than once", key)
				}
				rec.Keys = append(rec.Keys, key)
			}
			if len(rec.Keys) == 0 {
				return nil, fmt.Errorf("option keys is empty; omit it to expose every secret")
			}
		case "uid", "gid":
			n, err := strconv.Atoi(v)
			if err != nil || n < 0 || n > 2147483647 {
				return nil, fmt.Errorf("option %s must be a non-negative integer, got %q", k, v)
			}
			if k == "uid" {
				rec.UID = &n
			} else {
				rec.GID = &n
			}
		default:
			return nil, fmt.Errorf("unknown option %q (expected file, keys, uid, gid)", k)
		}
	}
	if rec.File == "" {
		return nil, fmt.Errorf("missing required option file (path of the encrypted document relative to the documents root)")
	}
	if (rec.UID == nil) != (rec.GID == nil) {
		return nil, fmt.Errorf("options uid and gid must be given together")
	}
	return rec, nil
}

// Create records a volume after verifying that its document decrypts and
// contains the selected keys. Creating an existing volume with identical
// options succeeds.
func (d *Driver) Create(name string, opts map[string]string) error {
	if err := ValidateName(name); err != nil {
		return err
	}
	rec, err := parseOptions(opts)
	if err != nil {
		return err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if existing, ok := d.state.Volumes[name]; ok {
		if existing.sameOptions(rec) {
			return nil
		}
		return fmt.Errorf("volume %s already exists with different options", name)
	}
	if _, err := d.load(rec); err != nil {
		return err
	}
	d.state.Volumes[name] = rec
	if err := d.state.save(); err != nil {
		delete(d.state.Volumes, name)
		return err
	}
	d.cfg.Log.Printf("volume %s: created from %s", name, rec.File)
	return nil
}

// Remove deletes a volume that is not mounted.
func (d *Driver) Remove(name string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	rec, err := d.get(name)
	if err != nil {
		return err
	}
	if len(rec.Refs) > 0 {
		return fmt.Errorf("volume %s is in use by %d mounts", name, len(rec.Refs))
	}
	if err := d.release(name); err != nil {
		return err
	}
	delete(d.state.Volumes, name)
	if err := d.state.save(); err != nil {
		d.state.Volumes[name] = rec
		return err
	}
	d.cfg.Log.Printf("volume %s: removed", name)
	return nil
}

// Mount returns the volume's mount point, publishing the current document
// when this is the first active mount.
func (d *Driver) Mount(name, id string) (string, error) {
	if id == "" {
		return "", fmt.Errorf("missing mount ID")
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	rec, err := d.get(name)
	if err != nil {
		return "", err
	}
	mp := d.mountpoint(name)
	if slices.Contains(rec.Refs, id) {
		return mp, nil
	}
	first := len(rec.Refs) == 0
	if first {
		if err := d.publish(name, rec); err != nil {
			return "", err
		}
	}
	rec.Refs = append(rec.Refs, id)
	if err := d.state.save(); err != nil {
		rec.Refs = rec.Refs[:len(rec.Refs)-1]
		if first {
			_ = d.release(name)
		}
		return "", err
	}
	d.cfg.Log.Printf("volume %s: mounted for %s (%d active)", name, id, len(rec.Refs))
	return mp, nil
}

// Unmount drops one mount ID, removing the published secrets on the last.
// Unknown IDs are ignored.
func (d *Driver) Unmount(name, id string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	rec, err := d.get(name)
	if err != nil {
		return err
	}
	i := slices.Index(rec.Refs, id)
	if i < 0 {
		return nil
	}
	rec.Refs = slices.Delete(rec.Refs, i, i+1)
	if len(rec.Refs) == 0 {
		if err := d.release(name); err != nil {
			rec.Refs = append(rec.Refs, id)
			return err
		}
	}
	if err := d.state.save(); err != nil {
		return err
	}
	d.cfg.Log.Printf("volume %s: unmounted for %s (%d active)", name, id, len(rec.Refs))
	return nil
}

// Path returns the mount point while the volume is mounted, else "".
func (d *Driver) Path(name string) (string, error) {
	v, err := d.Get(name)
	if err != nil {
		return "", err
	}
	return v.Mountpoint, nil
}

// Get describes one volume.
func (d *Driver) Get(name string) (Volume, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	rec, err := d.get(name)
	if err != nil {
		return Volume{}, err
	}
	return d.view(name, rec), nil
}

// List describes every volume, sorted by name.
func (d *Driver) List() []Volume {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make([]Volume, 0, len(d.state.Volumes))
	for name, rec := range d.state.Volumes {
		out = append(out, d.view(name, rec))
	}
	slices.SortFunc(out, func(a, b Volume) int { return strings.Compare(a.Name, b.Name) })
	return out
}

func (d *Driver) view(name string, rec *record) Volume {
	v := Volume{Name: name, File: rec.File, Keys: slices.Clone(rec.Keys)}
	if len(rec.Refs) > 0 {
		v.Mountpoint = d.mountpoint(name)
	}
	return v
}

func (d *Driver) get(name string) (*record, error) {
	rec, ok := d.state.Volumes[name]
	if !ok {
		return nil, fmt.Errorf("no such volume: %s", name)
	}
	return rec, nil
}

func (d *Driver) mountpoint(name string) string {
	return filepath.Join(d.cfg.MountRoot, name)
}

// load reads and decrypts the volume's document and returns the selected
// secrets in document order (or keys order when keys is set).
func (d *Driver) load(rec *record) ([]sops.Secret, error) {
	encrypted, err := readDocument(d.cfg.Documents, rec.File)
	if err != nil {
		return nil, err
	}
	ids, err := sops.LoadIdentities(d.cfg.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("cannot load age identity: %w", err)
	}
	all, err := sops.NewDecryptor(ids, sops.DefaultLimits).DecryptYAML(encrypted)
	if err != nil {
		return nil, fmt.Errorf("cannot decrypt %s: %w", rec.File, err)
	}
	if len(rec.Keys) == 0 {
		return all, nil
	}
	selected := make([]sops.Secret, 0, len(rec.Keys))
	for _, key := range rec.Keys {
		i := slices.IndexFunc(all, func(s sops.Secret) bool { return s.Name == key })
		if i < 0 {
			return nil, fmt.Errorf("%s has no secret named %q", rec.File, key)
		}
		selected = append(selected, all[i])
	}
	return selected, nil
}

// readDocument opens file beneath root, refusing paths and symlinks that
// resolve outside it.
func readDocument(root, file string) ([]byte, error) {
	r, err := os.OpenRoot(root)
	if err != nil {
		return nil, fmt.Errorf("cannot open documents root: %w", err)
	}
	defer r.Close()
	f, err := r.Open(file)
	if err != nil {
		return nil, fmt.Errorf("cannot open document %s: %w", file, err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("cannot stat document %s: %w", file, err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("document %s is not a regular file", file)
	}
	data, err := io.ReadAll(io.LimitReader(f, secrets.MaxDocumentSize+1))
	if err != nil {
		return nil, fmt.Errorf("cannot read document %s: %w", file, err)
	}
	if len(data) > secrets.MaxDocumentSize {
		return nil, fmt.Errorf("document %s exceeds the %d byte limit", file, secrets.MaxDocumentSize)
	}
	return data, nil
}

// publish decrypts the document and writes it to a fresh sealed tmpfs at
// the volume's mount point. Nothing stays mounted on failure.
func (d *Driver) publish(name string, rec *record) (err error) {
	selected, err := d.load(rec)
	if err != nil {
		return err
	}
	mp := d.mountpoint(name)
	if err := os.Mkdir(mp, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return fmt.Errorf("cannot create mount point: %w", err)
	}
	if mounted, err := d.cfg.Mounter.Mounted(mp); err != nil {
		return err
	} else if mounted {
		// Left over from an interrupted release; never reuse old contents.
		if err := d.cfg.Mounter.Unmount(mp); err != nil {
			return err
		}
	}
	const page = 4096
	size := page
	for _, s := range selected {
		size += (len(s.Value)/page + 1) * page
	}
	if err := d.cfg.Mounter.Mount(mp, size, len(selected)+8); err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = d.release(name)
		}
	}()
	for _, s := range selected {
		if err := system.WriteNewFile(mp, s.Name, []byte(s.Value), rec.UID, rec.GID); err != nil {
			return err
		}
	}
	return d.cfg.Mounter.Seal(mp)
}

// release unmounts the volume's tmpfs if mounted and removes the mount point.
func (d *Driver) release(name string) error {
	mp := d.mountpoint(name)
	mounted, err := d.cfg.Mounter.Mounted(mp)
	if err != nil {
		return err
	}
	if mounted {
		if err := d.cfg.Mounter.Unmount(mp); err != nil {
			return err
		}
	}
	if err := os.Remove(mp); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("cannot remove mount point: %w", err)
	}
	return nil
}
