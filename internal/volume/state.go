package volume

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"

	"github.com/greboid/compose-sops/internal/system"
)

const stateFile = "volumes.json"

// record is one persisted volume. It never holds document contents.
type record struct {
	File string   `json:"file"`
	Keys []string `json:"keys,omitempty"`
	UID  *int     `json:"uid,omitempty"`
	GID  *int     `json:"gid,omitempty"`
	// Refs are the IDs Docker mounted the volume for.
	Refs []string `json:"refs,omitempty"`
}

func (r *record) sameOptions(o *record) bool {
	return r.File == o.File && slices.Equal(r.Keys, o.Keys) && eqInt(r.UID, o.UID) && eqInt(r.GID, o.GID)
}

func eqInt(a, b *int) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

type state struct {
	path    string
	Version int                `json:"version"`
	Volumes map[string]*record `json:"volumes"`
}

func loadState(dir string) (*state, error) {
	st := &state{path: filepath.Join(dir, stateFile), Version: 1, Volumes: map[string]*record{}}
	data, err := system.ReadFileBounded(st.path, 16<<20)
	if errors.Is(err, os.ErrNotExist) {
		return st, nil
	}
	if err != nil {
		return nil, fmt.Errorf("cannot read state: %w", err)
	}
	if err := json.Unmarshal(data, st); err != nil {
		return nil, fmt.Errorf("cannot parse state %s: %w", st.path, err)
	}
	if st.Version != 1 {
		return nil, fmt.Errorf("unsupported state version %d in %s", st.Version, st.path)
	}
	if st.Volumes == nil {
		st.Volumes = map[string]*record{}
	}
	for name := range st.Volumes {
		if err := ValidateName(name); err != nil {
			return nil, fmt.Errorf("state %s: %w", st.path, err)
		}
	}
	return st, nil
}

func (s *state) save() error {
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	if err := system.ReplaceFile(s.path, append(data, '\n'), 0o600); err != nil {
		return fmt.Errorf("cannot save state: %w", err)
	}
	return nil
}
