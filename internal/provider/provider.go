// Package provider implements the compose-sops lifecycle commands of the
// Compose provider interface: up (decrypt and publish), down (remove), and
// stop (retain files so containers can restart).
package provider

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/greboid/compose-sops/internal/sops"
	"github.com/greboid/compose-sops/internal/system"
)

// MaxEncryptedFileSize bounds the encrypted input read.
const MaxEncryptedFileSize = 1 << 20 // 1 MiB

// Options are the provider options, translated by Compose from the
// provider.options block into command line flags.
type Options struct {
	// File is the path to the SOPS-encrypted YAML document.
	File string
	// AgeKeyFile is the host age identity file.
	AgeKeyFile string
	// RuntimeDir is the existing tmpfs root for published secrets.
	RuntimeDir string
	// OwnerUID/OwnerGID, when set, are applied to published secret files.
	// Bind mounts preserve ownership, so this is how a non-root application
	// inside the container gains read access.
	OwnerUID *int
	OwnerGID *int
}

// Decryptor decrypts SOPS documents on behalf of the provider. Defined in
// the consuming package so that changes to SOPS package APIs stay contained
// in sops.
type Decryptor interface {
	// DecryptYAML verifies the MAC and returns the flat secret mapping.
	DecryptYAML(encrypted []byte) ([]sops.Secret, error)
}

// Provider executes lifecycle commands against a runtime directory.
type Provider struct {
	decryptor Decryptor
	st        *Store
	emit      *Emitter
}

// New builds a Provider. The decryptor is injected so tests can substitute
// the SOPS-backed implementation.
func New(d Decryptor, st *Store, emit *Emitter) *Provider {
	return &Provider{decryptor: d, st: st, emit: emit}
}

// validateUp checks the options required for provisioning.
func (o Options) validateUp() error {
	if o.File == "" {
		return fmt.Errorf("missing required option --file (path to the SOPS-encrypted YAML file)")
	}
	if o.AgeKeyFile == "" {
		return fmt.Errorf("missing required option --age-key-file (path to the host age identity file)")
	}
	if o.RuntimeDir == "" {
		return fmt.Errorf("missing required option --runtime-dir (existing tmpfs directory for secrets)")
	}
	return nil
}

// Up materializes the decrypted secrets under
// <runtime-dir>/<project>/<service>/<secret-name>.
//
// It is idempotent: when the published files are byte-identical (including
// ownership), nothing is written and inodes are preserved. Any difference
// fails with instructions to rotate via down + up, because replacing files
// underneath running containers silently leaves them bound to old inodes.
func (p *Provider) Up(project, service string, opts Options) error {
	if err := opts.validateUp(); err != nil {
		return err
	}
	if err := ValidateName(project); err != nil {
		return fmt.Errorf("project name: %w", err)
	}
	if err := ValidateName(service); err != nil {
		return fmt.Errorf("service name: %w", err)
	}

	st, err := Open(opts.RuntimeDir)
	if err != nil {
		return err
	}
	p.st = st

	encrypted, err := system.ReadFileBounded(opts.File, MaxEncryptedFileSize)
	if err != nil {
		return fmt.Errorf("cannot read encrypted file: %w", err)
	}
	p.emit.Info(fmt.Sprintf("loaded encrypted file %s (%d bytes)", opts.File, len(encrypted)))

	ids, err := sops.LoadIdentities(opts.AgeKeyFile)
	if err != nil {
		return fmt.Errorf("cannot load age identity: %w", err)
	}
	p.decryptor = sops.NewDecryptor(ids, sops.DefaultLimits)

	secrets, err := p.decryptor.DecryptYAML(encrypted)
	if err != nil {
		return fmt.Errorf("decryption failed: %w", err)
	}
	p.emit.Info(fmt.Sprintf("decrypted %d secrets", len(secrets)))

	lk, err := st.Lock(project, service)
	if err != nil {
		return fmt.Errorf("cannot acquire lock: %w", err)
	}
	defer lk.Release()

	// Crash-orphaned staging directories cannot be live while the lock is
	// held; remove them.
	st.CleanStaging(project, service)

	serviceDir := st.ServicePath(project, service)
	cmp, err := st.Compare(project, service, secrets, derefInt(opts.OwnerUID), derefInt(opts.OwnerGID))
	if err != nil {
		return err
	}
	switch cmp.State {
	case StateMatch:
		p.emit.Info(fmt.Sprintf("secrets unchanged, retaining files under %s", serviceDir))
		return nil
	case StateMismatch:
		return fmt.Errorf(
			"published secrets under %s differ from the encrypted file (%s); secrets are never replaced underneath existing containers: run 'docker compose down' and then 'docker compose up' to apply the change",
			serviceDir, strings.Join(cmp.Details, ", "),
		)
	}

	if err := st.Provision(project, service, secrets, opts.OwnerUID, opts.OwnerGID); err != nil {
		// Failed initial provisioning removes staging files (Provision does
		// this itself); nothing published exists on failure.
		return fmt.Errorf("provisioning failed: %w", err)
	}
	p.emit.Info(fmt.Sprintf("provisioned %d secrets under %s", len(secrets), serviceDir))
	return nil
}

// Down removes the provider's service directory. It succeeds when the
// directory (or the entire runtime directory) is already absent, so
// teardown is idempotent. The encrypted file and identity are not needed.
func (p *Provider) Down(project, service string, opts Options) error {
	if err := ValidateName(project); err != nil {
		return fmt.Errorf("project name: %w", err)
	}
	if err := ValidateName(service); err != nil {
		return fmt.Errorf("service name: %w", err)
	}
	if opts.RuntimeDir == "" {
		return fmt.Errorf("missing required option --runtime-dir")
	}

	if _, err := os.Lstat(opts.RuntimeDir); errors.Is(err, os.ErrNotExist) {
		p.emit.Info("runtime dir absent, nothing to remove")
		return nil
	}

	st, err := Open(opts.RuntimeDir)
	if err != nil {
		return err
	}
	p.st = st

	lk, err := st.Lock(project, service)
	if err != nil {
		return fmt.Errorf("cannot acquire lock: %w", err)
	}
	defer lk.Release()

	st.CleanStaging(project, service)
	if _, err := os.Lstat(st.ServicePath(project, service)); errors.Is(err, os.ErrNotExist) {
		p.emit.Info("service directory already absent")
		return nil
	}
	if err := st.Remove(project, service); err != nil {
		return err
	}
	p.emit.Info(fmt.Sprintf("removed %s", st.ServicePath(project, service)))
	return nil
}

// Stop is a deliberate no-op: files are retained so existing containers can
// restart without re-provisioning (docker compose start does not invoke
// provider hooks).
func (p *Provider) Stop(project, service string, opts Options) error {
	if err := ValidateName(project); err != nil {
		return fmt.Errorf("project name: %w", err)
	}
	if err := ValidateName(service); err != nil {
		return fmt.Errorf("service name: %w", err)
	}
	p.emit.Info("stop: retaining secret files so containers can restart; use 'down' to remove them")
	return nil
}

func derefInt(p *int) int {
	if p == nil {
		return -1
	}
	return *p
}
