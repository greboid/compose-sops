// Setup implements `compose-sops setup`: an interactive walkthrough that
// installs the binary, generates an age key, seals it into a systemd
// encrypted credential, installs the decrypt-on-boot unit, optionally
// enables it, and optionally encrypts a first secrets file. It never offers
// a backup key: documents are encrypted to the generated key alone.

package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/greboid/compose-sops/internal/sops"
	"github.com/greboid/compose-sops/internal/system"
)

// Runner executes host commands (systemctl); overridable in tests.
type SetupRunner func(ctx context.Context, name string, args ...string) error

// SetupOptions carries the wizard's I/O and injection points.
type SetupOptions struct {
	In     io.Reader
	Out    io.Writer
	Err    io.Writer
	Runner SetupRunner // defaults to exec.Command
	// NewClient builds the io.systemd.Credentials varlink client; tests
	// point it at a fake server.
	NewClient func() (*system.CredsClient, error)
	// CheckSocket is the socket preflight; tests override it.
	CheckSocket func() bool
	// RuntimeKey is where the generated unit materializes the key;
	// defaults to system.RuntimeKey.
	RuntimeKey string
}

// RunSetup drives the wizard through all steps and returns the first failure.
// Steps are ordered so nothing is installed before its inputs exist; each
// step's prompt shows the default path it will use.
func RunSetup(opts SetupOptions) error {
	if opts.In == nil {
		opts.In = strings.NewReader("")
	}
	if opts.Out == nil {
		opts.Out = io.Discard
	}
	if opts.Err == nil {
		opts.Err = io.Discard
	}
	if opts.Runner == nil {
		opts.Runner = defaultRunner
	}
	if opts.NewClient == nil {
		opts.NewClient = system.NewCredsClient
	}
	if opts.CheckSocket == nil {
		opts.CheckSocket = system.SocketExists
	}
	runtimeKey := opts.RuntimeKey
	if runtimeKey == "" {
		runtimeKey = system.RuntimeKey
	}
	p := newPrompter(opts.In, opts.Out)
	out := opts.Out

	fmt.Fprintln(out, "compose-sops setup")
	fmt.Fprintln(out, "This wizard installs the binary, generates an age key, seals it into a")
	fmt.Fprintln(out, "systemd encrypted credential (io.systemd.Credentials over varlink),")
	fmt.Fprintln(out, "installs a unit that decrypts it to tmpfs at boot, and optionally")
	fmt.Fprintln(out, "encrypts your first secrets file.")
	fmt.Fprintln(out)

	if !opts.CheckSocket() {
		return fmt.Errorf("systemd credential varlink socket not found (tried /run/systemd/io.systemd.Credentials and /run/varlink/registry/io.systemd.Credentials): this wizard requires systemd >= 258 with systemd-creds.socket active; resolve this first (check 'systemctl status systemd-creds.socket') and re-run setup")
	}

	// Step 1: install the binary globally.
	installPath, err := p.Ask("Global binary path", system.Install)
	if err != nil {
		return err
	}
	src, err := system.InstallBinary(installPath)
	if err != nil {
		return fmt.Errorf("install: %w", err)
	}
	if src == installPath {
		fmt.Fprintf(out, "installed: already at %s\n", installPath)
	} else {
		fmt.Fprintf(out, "installed: %s -> %s\n", src, installPath)
	}

	// Step 2: generate the age key.
	keyPath, err := p.Ask("Path for the new age key", system.Key)
	if err != nil {
		return err
	}
	recipient, err := sops.GenerateKey(keyPath)
	if err != nil {
		return fmt.Errorf("keygen: %w", err)
	}
	fmt.Fprintf(out, "key:       %s (mode 0600)\nrecipient: %s\n", keyPath, recipient)

	// Step 3: seal the key into a systemd credential.
	credPath, err := p.Ask("Path for the encrypted credential", system.Cred)
	if err != nil {
		return err
	}
	withKey, err := p.Choose("Bind the credential to", []string{"host", "tpm2", "host+tpm2", "auto"}, "auto")
	if err != nil {
		return err
	}
	client, err := opts.NewClient()
	if err != nil {
		return err
	}
	keyData, err := system.ReadFileBounded(keyPath, maxKeyFileSize)
	if err != nil {
		return fmt.Errorf("read back key: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	credFile, err := client.Encrypt(ctx, system.CredName, keyData, withKey)
	if err != nil {
		return fmt.Errorf("seal credential: %w", err)
	}
	if err := system.WriteNewPathed(credPath, []byte(credFile), 0o600); err != nil {
		return fmt.Errorf("write credential: %w", err)
	}
	fmt.Fprintf(out, "credential: %s (mode 0600, name %s, bound to %s)\n", credPath, system.CredName, withKey)

	// Step 4: install the decrypt-on-boot unit.
	unitPath, err := p.Ask("Systemd unit path", system.Unit)
	if err != nil {
		return err
	}
	unitName, err := system.InstallUnit(unitPath, system.GenerateUnit(credPath, system.CredName, runtimeKey))
	if err != nil {
		return fmt.Errorf("unit: %w", err)
	}
	fmt.Fprintf(out, "unit:      %s\n", unitPath)

	// Step 5: optionally enable and start the unit now.
	enable, err := p.Confirm("Enable and start the unit now (runs 'systemctl daemon-reload' and 'systemctl enable --now')?", true)
	if err != nil {
		return err
	}
	if enable {
		if err := opts.Runner(ctx, "systemctl", "daemon-reload"); err != nil {
			return fmt.Errorf("systemctl daemon-reload: %w (run 'systemctl daemon-reload && systemctl enable --now %s' manually)", err, unitName)
		}
		if err := opts.Runner(ctx, "systemctl", "enable", "--now", unitName); err != nil {
			return fmt.Errorf("systemctl enable --now: %w (run 'systemctl enable --now %s' manually)", err, unitName)
		}
		if err := waitForKey(opts.Runner, runtimeKey); err != nil {
			return fmt.Errorf("unit started but the key did not appear: %w", err)
		}
		fmt.Fprintf(out, "key:       materialized at %s\n", runtimeKey)
	} else {
		fmt.Fprintf(out, "skipped; run 'systemctl daemon-reload && systemctl enable --now %s' later\n", unitName)
	}

	// Step 6: optionally encrypt a first secrets file. Deliberately no
	// backup key prompt: the document is sealed to the generated key only.
	inputPath, err := p.Ask("Plaintext secrets file to encrypt now (blank to skip)", "")
	if err != nil {
		return err
	}
	if inputPath != "" {
		recipients, err := sops.Recipients(keyPath)
		if err != nil {
			return fmt.Errorf("encrypt: %w", err)
		}
		plaintext, err := system.ReadFileBounded(inputPath, int64(sops.DefaultLimits.MaxTotalSize))
		if err != nil {
			return fmt.Errorf("encrypt: cannot read input: %w", err)
		}
		defaultOutput := defaultOutputName(inputPath)
		outputPath, err := p.Ask("Output path for the encrypted file", defaultOutput)
		if err != nil {
			return err
		}
		encrypted, err := sops.Encrypt(plaintext, inputPath, recipients, sops.DefaultLimits)
		if err != nil {
			return fmt.Errorf("encrypt: %w", err)
		}
		if err := system.ReplaceFile(outputPath, encrypted, 0o600); err != nil {
			return fmt.Errorf("encrypt: cannot write %s: %w", outputPath, err)
		}
		fmt.Fprintf(out, "encrypted: %s -> %s (mode 0600)\n", inputPath, outputPath)
	}

	fmt.Fprintln(out)
	fmt.Fprintln(out, "Setup complete. Provider options for your compose.yaml:")
	fmt.Fprintf(out, "  file: %s\n", "<your secrets.sops.yaml>")
	fmt.Fprintf(out, "  age-key-file: %s\n", runtimeKey)
	fmt.Fprintf(out, "  runtime-dir: <an existing tmpfs directory>\n")
	return nil
}

// waitForKey polls briefly for the materialized key and validates it, so a
// unit that starts but fails to decrypt is caught while the wizard runs.
func waitForKey(runner SetupRunner, keyPath string) error {
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, err := system.StatNoFollow(keyPath); err == nil {
			if _, err := sops.LoadIdentities(keyPath); err != nil {
				return fmt.Errorf("%s is not a valid age key file: %s", keyPath, err)
			}
			return nil
		} else if !os.IsNotExist(err) {
			return err
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("timed out waiting for %s (check 'systemctl status compose-sops-key.service')", keyPath)
		}
		time.Sleep(250 * time.Millisecond)
	}
}

// defaultOutputName turns secrets.yaml into secrets.sops.yaml.
func defaultOutputName(input string) string {
	dir, base := filepath.Split(input)
	if ext := filepath.Ext(base); ext == ".yaml" || ext == ".yml" {
		base = strings.TrimSuffix(base, ext) + ".sops.yaml"
	} else {
		base += ".sops.yaml"
	}
	return dir + base
}

func defaultRunner(ctx context.Context, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdout = nil
	cmd.Stderr = nil
	return cmd.Run()
}
