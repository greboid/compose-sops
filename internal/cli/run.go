package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"time"

	"github.com/greboid/compose-sops/internal/sops"
	"github.com/greboid/compose-sops/internal/system"
	"github.com/greboid/compose-sops/internal/volume"
	"github.com/greboid/compose-sops/secrets"
)

// RunPlugin implements `compose-sops plugin`: it serves the Docker volume
// driver API until ctx is done.
func RunPlugin(ctx context.Context, cmd *Command, logw io.Writer) error {
	d, err := volume.New(volume.Config{
		Documents: cmd.Documents,
		KeyFile:   cmd.EncryptKeyFile,
		StateDir:  cmd.StateDir,
		MountRoot: cmd.MountRoot,
		Mounter:   volume.Tmpfs{},
		Log:       log.New(logw, "", 0),
	})
	if err != nil {
		return err
	}
	return volume.Serve(ctx, cmd.Socket, volume.Handler(d))
}

// RunKeygen implements `compose-sops keygen`. It prompts for the output
// path when --output was not given, writes a fresh age identity file, and
// reports the recipient.
func RunKeygen(cmd *Command, stdout, stderr io.Writer, stdin io.Reader) error {
	output := cmd.OutputPath
	if output == "" {
		answered, err := newPrompter(stdin, stderr).Ask("Output path for the new age key", system.Key)
		if err != nil {
			return fmt.Errorf("cannot prompt for the output path (pass --output PATH when stdin is not interactive): %w", err)
		}
		output = answered
	}
	recipient, err := sops.GenerateKey(output)
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "key written to %s (mode 0600)\nrecipient: %s\n", output, recipient)
	return nil
}

// RunCred implements `compose-sops cred`. It seals the age key into a
// systemd encrypted credential over the io.systemd.Credentials varlink
// interface.
func RunCred(cmd *Command, stdout io.Writer) error {
	if _, err := sops.LoadIdentities(cmd.KeyPath); err != nil {
		return err
	}
	keyData, err := system.ReadFileBounded(cmd.KeyPath, maxKeyFileSize)
	if err != nil {
		return fmt.Errorf("cannot read key file: %w", err)
	}
	withKey, err := system.ParseWithKey(cmd.WithKey)
	if err != nil {
		return err
	}
	client, err := system.NewCredsClient()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	credFile, err := client.Encrypt(ctx, cmd.CredName, keyData, withKey)
	if err != nil {
		return err
	}
	if err := system.WriteNewPathed(cmd.CredPath, []byte(credFile), 0o600); err != nil {
		if errors.Is(err, os.ErrExist) {
			return fmt.Errorf("%s already exists; choose another path or remove the old file deliberately", cmd.CredPath)
		}
		return err
	}
	fmt.Fprintf(stdout, "credential written to %s (mode 0600)\nname: %s\nbound to: %s\n", cmd.CredPath, cmd.CredName, cmd.WithKey)
	return nil
}

// RunUnit implements `compose-sops unit`. It prints the generated systemd
// unit to stdout, or writes it to --output when given.
func RunUnit(cmd *Command, stdout io.Writer) error {
	content := system.GenerateUnit(cmd.UnitCredPath, cmd.CredName, system.RuntimeKey)
	if cmd.OutputPath == "" {
		_, err := io.WriteString(stdout, content)
		return err
	}
	if err := system.ReplaceFile(cmd.OutputPath, []byte(content), 0o644); err != nil {
		return fmt.Errorf("cannot write %s: %w", cmd.OutputPath, err)
	}
	fmt.Fprintf(stdout, "unit written to %s\n", cmd.OutputPath)
	return nil
}

// RunEncrypt implements `compose-sops encrypt`. It SOPS-encrypts the flat
// plaintext YAML input with the recipients derived from the key file. INPUT
// and --output may be "-" for stdin and stdout.
func RunEncrypt(cmd *Command, stdout io.Writer, stdin io.Reader) error {
	plaintext, err := readBounded(cmd.EncryptInput, stdin, sops.DefaultLimits.MaxTotalSize)
	if err != nil {
		return fmt.Errorf("cannot read input: %w", err)
	}
	encrypted, err := secrets.Encrypt(cmd.EncryptKeyFile, plaintext)
	if err != nil {
		return err
	}
	if cmd.EncryptOutput == "-" {
		_, err = stdout.Write(encrypted)
		return err
	}
	if err := system.ReplaceFile(cmd.EncryptOutput, encrypted, 0o600); err != nil {
		return fmt.Errorf("cannot write %s: %w", cmd.EncryptOutput, err)
	}
	fmt.Fprintf(stdout, "encrypted %s to %s (mode 0600)\n", cmd.EncryptInput, cmd.EncryptOutput)
	return nil
}

// RunInstall implements `compose-sops install`.
func RunInstall(cmd *Command, stdout io.Writer) error {
	src, err := system.InstallBinary(cmd.InstallPath)
	if err != nil {
		return err
	}
	if src == cmd.InstallPath {
		fmt.Fprintf(stdout, "already installed at %s\n", cmd.InstallPath)
		return nil
	}
	fmt.Fprintf(stdout, "installed %s to %s (mode 0755)\n", src, cmd.InstallPath)
	return nil
}

// maxKeyFileSize bounds the plaintext key read before sealing.
const maxKeyFileSize = 1 << 20 // 1 MiB

// readInput reads an encrypted INPUT, with "-" meaning stdin.
func readInput(path string, stdin io.Reader) ([]byte, error) {
	return readBounded(path, stdin, secrets.MaxDocumentSize)
}

// readBounded reads at most max bytes from path, with "-" meaning stdin.
func readBounded(path string, stdin io.Reader, max int) ([]byte, error) {
	if path != "-" {
		return system.ReadFileBounded(path, int64(max))
	}
	raw, err := io.ReadAll(io.LimitReader(stdin, int64(max)+1))
	if err != nil {
		return nil, fmt.Errorf("cannot read stdin: %w", err)
	}
	if len(raw) > max {
		return nil, fmt.Errorf("stdin exceeds the %d byte limit", max)
	}
	return raw, nil
}

// RunRecipient implements `compose-sops recipient`.
func RunRecipient(cmd *Command, stdout io.Writer) error {
	recipients, err := secrets.Recipients(cmd.EncryptKeyFile)
	if err != nil {
		return err
	}
	for _, r := range recipients {
		fmt.Fprintln(stdout, r)
	}
	return nil
}

// RunCheck implements `compose-sops check`.
func RunCheck(cmd *Command, stdout io.Writer, stdin io.Reader) error {
	encrypted, err := readInput(cmd.Input, stdin)
	if err != nil {
		return fmt.Errorf("cannot read encrypted file: %w", err)
	}
	if err := secrets.Check(cmd.EncryptKeyFile, encrypted); err != nil {
		return err
	}
	_, err = fmt.Fprintln(stdout, "valid")
	return err
}

// RunRekey implements `compose-sops rekey`.
func RunRekey(cmd *Command, stdout io.Writer, stdin io.Reader) error {
	encrypted, err := readInput(cmd.Input, stdin)
	if err != nil {
		return fmt.Errorf("cannot read encrypted file: %w", err)
	}
	out, err := secrets.Rekey(cmd.EncryptKeyFile, encrypted, cmd.Add, cmd.Remove)
	if err != nil {
		return err
	}
	_, err = stdout.Write(out)
	return err
}

// RunDecrypt implements `compose-sops decrypt`. Plaintext goes only to stdout.
func RunDecrypt(cmd *Command, stdout io.Writer, stdin io.Reader) error {
	encrypted, err := readInput(cmd.Input, stdin)
	if err != nil {
		return fmt.Errorf("cannot read encrypted file: %w", err)
	}
	out, err := secrets.Decrypt(cmd.EncryptKeyFile, encrypted)
	if err != nil {
		return err
	}
	return json.NewEncoder(stdout).Encode(out)
}
