package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/greboid/compose-sops/internal/provider"
	"github.com/greboid/compose-sops/internal/sops"
	"github.com/greboid/compose-sops/internal/system"
)

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
// plaintext YAML input with the recipients derived from the key file.
func RunEncrypt(cmd *Command, stdout io.Writer) error {
	plaintext, err := system.ReadFileBounded(cmd.EncryptInput, int64(sops.DefaultLimits.MaxTotalSize))
	if err != nil {
		return fmt.Errorf("cannot read input: %w", err)
	}
	recipients, err := sops.Recipients(cmd.EncryptKeyFile)
	if err != nil {
		return err
	}
	encrypted, err := sops.Encrypt(plaintext, cmd.EncryptInput, recipients, sops.DefaultLimits)
	if err != nil {
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

// readInput reads a check or rekey INPUT, with "-" meaning stdin.
func readInput(path string, stdin io.Reader) ([]byte, error) {
	if path != "-" {
		return system.ReadFileBounded(path, provider.MaxEncryptedFileSize)
	}
	raw, err := io.ReadAll(io.LimitReader(stdin, provider.MaxEncryptedFileSize+1))
	if err != nil {
		return nil, fmt.Errorf("cannot read stdin: %w", err)
	}
	if len(raw) > provider.MaxEncryptedFileSize {
		return nil, fmt.Errorf("stdin exceeds the %d byte limit", provider.MaxEncryptedFileSize)
	}
	return raw, nil
}

// RunRecipient implements `compose-sops recipient`.
func RunRecipient(cmd *Command, stdout io.Writer) error {
	ids, err := sops.LoadIdentities(cmd.EncryptKeyFile)
	if err != nil {
		return err
	}
	for _, r := range sops.IdentityRecipients(ids) {
		fmt.Fprintln(stdout, r)
	}
	return nil
}

// RunCheck implements `compose-sops check`. It never publishes or removes files.
func RunCheck(cmd *Command, stdout io.Writer, stdin io.Reader) error {
	encrypted, err := readInput(cmd.Input, stdin)
	if err != nil {
		return fmt.Errorf("cannot read encrypted file: %w", err)
	}
	ids, err := sops.LoadIdentities(cmd.EncryptKeyFile)
	if err != nil {
		return err
	}
	secrets, err := sops.NewDecryptor(ids, sops.DefaultLimits).DecryptYAML(encrypted)
	if err != nil {
		return err
	}
	if cmd.Options.RuntimeDir == "" {
		_, err = fmt.Fprintln(stdout, "valid")
		return err
	}
	if err := provider.ValidateName(cmd.ProjectName); err != nil {
		return fmt.Errorf("project name: %w", err)
	}
	if err := provider.ValidateName(cmd.Service); err != nil {
		return fmt.Errorf("service name: %w", err)
	}
	if _, err := os.Lstat(cmd.Options.RuntimeDir); errors.Is(err, os.ErrNotExist) {
		_, err = fmt.Fprintln(stdout, "absent")
		return err
	}
	st, err := provider.Open(cmd.Options.RuntimeDir)
	if err != nil {
		return err
	}
	uid, gid := -1, -1
	if cmd.Options.OwnerUID != nil {
		uid, gid = *cmd.Options.OwnerUID, *cmd.Options.OwnerGID
	}
	cmp, err := st.Compare(cmd.ProjectName, cmd.Service, secrets, uid, gid)
	if err != nil {
		return err
	}
	state := map[provider.State]string{provider.StateAbsent: "absent", provider.StateMatch: "unchanged", provider.StateMismatch: "changed"}[cmp.State]
	_, err = fmt.Fprintln(stdout, state)
	return err
}

// RunRekey implements `compose-sops rekey`. The identity is only loaded
// when the recipients change.
func RunRekey(cmd *Command, stdout io.Writer, stdin io.Reader) error {
	encrypted, err := readInput(cmd.Input, stdin)
	if err != nil {
		return fmt.Errorf("cannot read encrypted file: %w", err)
	}
	out, _, err := sops.Rekey(encrypted, nil, cmd.Add, cmd.Remove, sops.DefaultLimits)
	if errors.Is(err, sops.ErrIdentityRequired) {
		ids, loadErr := sops.LoadIdentities(cmd.EncryptKeyFile)
		if loadErr != nil {
			return loadErr
		}
		out, _, err = sops.Rekey(encrypted, ids, cmd.Add, cmd.Remove, sops.DefaultLimits)
	}
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
	ids, err := sops.LoadIdentities(cmd.EncryptKeyFile)
	if err != nil {
		return err
	}
	secrets, err := sops.NewDecryptor(ids, sops.DefaultLimits).DecryptYAML(encrypted)
	if err != nil {
		return err
	}
	out := make(map[string]string, len(secrets))
	for _, s := range secrets {
		out[s.Name] = s.Value
	}
	return json.NewEncoder(stdout).Encode(out)
}
