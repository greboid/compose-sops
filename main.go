// Command compose-sops is a Docker volume plugin that publishes
// SOPS-encrypted YAML documents as secret files on tmpfs, plus host tooling
// for systemd-creds-based key management.
package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/greboid/compose-sops/internal/cli"
)

func main() {
	os.Exit(run())
}

func run() int {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	cmd, err := cli.Parse(os.Args[1:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "compose-sops: %s\n\n%s", err, cli.UsageText())
		return cli.ExitUsage
	}

	stdout := os.Stdout
	stderr := os.Stderr

	switch cmd.Name {
	case "plugin":
		if err := cli.RunPlugin(ctx, cmd, stdout); err != nil {
			return fail(stderr, err)
		}
		return cli.ExitSuccess
	case "keygen":
		if err := cli.RunKeygen(cmd, stdout, stderr, os.Stdin); err != nil {
			return fail(stderr, err)
		}
		return cli.ExitSuccess
	case "cred":
		if err := cli.RunCred(cmd, stdout); err != nil {
			return fail(stderr, err)
		}
		return cli.ExitSuccess
	case "unit":
		if err := cli.RunUnit(cmd, stdout); err != nil {
			return fail(stderr, err)
		}
		return cli.ExitSuccess
	case "encrypt":
		if err := cli.RunEncrypt(cmd, stdout, os.Stdin); err != nil {
			return fail(stderr, err)
		}
		return cli.ExitSuccess
	case "install":
		if err := cli.RunInstall(cmd, stdout); err != nil {
			return fail(stderr, err)
		}
		return cli.ExitSuccess
	case "recipient":
		if err := cli.RunRecipient(cmd, stdout); err != nil {
			return fail(stderr, err)
		}
		return cli.ExitSuccess
	case "check":
		if err := cli.RunCheck(cmd, stdout, os.Stdin); err != nil {
			return fail(stderr, err)
		}
		return cli.ExitSuccess
	case "rekey":
		if err := cli.RunRekey(cmd, stdout, os.Stdin); err != nil {
			return fail(stderr, err)
		}
		return cli.ExitSuccess
	case "decrypt":
		if err := cli.RunDecrypt(cmd, stdout, os.Stdin); err != nil {
			return fail(stderr, err)
		}
		return cli.ExitSuccess
	case "setup":
		if err := cli.RunSetup(cli.SetupOptions{In: os.Stdin, Out: stdout, Err: stderr}); err != nil {
			return fail(stderr, err)
		}
		return cli.ExitSuccess
	}

	return fail(stderr, fmt.Errorf("unhandled command %q", cmd.Name))
}

func fail(stderr io.Writer, err error) int {
	fmt.Fprintf(stderr, "compose-sops: %s\n", err)
	return cli.ExitFailure
}
