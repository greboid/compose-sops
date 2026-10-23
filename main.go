// Command compose-sops is a Compose provider that materializes a
// SOPS-encrypted YAML file as individual secret files on host tmpfs, plus
// host tooling for systemd-creds-based key management.
package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/greboid/compose-sops/internal/cli"
	"github.com/greboid/compose-sops/internal/provider"
)

func main() {
	os.Exit(run())
}

func run() int {
	// Graceful cancellation: staging cleanup runs through defers on the
	// first signal; a second signal kills the process immediately.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		cancel()
	}()

	cmd, err := cli.Parse(os.Args[1:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "compose-sops: %s\n\n%s", err, cli.UsageText())
		return cli.ExitUsage
	}

	stdout := os.Stdout
	stderr := os.Stderr

	if cmd.Name == "metadata" {
		if err := cli.RunMetadata(stdout); err != nil {
			fmt.Fprintf(stderr, "compose-sops: %s\n", err)
			return cli.ExitFailure
		}
		return cli.ExitSuccess
	}

	switch cmd.Name {
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
		if err := cli.RunEncrypt(cmd, stdout); err != nil {
			return fail(stderr, err)
		}
		return cli.ExitSuccess
	case "install":
		if err := cli.RunInstall(cmd, stdout); err != nil {
			return fail(stderr, err)
		}
		return cli.ExitSuccess
	case "setup":
		if err := cli.RunSetup(cli.SetupOptions{In: os.Stdin, Out: stdout, Err: stderr}); err != nil {
			return fail(stderr, err)
		}
		return cli.ExitSuccess
	}

	emit := provider.NewEmitter(stdout)

	p := provider.New(nil, nil, emit)
	opts := provider.Options{
		File:       cmd.Options.File,
		AgeKeyFile: cmd.Options.AgeKeyFile,
		RuntimeDir: cmd.Options.RuntimeDir,
		OwnerUID:   cmd.Options.OwnerUID,
		OwnerGID:   cmd.Options.OwnerGID,
	}

	var runErr error
	switch cmd.Name {
	case "up":
		runErr = p.Up(cmd.ProjectName, cmd.Service, opts)
	case "down":
		runErr = p.Down(cmd.ProjectName, cmd.Service, opts)
	case "stop":
		runErr = p.Stop(cmd.ProjectName, cmd.Service, opts)
	}
	if ctx.Err() != nil && runErr == nil {
		runErr = fmt.Errorf("interrupted")
	}

	if runErr != nil {
		emit.Error(runErr.Error())
		fmt.Fprintf(stderr, "compose-sops: %s\n", runErr.Error())
		return cli.ExitFailure
	}
	return cli.ExitSuccess
}

func fail(stderr io.Writer, err error) int {
	fmt.Fprintf(stderr, "compose-sops: %s\n", err)
	return cli.ExitFailure
}
