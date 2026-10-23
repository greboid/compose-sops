package cli_test

import (
	"strings"
	"testing"

	"github.com/greboid/compose-sops/internal/cli"
	"github.com/greboid/compose-sops/internal/system"
)

func TestParseKeygenDefaults(t *testing.T) {
	cmd, err := cli.Parse([]string{"keygen"})
	if err != nil {
		t.Fatal(err)
	}
	if cmd.Name != "keygen" || cmd.OutputPath != "" {
		t.Fatalf("parsed = %+v", cmd)
	}
}

func TestParseKeygenOutputFlagForms(t *testing.T) {
	for _, args := range [][]string{
		{"keygen", "--output", "/k.txt"},
		{"keygen", "--output=/k.txt"},
	} {
		cmd, err := cli.Parse(args)
		if err != nil {
			t.Fatalf("%v: %v", args, err)
		}
		if cmd.OutputPath != "/k.txt" {
			t.Fatalf("%v: output = %q", args, cmd.OutputPath)
		}
	}
}

func TestParseCredDefaults(t *testing.T) {
	cmd, err := cli.Parse([]string{"cred", "/k.cred"})
	if err != nil {
		t.Fatal(err)
	}
	if cmd.CredPath != "/k.cred" || cmd.KeyPath != system.Key || cmd.CredName != system.CredName {
		t.Fatalf("parsed = %+v", cmd)
	}
	if cmd.WithKey != "auto" {
		t.Fatalf("withKey = %q, want auto", cmd.WithKey)
	}
}

func TestParseCredValidatesWithKey(t *testing.T) {
	if _, err := cli.Parse([]string{"cred", "--with-key", "bogus", "/k.cred"}); err == nil {
		t.Fatal("expected error for bogus --with-key")
	}
	cmd, err := cli.Parse([]string{"cred", "--with-key", "host+tpm2", "/k.cred"})
	if err != nil {
		t.Fatal(err)
	}
	enum, err := system.ParseWithKey(cmd.WithKey)
	if err != nil || enum != "host_tpm2" {
		t.Fatalf("withKey = %q (%v)", cmd.WithKey, err)
	}
}

func TestParseUnitDefaults(t *testing.T) {
	cmd, err := cli.Parse([]string{"unit", "/k.cred"})
	if err != nil {
		t.Fatal(err)
	}
	if cmd.UnitCredPath != "/k.cred" || cmd.CredName != system.CredName || cmd.OutputPath != "" {
		t.Fatalf("parsed = %+v", cmd)
	}
}

func TestParseEncryptRequiresOutput(t *testing.T) {
	if _, err := cli.Parse([]string{"encrypt", "in.yaml"}); err == nil {
		t.Fatal("expected error without --output")
	}
	cmd, err := cli.Parse([]string{"encrypt", "--output", "out.sops.yaml", "--key-file", "/run/k", "in.yaml"})
	if err != nil {
		t.Fatal(err)
	}
	if cmd.EncryptInput != "in.yaml" || cmd.EncryptOutput != "out.sops.yaml" || cmd.EncryptKeyFile != "/run/k" {
		t.Fatalf("parsed = %+v", cmd)
	}
	cmd, err = cli.Parse([]string{"encrypt", "in.yaml", "--output", "out.sops.yaml"})
	if err != nil {
		t.Fatal(err)
	}
	if cmd.EncryptKeyFile != system.RuntimeKey {
		t.Fatalf("default key file = %q, want %q", cmd.EncryptKeyFile, system.RuntimeKey)
	}
}

func TestParseInstallDefaults(t *testing.T) {
	cmd, err := cli.Parse([]string{"install"})
	if err != nil {
		t.Fatal(err)
	}
	if cmd.InstallPath != system.Install {
		t.Fatalf("install path = %q, want %q", cmd.InstallPath, system.Install)
	}
	cmd, err = cli.Parse([]string{"install", "--path=/opt/bin/compose-sops"})
	if err != nil {
		t.Fatal(err)
	}
	if cmd.InstallPath != "/opt/bin/compose-sops" {
		t.Fatalf("install path = %q", cmd.InstallPath)
	}
}

func TestParseSetupTakesNothing(t *testing.T) {
	if _, err := cli.Parse([]string{"setup"}); err != nil {
		t.Fatal(err)
	}
	if _, err := cli.Parse([]string{"setup", "extra"}); err == nil {
		t.Fatal("expected error for positional argument")
	}
	if _, err := cli.Parse([]string{"setup", "--path", "/x"}); err == nil {
		t.Fatal("expected error for flag")
	}
}

func TestParseHostCommandErrors(t *testing.T) {
	cases := [][]string{
		{},
		{"bogus"},
		{"keygen", "positional"},
		{"keygen", "--output"},
		{"cred"},
		{"cred", "a", "b"},
		{"cred", "--bogus", "x", "/k.cred"},
		{"unit"},
		{"unit", "a", "b"},
		{"encrypt"},
		{"encrypt", "a", "b", "--output", "o"},
		{"install", "positional"},
		{"--version"},
	}
	for _, args := range cases {
		if _, err := cli.Parse(args); err == nil {
			t.Fatalf("%v: expected error", args)
		}
	}
}

func TestParseComposeStillWorks(t *testing.T) {
	cmd, err := cli.Parse([]string{"compose", "metadata"})
	if err != nil {
		t.Fatal(err)
	}
	if cmd.Name != "metadata" {
		t.Fatalf("name = %s", cmd.Name)
	}
}

func TestUsageMentionsHostCommands(t *testing.T) {
	for _, want := range []string{"keygen", "cred", "unit", "encrypt", "install", "setup"} {
		if !strings.Contains(cli.UsageText(), want) {
			t.Fatalf("usage missing %q", want)
		}
	}
}
