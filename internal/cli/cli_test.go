package cli_test

import (
	"testing"

	"github.com/greboid/compose-sops/internal/cli"
	"github.com/greboid/compose-sops/internal/system"
)

func TestParsePluginDefaults(t *testing.T) {
	cmd, err := cli.Parse([]string{"plugin"})
	if err != nil {
		t.Fatal(err)
	}
	if cmd.Name != "plugin" || cmd.Socket != system.PluginSocket || cmd.Documents != system.PluginDocuments ||
		cmd.StateDir != system.PluginState || cmd.MountRoot != system.PluginMountRoot || cmd.EncryptKeyFile != system.RuntimeKey {
		t.Fatalf("parsed = %+v", cmd)
	}
}

func TestParsePluginFlags(t *testing.T) {
	cmd, err := cli.Parse([]string{"plugin", "--socket=/s.sock", "--documents", "/d", "--state", "/st", "--mount-root", "/m", "--key-file", "/k"})
	if err != nil {
		t.Fatal(err)
	}
	if cmd.Socket != "/s.sock" || cmd.Documents != "/d" || cmd.StateDir != "/st" || cmd.MountRoot != "/m" || cmd.EncryptKeyFile != "/k" {
		t.Fatalf("parsed = %+v", cmd)
	}
}

func TestParseErrors(t *testing.T) {
	cases := [][]string{
		{},
		{"compose", "metadata"},
		{"plugin", "extra"},
		{"plugin", "--bogus=1"},
		{"plugin", "--socket", "a", "--socket", "b"},
		{"check", "--documents", "/d", "-"},
		{"keygen", "--state", "/s"},
	}
	for _, args := range cases {
		if _, err := cli.Parse(args); err == nil {
			t.Errorf("Parse(%v) accepted", args)
		}
	}
}
