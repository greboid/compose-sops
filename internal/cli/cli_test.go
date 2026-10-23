package cli_test

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/greboid/compose-sops/internal/cli"
)

func TestParseUpFullForm(t *testing.T) {
	cmd, err := cli.Parse([]string{"compose", "--project-name", "proj", "up", "--file", "/s/enc.yaml", "--age-key-file", "/s/keys", "--runtime-dir", "/dev/shm/x", "--owner-uid", "10001", "--owner-gid", "10001", "secrets"})
	if err != nil {
		t.Fatal(err)
	}
	if cmd.Name != "up" || cmd.ProjectName != "proj" || cmd.Service != "secrets" {
		t.Fatalf("parsed = %+v", cmd)
	}
	if cmd.Options.File != "/s/enc.yaml" || cmd.Options.AgeKeyFile != "/s/keys" || cmd.Options.RuntimeDir != "/dev/shm/x" {
		t.Fatalf("options = %+v", cmd.Options)
	}
	if cmd.Options.OwnerUID == nil || *cmd.Options.OwnerUID != 10001 || cmd.Options.OwnerGID == nil || *cmd.Options.OwnerGID != 10001 {
		t.Fatalf("owner = %+v", cmd.Options)
	}
}

func TestParseEqualsFormAndFlagAfterService(t *testing.T) {
	cmd, err := cli.Parse([]string{"compose", "-p=proj", "up", "--file=/e.yaml", "svc", "--runtime-dir=/dev/shm/x", "--age-key-file", "/k"})
	if err != nil {
		t.Fatal(err)
	}
	if cmd.ProjectName != "proj" || cmd.Service != "svc" || cmd.Options.File != "/e.yaml" || cmd.Options.RuntimeDir != "/dev/shm/x" {
		t.Fatalf("parsed = %+v", cmd)
	}
}

func TestParseMetadata(t *testing.T) {
	cmd, err := cli.Parse([]string{"compose", "metadata"})
	if err != nil {
		t.Fatal(err)
	}
	if cmd.Name != "metadata" {
		t.Fatalf("name = %s", cmd.Name)
	}
}

func TestParseErrors(t *testing.T) {
	cases := [][]string{
		{},
		{"notcompose"},
		{"compose"},
		{"compose", "bogus"},
		{"compose", "up"},
		{"compose", "up", "svc"}, // no project name
		{"compose", "--project-name", "p", "up", "svc"},                                                                                                      // missing options
		{"compose", "--project-name", "p", "up", "a", "b"},                                                                                                   // two services
		{"compose", "--project-name", "p", "up", "--file=x", "svc"},                                                                                          // partial options
		{"compose", "--project-name", "p", "metadata", "svc"},                                                                                                // metadata with arg
		{"compose", "--project-name", "p", "up", "--bogus=1", "svc"},                                                                                         // unknown flag
		{"compose", "--project-name", "p", "up", "--file", "a", "--file", "b", "--age-key-file", "k", "--runtime-dir", "r", "svc"},                           // dup flag
		{"compose", "--project-name", "p", "up", "--file", "a", "--age-key-file", "k", "--runtime-dir", "r", "--owner-uid", "5", "svc"},                      // uid without gid
		{"compose", "--project-name", "p", "up", "--file", "a", "--age-key-file", "k", "--runtime-dir", "r", "--owner-uid", "-3", "--owner-gid", "5", "svc"}, // negative
		{"compose", "--project-name", "p", "up", "--file", "a", "--age-key-file", "k", "--runtime-dir", "r", "--owner-uid", "x", "--owner-gid", "5", "svc"},  // non-numeric
	}
	for _, args := range cases {
		if _, err := cli.Parse(args); err == nil {
			t.Errorf("Parse(%v) accepted", args)
		}
	}
}

func TestParseDownRequiresOnlyRuntimeDir(t *testing.T) {
	cmd, err := cli.Parse([]string{"compose", "--project-name", "p", "down", "--runtime-dir", "/dev/shm/x", "svc"})
	if err != nil {
		t.Fatal(err)
	}
	if cmd.Options.RuntimeDir != "/dev/shm/x" || cmd.Options.File != "" {
		t.Fatalf("parsed = %+v", cmd)
	}
}

func TestMetadataIsValidJSON(t *testing.T) {
	var buf bytes.Buffer
	if err := cli.RunMetadata(&buf); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Description string `json:"description"`
		Up          struct {
			Parameters []struct {
				Name     string `json:"name"`
				Required bool   `json:"required"`
				Type     string `json:"type"`
			} `json:"parameters"`
		} `json:"up"`
		Down struct {
			Parameters []struct {
				Name     string `json:"name"`
				Required bool   `json:"required"`
			} `json:"parameters"`
		} `json:"down"`
		Stop struct {
			Parameters []struct {
				Name string `json:"name"`
			} `json:"parameters"`
		} `json:"stop"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, buf.String())
	}
	if doc.Description == "" {
		t.Error("empty description")
	}
	requiredUp := map[string]bool{}
	for _, p := range doc.Up.Parameters {
		requiredUp[p.Name] = p.Required
	}
	for _, name := range []string{"file", "age-key-file", "runtime-dir"} {
		if !requiredUp[name] {
			t.Errorf("up parameter %s not required", name)
		}
	}
	// The stop block must exist: its presence opts the provider into the
	// stop lifecycle.
	if len(doc.Stop.Parameters) == 0 {
		t.Error("missing stop block")
	}
	requiredDown := map[string]bool{}
	for _, p := range doc.Down.Parameters {
		requiredDown[p.Name] = p.Required
	}
	if !requiredDown["runtime-dir"] {
		t.Error("down runtime-dir not required")
	}
	if requiredDown["file"] {
		t.Error("down file must be optional")
	}
}
