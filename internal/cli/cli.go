// Package cli parses the compose-sops command line and dispatches to the
// Compose provider lifecycle commands and the host key management commands:
//
//	compose-sops compose metadata
//	compose-sops compose --project-name NAME up [options] SERVICE
//	compose-sops compose --project-name NAME down [options] SERVICE
//	compose-sops compose --project-name NAME stop [options] SERVICE
//	compose-sops keygen [--output PATH]
//	compose-sops cred [--key PATH] [--with-key KEY] [--name NAME] PATH.cred
//	compose-sops unit [--name NAME] [--output PATH] PATH.cred
//	compose-sops encrypt --output PATH [--key-file PATH] INPUT
//	compose-sops install [--path PATH]
//	compose-sops setup
package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/greboid/compose-sops/internal/system"
)

// Exit codes.
const (
	// ExitSuccess is the zero exit code.
	ExitSuccess = 0
	// ExitFailure is a provider/runtime failure (Compose marks the service failed).
	ExitFailure = 1
	// ExitUsage is a command line error.
	ExitUsage = 2
)

const usage = `compose-sops - SOPS-encrypted file secrets provider for Docker Compose

Compose provider (invoked by Docker Compose, not by hand):
  compose-sops compose metadata
  compose-sops compose --project-name NAME up    [options] SERVICE
  compose-sops compose --project-name NAME down  [options] SERVICE
  compose-sops compose --project-name NAME stop  [options] SERVICE

Host key management (systemd-creds):
  compose-sops setup
      interactive wizard: install, keygen, cred, unit, first encryption
  compose-sops keygen [--output PATH]
      generate a new age key (asks for the output path)
  compose-sops cred [--key PATH] [--with-key KEY] [--name NAME] PATH.cred
      seal the key into a systemd encrypted credential over varlink
      KEY: host, tpm2, host+tpm2, tpm2-with-public-key,
           host+tpm2-with-public-key, auto, auto-initrd, null
  compose-sops unit [--name NAME] [--output PATH] PATH.cred
      print the systemd unit decrypting the credential to /run at boot
  compose-sops encrypt --output PATH [--key-file PATH] INPUT
      SOPS-encrypt a flat secrets YAML file with an age key
  compose-sops install [--path PATH]
      install the binary to a global path

Compose provider options:
  --file PATH          SOPS-encrypted YAML file (up only; required)
  --age-key-file PATH  host age identity file, native AGE-SECRET-KEY-1...
                       identities only (up only; required)
  --runtime-dir PATH   existing tmpfs directory for the published secrets
                       (required)
  --owner-uid N        numeric UID owning the secret files (optional)
  --owner-gid N        numeric GID owning the secret files (optional)

Secrets are published to <runtime-dir>/<project>/<SERVICE>/<secret-name>.
Secret values are never emitted as provider messages or logs.
`

// Command is a parsed invocation.
type Command struct {
	Name        string // metadata, up, down, stop, keygen, cred, unit, encrypt, install, setup
	ProjectName string
	Service     string
	Options     Options

	// Host tooling command inputs, resolved to their defaults by Parse.
	OutputPath     string // keygen --output, unit --output
	CredPath       string // cred OUTPUT.cred
	KeyPath        string // cred --key
	WithKey        string // cred --with-key
	CredName       string // cred/unit --name
	UnitCredPath   string // unit PATH.cred
	EncryptInput   string // encrypt INPUT
	EncryptOutput  string // encrypt --output
	EncryptKeyFile string // encrypt --key-file
	InstallPath    string // install --path
}

// Options carries parsed option values.
type Options struct {
	File       string
	AgeKeyFile string
	RuntimeDir string
	OwnerUID   *int
	OwnerGID   *int
}

// flagSpec describes one option flag.
type flagSpec struct {
	name  string
	typ   string
	reqUp bool
}

// optionSpecs is the single source of truth for parsing and metadata output.
var optionSpecs = []flagSpec{
	{name: "file", typ: "string", reqUp: true},
	{name: "age-key-file", typ: "string", reqUp: true},
	{name: "runtime-dir", typ: "string", reqUp: true},
	{name: "owner-uid", typ: "integer", reqUp: false},
	{name: "owner-gid", typ: "integer", reqUp: false},
}

// Parse parses args (without the program name).
func Parse(args []string) (*Command, error) {
	if len(args) > 0 && args[0] == "compose" {
		return parseCompose(args)
	}
	return parseCommand(args)
}

// parseCommand parses the host tooling commands (everything except the
// Compose provider's 'compose' subcommand).
func parseCommand(args []string) (*Command, error) {
	var cmd Command
	var positional []string
	seen := map[string]string{}

	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			positional = append(positional, args[i+1:]...)
			break
		}
		if !strings.HasPrefix(arg, "-") {
			positional = append(positional, arg)
			continue
		}
		name, value, hasValue := cutFlag(arg)
		switch name {
		case "--help", "-h":
			return nil, fmt.Errorf("usage requested")
		case "--output", "--key", "--with-key", "--name", "--key-file", "--path":
			if !hasValue {
				i++
				if i >= len(args) {
					return nil, fmt.Errorf("%s requires a value", name)
				}
				value = args[i]
			}
			if _, dup := seen[name]; dup {
				return nil, fmt.Errorf("flag %s given more than once", name)
			}
			seen[name] = value
		default:
			return nil, fmt.Errorf("unknown flag %s", arg)
		}
	}

	if len(positional) == 0 {
		return nil, fmt.Errorf("missing command (setup, keygen, cred, unit, encrypt, install, or compose)")
	}
	cmd.Name, positional = positional[0], positional[1:]

	// Defaults, applied so the parsed Command is ready to run.
	cmd.KeyPath = system.Key
	cmd.WithKey = "auto"
	cmd.CredName = system.CredName
	cmd.EncryptKeyFile = system.RuntimeKey
	cmd.InstallPath = system.Install

	for name, value := range seen {
		switch name {
		case "--output":
			cmd.OutputPath = value
		case "--key":
			cmd.KeyPath = value
		case "--with-key":
			cmd.WithKey = value
		case "--name":
			cmd.CredName = value
		case "--key-file":
			cmd.EncryptKeyFile = value
		case "--path":
			cmd.InstallPath = value
		}
	}

	switch cmd.Name {
	case "setup":
		if len(positional) > 0 || len(seen) > 0 {
			return nil, fmt.Errorf("setup takes no arguments or flags")
		}
	case "keygen":
		if len(positional) > 0 {
			return nil, fmt.Errorf("keygen takes no arguments (use --output PATH for the key file)")
		}
	case "cred":
		if len(positional) != 1 {
			return nil, fmt.Errorf("exactly one PATH.cred argument is required")
		}
		cmd.CredPath = positional[0]
		if err := validateCredName(cmd.CredName); err != nil {
			return nil, err
		}
		if _, err := system.ParseWithKey(cmd.WithKey); err != nil {
			return nil, err
		}
	case "unit":
		if len(positional) != 1 {
			return nil, fmt.Errorf("exactly one PATH.cred argument is required")
		}
		cmd.UnitCredPath = positional[0]
		if err := validateCredName(cmd.CredName); err != nil {
			return nil, err
		}
	case "encrypt":
		if len(positional) != 1 {
			return nil, fmt.Errorf("exactly one INPUT argument is required")
		}
		cmd.EncryptInput = positional[0]
		cmd.EncryptOutput = cmd.OutputPath
		if cmd.EncryptOutput == "" {
			return nil, fmt.Errorf("--output PATH is required (encrypted output file)")
		}
	case "install":
		if len(positional) > 0 {
			return nil, fmt.Errorf("install takes no arguments (use --path PATH for the destination)")
		}
	default:
		return nil, fmt.Errorf("unknown command %q (expected setup, keygen, cred, unit, encrypt, install, or compose)", cmd.Name)
	}
	return &cmd, nil
}

// validateCredName rejects names that would break the generated unit's
// quoted arguments or systemd's credential name rules.
func validateCredName(name string) error {
	if name == "" || len(name) > 128 {
		return fmt.Errorf("invalid credential name %q: must be 1-128 characters", name)
	}
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9',
			r == '.', r == '_', r == '-':
		default:
			return fmt.Errorf("invalid credential name %q: allowed characters are letters, digits, dot, underscore, dash", name)
		}
	}
	return nil
}

// parseCompose parses the Compose provider invocation (args[0] == "compose").
func parseCompose(args []string) (*Command, error) {
	if len(args) == 0 || args[0] != "compose" {
		return nil, fmt.Errorf("first argument must be 'compose'")
	}
	rest := args[1:]

	var cmd Command
	var positional []string
	seen := map[string]string{}

	for i := 0; i < len(rest); i++ {
		arg := rest[i]
		if arg == "--" {
			positional = append(positional, rest[i+1:]...)
			break
		}
		if !strings.HasPrefix(arg, "-") {
			positional = append(positional, arg)
			continue
		}

		name, value, hasValue := cutFlag(arg)
		switch name {
		case "--project-name", "-p":
			if !hasValue {
				i++
				if i >= len(rest) {
					return nil, fmt.Errorf("--project-name requires a value")
				}
				value = rest[i]
			}
			cmd.ProjectName = value
		case "--help", "-h":
			return nil, fmt.Errorf("usage requested")
		default:
			if !isOptionFlag(name) {
				return nil, fmt.Errorf("unknown flag %s", arg)
			}
			if !hasValue {
				i++
				if i >= len(rest) {
					return nil, fmt.Errorf("%s requires a value", name)
				}
				value = rest[i]
			}
			if _, dup := seen[name]; dup {
				return nil, fmt.Errorf("flag --%s given more than once", strings.TrimPrefix(name, "--"))
			}
			seen[name] = value
		}
	}

	if len(positional) == 0 {
		return nil, fmt.Errorf("missing subcommand (metadata, up, down, stop)")
	}
	cmd.Name, positional = positional[0], positional[1:]

	switch cmd.Name {
	case "metadata":
		if len(positional) > 0 {
			return nil, fmt.Errorf("metadata takes no arguments")
		}
		return &cmd, nil
	case "up", "down", "stop":
	default:
		return nil, fmt.Errorf("unknown subcommand %q (expected metadata, up, down, stop)", cmd.Name)
	}

	if cmd.ProjectName == "" {
		return nil, fmt.Errorf("--project-name is required")
	}
	if len(positional) != 1 {
		return nil, fmt.Errorf("exactly one SERVICE argument is required")
	}
	cmd.Service = positional[0]

	if err := applyOptions(&cmd.Options, seen, cmd.Name); err != nil {
		return nil, err
	}
	return &cmd, nil
}

func isOptionFlag(name string) bool {
	for _, spec := range optionSpecs {
		if "--"+spec.name == name {
			return true
		}
	}
	return false
}

func applyOptions(opts *Options, seen map[string]string, subcommand string) error {
	for _, spec := range optionSpecs {
		value, ok := seen["--"+spec.name]
		if !ok {
			if spec.reqUp && subcommand == "up" {
				return fmt.Errorf("missing required option --%s", spec.name)
			}
			continue
		}
		switch spec.name {
		case "file":
			opts.File = value
		case "age-key-file":
			opts.AgeKeyFile = value
		case "runtime-dir":
			opts.RuntimeDir = value
		case "owner-uid":
			n, err := parseID("--owner-uid", value)
			if err != nil {
				return err
			}
			opts.OwnerUID = &n
		case "owner-gid":
			n, err := parseID("--owner-gid", value)
			if err != nil {
				return err
			}
			opts.OwnerGID = &n
		}
	}
	if (opts.OwnerUID == nil) != (opts.OwnerGID == nil) {
		return fmt.Errorf("--owner-uid and --owner-gid must be given together")
	}
	return nil
}

func parseID(flag, value string) (int, error) {
	n, err := strconv.Atoi(value)
	if err != nil || n < 0 || n > 2147483647 {
		return 0, fmt.Errorf("%s must be a non-negative integer, got %q", flag, value)
	}
	return n, nil
}

func cutFlag(arg string) (name, value string, hasValue bool) {
	if before, after, ok := strings.Cut(arg, "="); ok {
		return before, after, true
	}
	return arg, "", false
}

// metadata types mirror the JSON structure Compose expects from
// `compose metadata`.
type metadataParameter struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Required    bool   `json:"required"`
	Type        string `json:"type"`
}

type metadataCommand struct {
	Parameters []metadataParameter `json:"parameters"`
}

type metadataOutput struct {
	Description string          `json:"description"`
	Up          metadataCommand `json:"up"`
	Down        metadataCommand `json:"down"`
	Stop        metadataCommand `json:"stop"`
}

const metadataDescription = "Materializes SOPS-encrypted YAML files as individual secret files on host tmpfs for Compose file secrets"

func parameterDescriptions(cmd string) []metadataParameter {
	params := make([]metadataParameter, 0, len(optionSpecs))
	for _, spec := range optionSpecs {
		params = append(params, metadataParameter{
			Name:        spec.name,
			Description: optionDescription(spec.name, cmd),
			Required:    requiredFor(spec, cmd),
			Type:        spec.typ,
		})
	}
	return params
}

// requiredFor mirrors the actual per-command option enforcement: up needs
// everything, down only needs to locate the runtime dir, stop needs nothing.
func requiredFor(spec flagSpec, cmd string) bool {
	switch cmd {
	case "metadata", "up":
		return spec.reqUp
	case "down":
		return spec.name == "runtime-dir"
	default:
		return false
	}
}

func optionDescription(name, cmd string) string {
	switch name {
	case "file":
		if cmd == "up" {
			return "Path to the SOPS-encrypted YAML file"
		}
		return "Path to the SOPS-encrypted YAML file (ignored by " + cmd + ")"
	case "age-key-file":
		if cmd == "up" {
			return "Path to the host age identity file (native AGE-SECRET-KEY-1... identities only)"
		}
		return "Path to the host age identity file (ignored by " + cmd + ")"
	case "runtime-dir":
		return "Existing tmpfs directory under which secrets are published"
	case "owner-uid":
		return "Numeric UID owning the published secret files (default: invoking user)"
	case "owner-gid":
		return "Numeric GID owning the published secret files (default: invoking group)"
	}
	return ""
}

// RunMetadata writes the provider metadata JSON.
func RunMetadata(w io.Writer) error {
	out := metadataOutput{
		Description: metadataDescription,
		Up:          metadataCommand{Parameters: parameterDescriptions("up")},
		Down:        metadataCommand{Parameters: parameterDescriptions("down")},
		Stop:        metadataCommand{Parameters: parameterDescriptions("stop")},
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

// UsageText returns the usage message.
func UsageText() string { return usage }
