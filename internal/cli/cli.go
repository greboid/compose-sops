// Package cli parses the compose-sops command line:
//
//	compose-sops plugin [--socket PATH] [--documents DIR] [--key-file PATH] [--state DIR] [--mount-root DIR]
//	compose-sops keygen [--output PATH]
//	compose-sops cred [--key PATH] [--with-key KEY] [--name NAME] PATH.cred
//	compose-sops unit [--name NAME] [--output PATH] PATH.cred
//	compose-sops encrypt --output PATH [--key-file PATH] INPUT
//	compose-sops install [--path PATH]
//	compose-sops recipient [--key-file PATH]
//	compose-sops check [--key-file PATH] INPUT
//	compose-sops rekey [--key-file PATH] [--add R,...] [--remove R,...] INPUT
//	compose-sops decrypt [--key-file PATH] INPUT
//	compose-sops setup
package cli

import (
	"fmt"
	"strings"

	"github.com/greboid/compose-sops/internal/system"
)

// Exit codes.
const (
	// ExitSuccess is the zero exit code.
	ExitSuccess = 0
	// ExitFailure is a runtime failure.
	ExitFailure = 1
	// ExitUsage is a command line error.
	ExitUsage = 2
)

const usage = `compose-sops - SOPS-encrypted secrets as Docker volumes

Docker volume plugin (run by Docker inside the managed plugin):
  compose-sops plugin [--socket PATH] [--documents DIR] [--key-file PATH]
                      [--state DIR] [--mount-root DIR]
      serve the volume driver API; defaults match plugin/config.json

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
      SOPS-encrypt a flat secrets YAML file with an age key; INPUT and
      PATH may be '-' for stdin and stdout
  compose-sops install [--path PATH]
      install the binary to a global path
  compose-sops recipient [--key-file PATH]
      print the age recipient of each identity in the key file
  compose-sops check [--key-file PATH] INPUT
      decrypt and verify INPUT ('-' for stdin) and print "valid"
  compose-sops rekey [--key-file PATH] [--add R,...] [--remove R,...] INPUT
      write INPUT ('-' for stdin) to stdout with the age recipients added or
      removed; removing rotates the data key; unchanged input is copied
  compose-sops decrypt [--key-file PATH] INPUT
      decrypt and verify INPUT ('-' for stdin) and print its secrets to
      stdout as a JSON object, for orchestrators that consume them directly

Volume driver options (docker volume create -o / Compose driver_opts):
  file=PATH   encrypted document, relative to the documents root (required)
  keys=A,B    expose only these secrets (default: all)
  uid=N,gid=N owner of the secret files (default: root)
`

// Command is a parsed invocation.
type Command struct {
	Name string

	// Host tooling command inputs, resolved to their defaults by Parse.
	OutputPath     string   // keygen --output, unit --output
	CredPath       string   // cred OUTPUT.cred
	KeyPath        string   // cred --key
	WithKey        string   // cred --with-key
	CredName       string   // cred/unit --name
	UnitCredPath   string   // unit PATH.cred
	EncryptInput   string   // encrypt INPUT
	EncryptOutput  string   // encrypt --output
	EncryptKeyFile string   // --key-file
	InstallPath    string   // install --path
	Input          string   // check/rekey/decrypt INPUT
	Add            []string // rekey --add
	Remove         []string // rekey --remove

	// Plugin locations.
	Socket    string // plugin --socket
	Documents string // plugin --documents
	StateDir  string // plugin --state
	MountRoot string // plugin --mount-root
}

// Parse parses args (without the program name).
func Parse(args []string) (*Command, error) {
	return parseCommand(args)
}

// parseCommand parses every command.
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
		if arg == "-" || !strings.HasPrefix(arg, "-") {
			positional = append(positional, arg)
			continue
		}
		name, value, hasValue := cutFlag(arg)
		switch name {
		case "--help", "-h":
			return nil, fmt.Errorf("usage requested")
		case "--output", "--key", "--with-key", "--name", "--key-file", "--path",
			"--add", "--remove", "--socket", "--documents", "--state", "--mount-root":
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
		return nil, fmt.Errorf("missing command (plugin, setup, keygen, cred, unit, encrypt, install, recipient, check, rekey, decrypt)")
	}
	cmd.Name, positional = positional[0], positional[1:]

	// Defaults, applied so the parsed Command is ready to run.
	cmd.KeyPath = system.Key
	cmd.WithKey = "auto"
	cmd.CredName = system.CredName
	cmd.EncryptKeyFile = system.RuntimeKey
	cmd.InstallPath = system.Install
	cmd.Socket = system.PluginSocket
	cmd.Documents = system.PluginDocuments
	cmd.StateDir = system.PluginState
	cmd.MountRoot = system.PluginMountRoot

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
		case "--add":
			cmd.Add = splitList(value)
		case "--remove":
			cmd.Remove = splitList(value)
		case "--socket":
			cmd.Socket = value
		case "--documents":
			cmd.Documents = value
		case "--state":
			cmd.StateDir = value
		case "--mount-root":
			cmd.MountRoot = value
		}
	}

	switch cmd.Name {
	case "plugin":
		if len(positional) > 0 {
			return nil, fmt.Errorf("plugin takes no arguments")
		}
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
	case "recipient":
		if len(positional) > 0 {
			return nil, fmt.Errorf("recipient takes no arguments (use --key-file PATH)")
		}
	case "check":
		if len(positional) != 1 {
			return nil, fmt.Errorf("exactly one INPUT argument is required ('-' for stdin)")
		}
		cmd.Input = positional[0]
	case "rekey", "decrypt":
		if len(positional) != 1 {
			return nil, fmt.Errorf("exactly one INPUT argument is required ('-' for stdin)")
		}
		cmd.Input = positional[0]
	default:
		return nil, fmt.Errorf("unknown command %q (expected plugin, setup, keygen, cred, unit, encrypt, install, recipient, check, rekey, decrypt)", cmd.Name)
	}
	for name := range seen {
		switch name {
		case "--add", "--remove":
			if cmd.Name != "rekey" {
				return nil, fmt.Errorf("%s is only valid for rekey", name)
			}
		case "--socket", "--documents", "--state", "--mount-root":
			if cmd.Name != "plugin" {
				return nil, fmt.Errorf("%s is only valid for plugin", name)
			}
		}
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

func splitList(value string) []string {
	var out []string
	for v := range strings.SplitSeq(value, ",") {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return out
}

func cutFlag(arg string) (name, value string, hasValue bool) {
	if before, after, ok := strings.Cut(arg, "="); ok {
		return before, after, true
	}
	return arg, "", false
}

// UsageText returns the usage message.
func UsageText() string { return usage }
