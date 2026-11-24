// Default filesystem locations shared by the compose-sops host tooling
// commands (keygen, cred, unit, encrypt, install, setup). Every location can
// be overridden per invocation with command line flags; these constants are
// the prompts' and defaults' single source of truth.

package system

const (
	// Key is the default plaintext age identity file created by keygen and
	// consumed by cred.
	Key = "/etc/compose-sops/key.txt"
	// Cred is the default systemd encrypted credential wrapping Key.
	Cred = "/etc/compose-sops/key.cred"
	// CredName is the credential name embedded in the encrypted credential
	// by cred and validated by the generated unit at decrypt time.
	CredName = "compose-sops-key"
	// RuntimeKey is where the generated systemd unit materializes the
	// decrypted age identity on tmpfs at boot. It is the default key file
	// for the commands taking --key-file, and the plugin reads it from the
	// same path through its key mount.
	RuntimeKey = "/run/compose-sops/age-key.txt"
	// RuntimeDir is the tmpfs directory the generated unit owns through
	// RuntimeDirectory=.
	RuntimeDir = "/run/compose-sops"
	// Unit is the default install location of the generated systemd unit.
	Unit = "/etc/systemd/system/compose-sops-key.service"
	// Install is the default global installation path of the binary itself.
	Install = "/usr/local/bin/compose-sops"
)

// Locations inside the managed plugin, matching plugin/config.json.
const (
	// PluginSocket is the volume driver socket Docker connects to.
	PluginSocket = "/run/docker/plugins/compose-sops.sock"
	// PluginDocuments is where the host documents root is mounted.
	PluginDocuments = "/documents"
	// PluginState is where the host state directory is mounted.
	PluginState = "/state"
	// PluginMountRoot is the plugin's propagated mount.
	PluginMountRoot = "/mnt/volumes"
)
