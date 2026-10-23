// Credential sealing and unsealing through systemd's
// io.systemd.Credentials varlink interface (systemd 258+, served by
// systemd-creds behind systemd-creds.socket) without executing any external
// binary.

package system

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/varlink/go/varlink"
)

// CredsInterface is the varlink interface implemented by systemd-creds.
const CredsInterface = "io.systemd.Credentials"

// Socket candidates: the unit's ListenStream= path and its
// /run/varlink/registry symlink.
var defaultSockets = []string{
	"/run/systemd/io.systemd.Credentials",
	"/run/varlink/registry/io.systemd.Credentials",
}

// CredsClient issues io.systemd.Credentials method calls. Each call uses its own
// connection: the socket unit is Accept=yes and spawns one service instance
// per connection.
type CredsClient struct {
	address string
}

// NewCredsClient returns a CredsClient connected to the system's systemd-creds varlink
// socket. It fails when no socket is reachable, which means either systemd
// is older than 258 or systemd-creds.socket is not active.
func NewCredsClient() (*CredsClient, error) {
	lastErr := error(nil)
	for _, path := range defaultSockets {
		conn, err := net.DialTimeout("unix", path, 2*time.Second)
		if err == nil {
			conn.Close()
			return &CredsClient{address: "unix:" + path}, nil
		}
		lastErr = err
	}
	return nil, fmt.Errorf("systemd credential varlink socket not reachable (tried %s): this requires systemd >= 258 with systemd-creds.socket active; check 'systemctl status systemd-creds.socket': %w", strings.Join(defaultSockets, ", "), lastErr)
}

// NewCredsClientAt returns a CredsClient for an explicit varlink address (for tests).
func NewCredsClientAt(address string) *CredsClient {
	return &CredsClient{address: address}
}

// WithKey values as defined by the io.systemd.Credentials interface.
const (
	WithKeyAuto                = "auto"
	WithKeyAutoInitrd          = "auto_initrd"
	WithKeyHost                = "host"
	WithKeyTPM2                = "tpm2"
	WithKeyTPM2WithPublicKey   = "tpm2_with_public_key"
	WithKeyHostTPM2            = "host_tpm2"
	WithKeyHostTPM2WithPublicK = "host_tpm2_with_public_key"
	WithKeyNull                = "null"
)

// ParseWithKey accepts both the systemd-creds CLI spellings and the varlink
// enum tokens, and returns the enum token.
func ParseWithKey(value string) (string, error) {
	switch value {
	case "auto":
		return WithKeyAuto, nil
	case "auto-initrd", "auto_initrd":
		return WithKeyAutoInitrd, nil
	case "host":
		return WithKeyHost, nil
	case "tpm2":
		return WithKeyTPM2, nil
	case "tpm2-with-public-key", "tpm2_with_public_key":
		return WithKeyTPM2WithPublicKey, nil
	case "host+tpm2", "tpm2+host", "host_tpm2":
		return WithKeyHostTPM2, nil
	case "host+tpm2-with-public-key", "host_tpm2_with_public_key":
		return WithKeyHostTPM2WithPublicK, nil
	case "null":
		return WithKeyNull, nil
	default:
		return "", fmt.Errorf("invalid --with-key value %q (expected host, tpm2, host+tpm2, tpm2-with-public-key, host+tpm2-with-public-key, auto, auto-initrd, or null)", value)
	}
}

// Encrypt seals data into a systemd encrypted credential bound to the
// selected key(s) and returns the credential file content: the base64
// encoding of the credential blob with a trailing newline. systemd expects
// credential files to retain this base64 encoding (the same format
// 'systemd-creds encrypt' writes). name is embedded for authentication and
// must be passed back to Decrypt (and to systemd-creds decrypt at boot).
func (c *CredsClient) Encrypt(ctx context.Context, name string, data []byte, withKey string) (string, error) {
	// Accept both the systemd-creds CLI spellings and the varlink enum
	// tokens; the interface expects the underscore enum forms.
	withKey, err := ParseWithKey(withKey)
	if err != nil {
		return "", err
	}
	type params struct {
		Name    string `json:"name,omitempty"`
		Data    string `json:"data"`
		WithKey string `json:"withKey,omitempty"`
	}
	var reply struct {
		Blob string `json:"blob"`
	}
	conn, err := varlink.NewConnection(ctx, c.address)
	if err != nil {
		return "", fmt.Errorf("cannot connect to %s: %w", c.address, err)
	}
	defer conn.Close()
	err = conn.Call(ctx, CredsInterface+".Encrypt", params{
		Name:    name,
		Data:    base64.StdEncoding.EncodeToString(data),
		WithKey: withKey,
	}, &reply)
	if err != nil {
		return "", callError("Encrypt", err)
	}
	if _, err := base64.StdEncoding.DecodeString(reply.Blob); err != nil {
		return "", fmt.Errorf("%s.Encrypt returned an invalid blob", CredsInterface)
	}
	return reply.Blob + "\n", nil
}

// Decrypt unseals a systemd encrypted credential. It requires the
// privileges the credential's binding demands (host key, TPM2, user scope).
func (c *CredsClient) Decrypt(ctx context.Context, name string, blob []byte) ([]byte, error) {
	type params struct {
		Name string `json:"name,omitempty"`
		Blob string `json:"blob"`
	}
	var reply struct {
		Data string `json:"data"`
	}
	conn, err := varlink.NewConnection(ctx, c.address)
	if err != nil {
		return nil, fmt.Errorf("cannot connect to %s: %w", c.address, err)
	}
	defer conn.Close()
	err = conn.Call(ctx, CredsInterface+".Decrypt", params{
		Name: name,
		Blob: base64.StdEncoding.EncodeToString(blob),
	}, &reply)
	if err != nil {
		return nil, callError("Decrypt", err)
	}
	data, err := base64.StdEncoding.DecodeString(reply.Data)
	if err != nil {
		return nil, fmt.Errorf("%s.Decrypt returned invalid plaintext", CredsInterface)
	}
	return data, nil
}

// callError converts varlink transport and interface errors into messages
// that point at what to fix.
func callError(method string, err error) error {
	if _, ok := errors.AsType[*varlink.InterfaceNotFound](err); ok {
		return fmt.Errorf("%s interface is not provided by this systemd (requires systemd >= 258)", CredsInterface)
	}
	if _, ok := errors.AsType[*varlink.MethodNotImplemented](err); ok {
		return fmt.Errorf("%s.%s is not implemented by this systemd (interface requires systemd >= 258)", CredsInterface, method)
	}
	if invalidParam, ok := errors.AsType[*varlink.InvalidParameter](err); ok {
		return fmt.Errorf("%s.%s rejected a parameter (%s); this compose-sops build may be incompatible with this systemd", CredsInterface, method, invalidParam.Parameter)
	}
	var vlerr *varlink.Error
	if !errors.As(err, &vlerr) {
		return fmt.Errorf("%s.%s failed: %w", CredsInterface, method, err)
	}
	switch vlerr.Name {
	case "io.systemd.System":
		return fmt.Errorf("%s.%s failed: not available on this system (for example no TPM present for a tpm2 binding, or no host key)", CredsInterface, method)
	case CredsInterface + ".NameMismatch":
		return fmt.Errorf("%s.%s failed: the credential name does not match the name it was encrypted with", CredsInterface, method)
	case CredsInterface + ".TimeMismatch":
		return fmt.Errorf("%s.%s failed: the credential is not valid at this time (timestamp or notAfter mismatch)", CredsInterface, method)
	case CredsInterface + ".BadFormat":
		return fmt.Errorf("%s.%s failed: the credential blob is corrupt or in an unsupported format", CredsInterface, method)
	case CredsInterface + ".NullKeyNotAllowed":
		return fmt.Errorf("%s.%s failed: the credential uses null encryption, which is not permitted here", CredsInterface, method)
	case CredsInterface + ".KeyBelongsToOtherTPM":
		return fmt.Errorf("%s.%s failed: the credential is bound to a different TPM", CredsInterface, method)
	case CredsInterface + ".UnexpectedPCRState":
		return fmt.Errorf("%s.%s failed: TPM PCR state does not match the state the credential was sealed against", CredsInterface, method)
	case CredsInterface + ".TPMInDictionaryLockout":
		return fmt.Errorf("%s.%s failed: the TPM is in dictionary lockout", CredsInterface, method)
	case CredsInterface + ".NoSuchUser":
		return fmt.Errorf("%s.%s failed: the credential is scoped to a user that does not exist", CredsInterface, method)
	case CredsInterface + ".BadScope":
		return fmt.Errorf("%s.%s failed: the credential does not match the requested scope", CredsInterface, method)
	case "org.varlink.service.MethodNotImplemented":
		return fmt.Errorf("%s.%s is not implemented by this systemd (interface requires systemd >= 258)", CredsInterface, method)
	case "org.varlink.service.InterfaceNotFound":
		return fmt.Errorf("%s interface is not provided by this systemd (requires systemd >= 258)", CredsInterface)
	default:
		return fmt.Errorf("%s.%s failed: %s", CredsInterface, method, vlerr.Name)
	}
}

// SocketExists reports whether any default credentials socket file exists.
// The wizard uses it for an early preflight so failures surface before any
// state is changed.
func SocketExists() bool {
	for _, path := range defaultSockets {
		if _, err := os.Stat(path); err == nil {
			return true
		}
	}
	return false
}
