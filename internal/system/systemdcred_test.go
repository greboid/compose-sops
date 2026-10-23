package system_test

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/greboid/compose-sops/internal/system"
)

// fakeServer serves scripted replies on a unix socket, one reply per
// accepted connection.
type fakeServer struct {
	listener net.Listener
	path     string
	reply    func(method string, params json.RawMessage) (string, error)
}

func newFakeServer(t *testing.T, reply func(method string, params json.RawMessage) (string, error)) *fakeServer {
	t.Helper()
	dir, err := os.MkdirTemp("", "varlink-test")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	path := filepath.Join(dir, "creds.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	s := &fakeServer{listener: ln, path: path, reply: reply}
	go s.serve()
	t.Cleanup(func() { ln.Close() })
	return s
}

func (s *fakeServer) serve() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return
		}
		go s.handle(conn)
	}
}

func (s *fakeServer) handle(conn net.Conn) {
	defer conn.Close()
	// varlink messages are NUL-terminated (this is what sd-varlink speaks).
	line, err := bufio.NewReader(conn).ReadBytes('\x00')
	if err != nil {
		return
	}
	line = line[:len(line)-1]
	var call struct {
		Method     string          `json:"method"`
		Parameters json.RawMessage `json:"parameters"`
	}
	if err := json.Unmarshal(line, &call); err != nil {
		return
	}
	out, err := s.reply(call.Method, call.Parameters)
	if err != nil {
		return
	}
	conn.Write([]byte(out + "\x00"))
}

func (s *fakeServer) client() *system.CredsClient {
	return system.NewCredsClientAt("unix:" + s.path)
}

// TestEncryptSendsInterfaceMethodAndReturnsBlob checks the request shape
// and that the returned base64 blob is preserved as credential file content.
func TestEncryptSendsInterfaceMethodAndReturnsBlob(t *testing.T) {
	data := []byte("age identity bytes")
	var gotMethod string
	var gotParams struct {
		Name    string `json:"name"`
		Data    string `json:"data"`
		WithKey string `json:"withKey"`
	}
	server := newFakeServer(t, func(method string, params json.RawMessage) (string, error) {
		gotMethod = method
		if err := json.Unmarshal(params, &gotParams); err != nil {
			t.Error(err)
		}
		return fmt.Sprintf(`{"parameters":{"blob":%q}}`, base64.StdEncoding.EncodeToString(data)), nil
	})

	blob, err := server.client().Encrypt(context.Background(), "compose-sops-key", data, system.WithKeyHost)
	if err != nil {
		t.Fatal(err)
	}
	want := base64.StdEncoding.EncodeToString(data) + "\n"
	if blob != want {
		t.Fatalf("blob = %q, want base64 text %q", blob, want)
	}
	if gotMethod != "io.systemd.Credentials.Encrypt" {
		t.Fatalf("method = %s", gotMethod)
	}
	if gotParams.Name != "compose-sops-key" || gotParams.WithKey != "host" {
		t.Fatalf("params = %+v", gotParams)
	}
	decoded, err := base64.StdEncoding.DecodeString(gotParams.Data)
	if err != nil || string(decoded) != string(data) {
		t.Fatalf("data parameter = %q (%v)", gotParams.Data, err)
	}
}

func TestDecryptReturnsPlaintext(t *testing.T) {
	data := []byte("plaintext identity")
	server := newFakeServer(t, func(method string, params json.RawMessage) (string, error) {
		if method != "io.systemd.Credentials.Decrypt" {
			t.Errorf("method = %s", method)
		}
		var p struct {
			Name string `json:"name"`
			Blob string `json:"blob"`
		}
		if err := json.Unmarshal(params, &p); err != nil {
			t.Error(err)
		}
		if p.Name != "compose-sops-key" {
			t.Errorf("name = %q", p.Name)
		}
		blob, err := base64.StdEncoding.DecodeString(p.Blob)
		if err != nil || string(blob) != "ciphertext" {
			t.Errorf("blob = %q (%v)", p.Blob, err)
		}
		return fmt.Sprintf(`{"parameters":{"data":%q}}`, base64.StdEncoding.EncodeToString(data)), nil
	})

	got, err := server.client().Decrypt(context.Background(), "compose-sops-key", []byte("ciphertext"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(data) {
		t.Fatalf("plaintext = %q, want %q", got, data)
	}
}

func TestInterfaceErrorsMapToFriendlyMessages(t *testing.T) {
	server := newFakeServer(t, func(method string, _ json.RawMessage) (string, error) {
		return `{"error":"io.systemd.Credentials.NameMismatch","parameters":null}`, nil
	})
	_, err := server.client().Decrypt(context.Background(), "compose-sops-key", []byte("x"))
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "name does not match") {
		t.Fatalf("error = %v", err)
	}
	if _, ok := errors.AsType[interface{ Error() string }](err); !ok {
		t.Fatalf("error does not implement error interface")
	}
}

func TestUnimplementedInterfaceReportsSystemdVersion(t *testing.T) {
	server := newFakeServer(t, func(method string, _ json.RawMessage) (string, error) {
		return `{"error":"org.varlink.service.InterfaceNotFound","parameters":{"interface":"io.systemd.Credentials"}}`, nil
	})
	_, err := server.client().Encrypt(context.Background(), "n", []byte("d"), "host")
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "systemd >= 258") {
		t.Fatalf("error = %v", err)
	}
}

func TestParseWithKey(t *testing.T) {
	cases := map[string]string{
		"host":                      "host",
		"tpm2":                      "tpm2",
		"host+tpm2":                 "host_tpm2",
		"tpm2+host":                 "host_tpm2",
		"auto":                      "auto",
		"auto-initrd":               "auto_initrd",
		"tpm2-with-public-key":      "tpm2_with_public_key",
		"host+tpm2-with-public-key": "host_tpm2_with_public_key",
		"null":                      "null",
	}
	for in, want := range cases {
		got, err := system.ParseWithKey(in)
		if err != nil {
			t.Fatalf("%s: %v", in, err)
		}
		if got != want {
			t.Fatalf("%s = %s, want %s", in, got, want)
		}
	}
	if _, err := system.ParseWithKey("bogus"); err == nil {
		t.Fatal("expected error for bogus value")
	}
}

// TestSystemdCredsRealRoundTrip exercises the client against the real
// systemd-creds varlink service. It needs root (host/TPM key access) and is
// skipped elsewhere.
func TestSystemdCredsRealRoundTrip(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root for the systemd-creds service")
	}
	if _, err := os.Stat("/usr/bin/systemd-creds"); err != nil {
		t.Skip("systemd-creds not installed")
	}

	dir, err := os.MkdirTemp("", "varlink-real")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	path := filepath.Join(dir, "creds.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })

	// Accept one connection and hand it to a fresh systemd-creds instance,
	// mirroring systemd-creds.socket's Accept=yes behavior.
	serve := func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go func() {
			defer conn.Close()
			uconn, ok := conn.(*net.UnixConn)
			if !ok {
				return
			}
			rawConn, err := uconn.SyscallConn()
			if err != nil {
				return
			}
			var rawFd int
			rawConn.Control(func(fd uintptr) { rawFd = int(fd) })
			dup, err := unix.Dup(rawFd)
			if err != nil {
				return
			}
			f := os.NewFile(uintptr(dup), "varlink")
			defer f.Close()
			cmd := exec.Command("/bin/sh", "-c", "LISTEN_PID=$$ LISTEN_FDS=1 LISTEN_FDNAMES=varlink exec /usr/bin/systemd-creds")
			cmd.ExtraFiles = []*os.File{f}
			cmd.Start()
		}()
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	serve()
	client := system.NewCredsClientAt("unix:" + path)
	plaintext := []byte("AGE-SECRET-KEY-TEST")
	credFile, err := client.Encrypt(ctx, "compose-sops-key", plaintext, system.WithKeyNull)
	if err != nil {
		t.Fatal(err)
	}
	blob, err := base64.StdEncoding.DecodeString(strings.TrimSpace(credFile))
	if err != nil {
		t.Fatal(err)
	}

	serve()
	got, err := client.Decrypt(ctx, "compose-sops-key", blob)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(plaintext) {
		t.Fatalf("round trip = %q, want %q", got, plaintext)
	}
}
