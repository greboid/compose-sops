package provider

import (
	"encoding/json"
	"io"
	"os"
	"strings"
)

// Message types from the Compose provider protocol. compose-sops only ever
// sends info and error: secret values must never travel through provider
// messages (setenv/rawsetenv are merged into dependent containers'
// Environment and become visible in `docker inspect`).
const (
	msgInfo  = "info"
	msgError = "error"
)

// Emitter writes JSON line-delimited provider messages.
type Emitter struct {
	w io.Writer
	// infoSupported reflects COMPOSE_PROVIDER_MESSAGES: when the variable is
	// set, an unknown message type fails the command, so optional messages
	// must be gated on membership. error is always sent: failing loudly is
	// required.
	infoSupported bool
}

// NewEmitter returns an Emitter writing to w, honoring the
// COMPOSE_PROVIDER_MESSAGES environment variable.
func NewEmitter(w io.Writer) *Emitter {
	return &Emitter{w: w, infoSupported: accepts(msgInfo)}
}

// accepts reports whether the announced message type list (if any) includes
// typ. An unset variable means the running Compose predates the announcement
// and supports the core info/error types.
func accepts(typ string) bool {
	announced, ok := os.LookupEnv("COMPOSE_PROVIDER_MESSAGES")
	if !ok || announced == "" {
		return typ == msgInfo || typ == msgError
	}
	for t := range strings.SplitSeq(announced, ",") {
		if strings.TrimSpace(t) == typ {
			return true
		}
	}
	return false
}

type wireMessage struct {
	Type    string `json:"type"`
	Message string `json:"message"`
}

func (e *Emitter) send(typ, msg string) {
	if e == nil || e.w == nil {
		return
	}
	b, err := json.Marshal(wireMessage{Type: typ, Message: msg})
	if err != nil {
		return
	}
	_, _ = e.w.Write(append(b, '\n'))
}

// Info reports a status update, unless the running Compose does not accept
// info messages.
func (e *Emitter) Info(msg string) {
	if e.infoSupported {
		e.send(msgInfo, msg)
	}
}

// Error reports a failure reason.
func (e *Emitter) Error(msg string) {
	e.send(msgError, msg)
}
