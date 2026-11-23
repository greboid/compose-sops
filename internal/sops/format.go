// SOPS YAML file format, implemented for the subset compose-sops accepts:
// one flat mapping of string values, a single group of age recipients and the
// default unencrypted-suffix rule. Anything else in the metadata is rejected
// rather than ignored, because it would change which values are encrypted or
// covered by the MAC.

package sops

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"

	"filippo.io/age"
	"filippo.io/age/armor"
	"go.yaml.in/yaml/v4"
)

const (
	// formatVersion is the SOPS release whose format this implements.
	formatVersion            = "3.13.3"
	sopsMetadataKey          = "sops"
	defaultUnencryptedSuffix = "_unencrypted"
	nonceSize                = 32
	tagSize                  = 16
	dataKeySize              = 32
	// commentAAD is the additional data SOPS uses for top-level comments.
	commentAAD = ":"
)

var encPattern = regexp.MustCompile(`^ENC\[AES256_GCM,data:([A-Za-z0-9+/=]*),iv:([A-Za-z0-9+/=]+),tag:([A-Za-z0-9+/=]+),type:([a-z]+)\]$`)

// Metadata fields SOPS writes as empty lists or zero values when unused.
// They are accepted only when empty.
var emptyKeyFields = map[string]bool{"kms": true, "gcp_kms": true, "azure_kv": true, "hc_vault": true, "pgp": true, "hckms": true}
var emptyOptionFields = map[string]bool{
	"encrypted_suffix": true, "unencrypted_regex": true, "encrypted_regex": true,
	"unencrypted_comment_regex": true, "encrypted_comment_regex": true,
	"key_groups": true, "shamir_threshold": true, "mac_only_encrypted": true,
}

var (
	errDecrypt = errors.New("decryption failed: an encrypted value could not be decrypted with the recovered data key")
	errMAC     = errors.New("integrity check failed: MAC mismatch, the document was modified after encryption or is corrupted")
)

type encValue struct {
	data, iv, tag []byte
	typ           string
}

func parseEnc(s string) (*encValue, bool) {
	m := encPattern.FindStringSubmatch(s)
	if m == nil {
		return nil, false
	}
	var v encValue
	for i, dst := range []*[]byte{&v.data, &v.iv, &v.tag} {
		b, err := base64.StdEncoding.DecodeString(m[i+1])
		if err != nil {
			return nil, false
		}
		*dst = b
	}
	if len(v.iv) != nonceSize || len(v.tag) != tagSize {
		return nil, false
	}
	v.typ = m[4]
	return &v, true
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCMWithNonceSize(block, nonceSize)
}

func (v *encValue) open(key []byte, aad string) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, v.iv, append(bytes.Clone(v.data), v.tag...), []byte(aad))
}

// seal encrypts plaintext in SOPS value form. Empty plaintext is stored as
// an empty string, as SOPS does; the MAC covers it.
func seal(key []byte, plaintext, aad, typ string) (string, error) {
	if plaintext == "" {
		return "", nil
	}
	gcm, err := newGCM(key)
	if err != nil {
		return "", err
	}
	iv := make([]byte, nonceSize)
	if _, err := rand.Read(iv); err != nil {
		return "", err
	}
	out := gcm.Seal(nil, iv, []byte(plaintext), []byte(aad))
	enc := base64.StdEncoding.EncodeToString
	return fmt.Sprintf("ENC[AES256_GCM,data:%s,iv:%s,tag:%s,type:%s]",
		enc(out[:len(out)-tagSize]), enc(iv), enc(out[len(out)-tagSize:]), typ), nil
}

// macOf is the SOPS MAC: SHA-512 over every value in document order.
func macOf(values []string) string {
	h := sha512.New()
	for _, v := range values {
		h.Write([]byte(v))
	}
	return fmt.Sprintf("%X", h.Sum(nil))
}

type ageStanza struct {
	recipient, enc string
}

func wrapDataKey(dataKey []byte, recipient string) (ageStanza, error) {
	r, err := age.ParseX25519Recipient(recipient)
	if err != nil {
		return ageStanza{}, fmt.Errorf("invalid age recipient %q", recipient)
	}
	var buf bytes.Buffer
	aw := armor.NewWriter(&buf)
	w, err := age.Encrypt(aw, r)
	if err != nil {
		return ageStanza{}, fmt.Errorf("cannot encrypt data key for an age recipient: %w", err)
	}
	if _, err := w.Write(dataKey); err != nil {
		return ageStanza{}, fmt.Errorf("cannot encrypt data key for an age recipient: %w", err)
	}
	if err := w.Close(); err != nil {
		return ageStanza{}, fmt.Errorf("cannot encrypt data key for an age recipient: %w", err)
	}
	if err := aw.Close(); err != nil {
		return ageStanza{}, fmt.Errorf("cannot encrypt data key for an age recipient: %w", err)
	}
	return ageStanza{recipient: recipient, enc: buf.String()}, nil
}

func wrapDataKeyFor(dataKey []byte, recipients []string) ([]ageStanza, error) {
	stanzas := make([]ageStanza, 0, len(recipients))
	for _, r := range recipients {
		s, err := wrapDataKey(dataKey, r)
		if err != nil {
			return nil, err
		}
		stanzas = append(stanzas, s)
	}
	return stanzas, nil
}

func newDataKey() ([]byte, error) {
	key := make([]byte, dataKeySize)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("cannot generate data key: %w", err)
	}
	return key, nil
}

type metadata struct {
	age          []ageStanza
	lastModified string
	mac          string
	// suffix is the stored unencrypted_suffix; empty means the default.
	suffix  string
	version string
}

func (m *metadata) unencryptedSuffix() string {
	if m.suffix == "" {
		return defaultUnencryptedSuffix
	}
	return m.suffix
}

func (m *metadata) recipients() []string {
	out := make([]string, 0, len(m.age))
	for _, s := range m.age {
		out = append(out, s.recipient)
	}
	return out
}

// macAAD is lastmodified re-formatted, which is what SOPS authenticates.
func (m *metadata) macAAD() string {
	t, _ := time.Parse(time.RFC3339, m.lastModified)
	return t.Format(time.RFC3339)
}

func stringScalar(n *yaml.Node) (string, bool) {
	if n.Kind != yaml.ScalarNode || n.ShortTag() != "!!str" {
		return "", false
	}
	return n.Value, true
}

func isEmptyField(n *yaml.Node) bool {
	switch n.Kind {
	case yaml.SequenceNode, yaml.MappingNode:
		return len(n.Content) == 0
	case yaml.ScalarNode:
		switch n.ShortTag() {
		case "!!null":
			return true
		case "!!str":
			return n.Value == ""
		case "!!int":
			return n.Value == "0"
		case "!!bool":
			return n.Value == "false"
		}
	}
	return false
}

func parseMetadata(n *yaml.Node) (metadata, error) {
	var m metadata
	if n.Kind != yaml.MappingNode {
		return m, fmt.Errorf("SOPS metadata is not a mapping")
	}
	seen := map[string]bool{}
	for i := 0; i+1 < len(n.Content); i += 2 {
		name, ok := stringScalar(n.Content[i])
		if !ok {
			return m, fmt.Errorf("SOPS metadata has a non-string key")
		}
		if seen[name] {
			return m, fmt.Errorf("SOPS metadata field %q appears more than once", name)
		}
		seen[name] = true
		v := n.Content[i+1]
		switch {
		case name == "age":
			stanzas, err := parseAgeStanzas(v)
			if err != nil {
				return m, err
			}
			m.age = stanzas
		case name == "lastmodified":
			s, ok := stringScalar(v)
			if !ok {
				return m, fmt.Errorf("SOPS metadata lastmodified is not a string")
			}
			if _, err := time.Parse(time.RFC3339, s); err != nil {
				return m, fmt.Errorf("SOPS metadata lastmodified is not an RFC 3339 timestamp")
			}
			m.lastModified = s
		case name == "mac":
			if m.mac, ok = stringScalar(v); !ok {
				return m, fmt.Errorf("SOPS metadata mac is not a string")
			}
		case name == "unencrypted_suffix":
			if m.suffix, ok = stringScalar(v); !ok {
				return m, fmt.Errorf("SOPS metadata unencrypted_suffix is not a string")
			}
		case name == "version":
			if m.version, ok = stringScalar(v); !ok {
				return m, fmt.Errorf("SOPS metadata version is not a string")
			}
		case emptyKeyFields[name]:
			if !isEmptyField(v) {
				return m, fmt.Errorf("document uses non-age master keys (%s); only age recipients are supported", name)
			}
		case emptyOptionFields[name]:
			if !isEmptyField(v) {
				return m, fmt.Errorf("unsupported SOPS option %q", name)
			}
		default:
			return m, fmt.Errorf("unsupported SOPS metadata field %q", name)
		}
	}
	switch {
	case len(m.age) == 0:
		return m, fmt.Errorf("document has no age recipients")
	case m.lastModified == "":
		return m, fmt.Errorf("SOPS metadata has no lastmodified timestamp")
	case m.mac == "":
		return m, fmt.Errorf("SOPS metadata has no MAC")
	}
	return m, nil
}

func parseAgeStanzas(n *yaml.Node) ([]ageStanza, error) {
	if n.Kind != yaml.SequenceNode {
		return nil, fmt.Errorf("SOPS metadata age is not a list")
	}
	var out []ageStanza
	for _, item := range n.Content {
		if item.Kind != yaml.MappingNode {
			return nil, fmt.Errorf("SOPS metadata age entry is not a mapping")
		}
		var s ageStanza
		for i := 0; i+1 < len(item.Content); i += 2 {
			k, ok1 := stringScalar(item.Content[i])
			v, ok2 := stringScalar(item.Content[i+1])
			if !ok1 || !ok2 {
				return nil, fmt.Errorf("SOPS metadata age entry has a non-string field")
			}
			switch {
			case k == "recipient" && s.recipient == "":
				s.recipient = v
			case k == "enc" && s.enc == "":
				s.enc = v
			default:
				return nil, fmt.Errorf("SOPS metadata age entry has an unsupported or repeated field %q", k)
			}
		}
		if s.recipient == "" || s.enc == "" {
			return nil, fmt.Errorf("SOPS metadata age entry needs recipient and enc")
		}
		out = append(out, s)
	}
	return out, nil
}

func metadataNode(m metadata) *yaml.Node {
	str := func(s string) *yaml.Node { return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: s} }
	ages := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
	for _, s := range m.age {
		enc := str(s.enc)
		enc.Style = yaml.LiteralStyle
		ages.Content = append(ages.Content, &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map", Content: []*yaml.Node{
			str("enc"), enc, str("recipient"), str(s.recipient),
		}})
	}
	lastModified := str(m.lastModified)
	lastModified.Style = yaml.DoubleQuotedStyle
	out := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map", Content: []*yaml.Node{
		str("age"), ages,
		str("lastmodified"), lastModified,
		str("mac"), str(m.mac),
	}}
	if m.suffix != "" {
		out.Content = append(out.Content, str("unencrypted_suffix"), str(m.suffix))
	}
	out.Content = append(out.Content, str("version"), str(m.version))
	return out
}

// entry is one secret in the document; plain entries are stored
// unencrypted because their name ends with the unencrypted suffix.
type entry struct {
	name  string
	value *yaml.Node
	plain bool
}

type document struct {
	root *yaml.Node
	body *yaml.Node
	// sopsAt is the index in body.Content of the sops key, or -1.
	sopsAt  int
	meta    metadata
	entries []entry
}

// parseYAML decodes exactly one YAML document whose root is a mapping.
func parseYAML(b []byte) (*yaml.Node, error) {
	dec := yaml.NewDecoder(bytes.NewReader(b))
	var root yaml.Node
	if err := dec.Decode(&root); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("document contains no secrets")
		}
		return nil, fmt.Errorf("not a valid YAML document")
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("expected exactly one YAML document")
	}
	if root.Kind != yaml.DocumentNode || len(root.Content) != 1 || root.Content[0].Kind != yaml.MappingNode {
		return nil, fmt.Errorf("document is not a YAML mapping")
	}
	return &root, nil
}

func valueTypeName(n *yaml.Node) string {
	switch n.Kind {
	case yaml.MappingNode:
		return "nested mapping"
	case yaml.SequenceNode:
		return "sequence"
	case yaml.AliasNode:
		return "alias"
	}
	switch n.ShortTag() {
	case "!!null":
		return "null"
	case "!!int":
		return "integer"
	case "!!float":
		return "float"
	case "!!bool":
		return "boolean"
	case "!!timestamp":
		return "timestamp"
	}
	return fmt.Sprintf("%q-tagged", n.ShortTag())
}

func encTypeName(t string) string {
	switch t {
	case "int":
		return "integer"
	case "bool":
		return "boolean"
	case "float", "bytes", "comment":
		return t
	case "time":
		return "timestamp"
	}
	return "unknown"
}

func nonString(name, kind string) error {
	return fmt.Errorf("secret %q has a %s value; all values must be YAML strings (quote the value)", name, kind)
}

// flatEntries checks that body is a flat mapping of names to strings.
// When encrypted, the sops key is skipped and its index returned, and every
// value that should be encrypted must be a SOPS string value.
func flatEntries(body *yaml.Node, encrypted bool, suffix string) ([]entry, int, error) {
	sopsAt := -1
	var entries []entry
	for i := 0; i+1 < len(body.Content); i += 2 {
		k, v := body.Content[i], body.Content[i+1]
		name, ok := stringScalar(k)
		if !ok {
			return nil, 0, fmt.Errorf("secret names must be strings")
		}
		if name == sopsMetadataKey {
			if !encrypted {
				return nil, 0, fmt.Errorf("input already contains a %q top-level key and appears to be SOPS-encrypted", sopsMetadataKey)
			}
			if sopsAt >= 0 {
				return nil, 0, fmt.Errorf("document has more than one %q key", sopsMetadataKey)
			}
			sopsAt = i
			continue
		}
		if !namePattern.MatchString(name) {
			return nil, 0, invalidName(name)
		}
		if _, ok := stringScalar(v); !ok {
			return nil, 0, nonString(name, valueTypeName(v))
		}
		e := entry{name: name, value: v, plain: encrypted && strings.HasSuffix(name, suffix)}
		if encrypted && !e.plain && v.Value != "" {
			enc, ok := parseEnc(v.Value)
			if !ok {
				return nil, 0, fmt.Errorf("secret %q is not a SOPS-encrypted value", name)
			}
			if enc.typ != "str" {
				return nil, 0, nonString(name, encTypeName(enc.typ))
			}
		}
		entries = append(entries, e)
	}
	return entries, sopsAt, nil
}

func parseEncrypted(b []byte) (*document, error) {
	root, err := parseYAML(b)
	if err != nil {
		return nil, fmt.Errorf("not a valid SOPS-encrypted YAML document (%d bytes): %w", len(b), err)
	}
	body := root.Content[0]
	var meta metadata
	found := false
	for i := 0; i+1 < len(body.Content); i += 2 {
		if name, ok := stringScalar(body.Content[i]); ok && name == sopsMetadataKey && !found {
			found = true
			if meta, err = parseMetadata(body.Content[i+1]); err != nil {
				return nil, err
			}
		}
	}
	if !found {
		return nil, fmt.Errorf("not a valid SOPS-encrypted YAML document (%d bytes): no %q metadata", len(b), sopsMetadataKey)
	}
	entries, sopsAt, err := flatEntries(body, true, meta.unencryptedSuffix())
	if err != nil {
		return nil, fmt.Errorf("document rejected: %w", err)
	}
	return &document{root: root, body: body, sopsAt: sopsAt, meta: meta, entries: entries}, nil
}

// unwrap recovers the data key with the first age stanza an identity opens.
func (d *document) unwrap(identities []age.Identity) ([]byte, error) {
	if len(identities) == 0 {
		return nil, errors.New("no identities")
	}
	for _, s := range d.meta.age {
		r, err := age.Decrypt(armor.NewReader(strings.NewReader(s.enc)), identities...)
		if err != nil {
			continue
		}
		key, err := io.ReadAll(io.LimitReader(r, dataKeySize+1))
		if err == nil && len(key) == dataKeySize {
			return key, nil
		}
	}
	return nil, errors.New("no identity matches")
}

// open decrypts every value and verifies the document MAC before returning
// any of them.
func (d *document) open(dataKey []byte) ([]string, error) {
	values := make([]string, 0, len(d.entries))
	for _, e := range d.entries {
		if e.plain || e.value.Value == "" {
			values = append(values, e.value.Value)
			continue
		}
		enc, _ := parseEnc(e.value.Value)
		pt, err := enc.open(dataKey, e.name+":")
		if err != nil {
			return nil, errDecrypt
		}
		values = append(values, string(pt))
	}
	stored, ok := parseEnc(d.meta.mac)
	if !ok || stored.typ != "str" {
		return nil, errMAC
	}
	mac, err := stored.open(dataKey, d.meta.macAAD())
	if err != nil || subtle.ConstantTimeCompare(mac, []byte(macOf(values))) != 1 {
		return nil, errMAC
	}
	return values, nil
}

// seal encrypts values into the entry nodes with dataKey and records a new
// MAC and timestamp.
func (d *document) seal(dataKey []byte, values []string) error {
	for i, e := range d.entries {
		if e.plain {
			continue
		}
		enc, err := seal(dataKey, values[i], e.name+":", "str")
		if err != nil {
			return fmt.Errorf("cannot encrypt document values: %w", err)
		}
		e.value.Value = enc
		e.value.Tag = "!!str"
		e.value.Style = 0
	}
	d.meta.lastModified = time.Now().UTC().Format(time.RFC3339)
	d.meta.version = formatVersion
	mac, err := seal(dataKey, macOf(values), d.meta.macAAD(), "str")
	if err != nil {
		return fmt.Errorf("cannot encrypt document MAC: %w", err)
	}
	d.meta.mac = mac
	return nil
}

// reencryptComments moves SOPS-encrypted comments to newKey. Comments that
// are not encrypted, or do not open with oldKey, are left as they are.
func reencryptComments(n *yaml.Node, oldKey, newKey []byte) error {
	for _, c := range []*string{&n.HeadComment, &n.LineComment, &n.FootComment} {
		if *c == "" {
			continue
		}
		lines := strings.Split(*c, "\n")
		for i, line := range lines {
			enc, ok := parseEnc(strings.TrimPrefix(line, "#"))
			if !ok || !strings.HasPrefix(line, "#") || enc.typ != "comment" {
				continue
			}
			pt, err := enc.open(oldKey, commentAAD)
			if err != nil {
				continue
			}
			out, err := seal(newKey, string(pt), commentAAD, "comment")
			if err != nil {
				return fmt.Errorf("cannot encrypt comment: %w", err)
			}
			lines[i] = "#" + out
		}
		*c = strings.Join(lines, "\n")
	}
	for _, child := range n.Content {
		if err := reencryptComments(child, oldKey, newKey); err != nil {
			return err
		}
	}
	return nil
}

func (d *document) emit() ([]byte, error) {
	meta := metadataNode(d.meta)
	if d.sopsAt >= 0 {
		d.body.Content[d.sopsAt+1] = meta
	} else {
		key := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: sopsMetadataKey}
		d.body.Content = append(d.body.Content, key, meta)
		d.sopsAt = len(d.body.Content) - 2
	}
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(4)
	if err := enc.Encode(d.root); err != nil {
		return nil, fmt.Errorf("cannot serialize encrypted document: %w", err)
	}
	if err := enc.Close(); err != nil {
		return nil, fmt.Errorf("cannot serialize encrypted document: %w", err)
	}
	return buf.Bytes(), nil
}

func (d *document) secrets(values []string) []Secret {
	out := make([]Secret, len(d.entries))
	for i, e := range d.entries {
		out[i] = Secret{Name: e.name, Value: values[i]}
	}
	return out
}
