// Package fingerprint turns a plaintext secret into a stable, keyed
// fingerprint and a short preview. The plaintext never leaves this step.
package fingerprint

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"unicode/utf8"
)

// MinKeyLen is the minimum length of the HMAC key in bytes.
const MinKeyLen = 32

// Hasher computes HMAC-SHA256 fingerprints.
type Hasher struct {
	key       []byte
	ephemeral bool
}

// New returns a Hasher for a key.
func New(key []byte) (*Hasher, error) {
	if len(key) < MinKeyLen {
		return nil, fmt.Errorf("the HMAC key has %d bytes: use %d bytes or more", len(key), MinKeyLen)
	}
	return &Hasher{key: append([]byte(nil), key...)}, nil
}

// NewEphemeral returns a Hasher with a random key. Its fingerprints are
// valid only for the current process. Local scans use it when no key is
// set.
func NewEphemeral() *Hasher {
	key := make([]byte, MinKeyLen)
	if _, err := rand.Read(key); err != nil {
		panic(err)
	}
	return &Hasher{key: key, ephemeral: true}
}

// Ephemeral reports whether the key is random for this process.
func (h *Hasher) Ephemeral() bool { return h.ephemeral }

// Fingerprint returns HMAC-SHA256(key, secret).
func (h *Hasher) Fingerprint(secret []byte) []byte {
	m := hmac.New(sha256.New, h.key)
	m.Write(secret)
	return m.Sum(nil)
}

// KeyID returns 8 bytes that identify the key. It is an HMAC of a fixed
// text, so it tells nothing about the key itself.
func (h *Hasher) KeyID() []byte {
	return h.Fingerprint([]byte("terces key id"))[:8]
}

// ParseKey decodes a key from hex or base64 text.
func ParseKey(text string) ([]byte, error) {
	text = strings.TrimSpace(text)
	if text == "" {
		return nil, fmt.Errorf("the HMAC key is empty")
	}
	if b, err := hex.DecodeString(text); err == nil {
		return b, nil
	}
	if b, err := base64.StdEncoding.DecodeString(text); err == nil {
		return b, nil
	}
	if b, err := base64.RawStdEncoding.DecodeString(text); err == nil {
		return b, nil
	}
	return nil, fmt.Errorf("the HMAC key is not hex or base64")
}

// LoadKey reads the key from a value or from a file. The value has
// priority. It returns nil when both are empty.
func LoadKey(value, file string) ([]byte, error) {
	if value == "" && file != "" {
		data, err := os.ReadFile(file)
		if err != nil {
			return nil, fmt.Errorf("read HMAC key file: %w", err)
		}
		value = string(data)
	}
	if value == "" {
		return nil, nil
	}
	return ParseKey(value)
}

// Hex returns the lowercase hex form of a fingerprint.
func Hex(fp []byte) string { return hex.EncodeToString(fp) }

// Short returns the first 12 hex characters of a fingerprint.
func Short(fp []byte) string {
	s := Hex(fp)
	if len(s) > 12 {
		return s[:12]
	}
	return s
}

// Preview returns the first characters of a secret and its length, for
// example "AKIA… (20)". A secret with fewer than 16 characters shows one
// character for each 4 characters of length. This keeps short secrets,
// such as passwords, mostly hidden.
func Preview(secret []byte) string {
	n := utf8.RuneCount(secret)
	show := 4
	if n < 16 {
		show = n / 4
	}
	var b strings.Builder
	i := 0
	for _, r := range string(secret) {
		if i >= show {
			break
		}
		if r < 0x20 || r == 0x7f || r == utf8.RuneError {
			r = '.'
		}
		b.WriteRune(r)
		i++
	}
	return fmt.Sprintf("%s… (%d)", b.String(), n)
}
