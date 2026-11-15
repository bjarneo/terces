package fingerprint

import (
	"bytes"
	"strings"
	"testing"
)

func TestPreview(t *testing.T) {
	cases := map[string]string{
		"abcdEFGHijklMNOPqrst": "abcd… (20)",
		"hunter2!":             "hu… (8)",
		"abc":                  "… (3)",
		"line1\nline2xxxxxxxx": "line… (19)",
		"\x01\x02\x03\x04" + strings.Repeat("z", 20): "....… (24)",
	}
	for in, want := range cases {
		if got := Preview([]byte(in)); got != want {
			t.Errorf("Preview(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestFingerprintIsKeyed(t *testing.T) {
	a, _ := New(bytes.Repeat([]byte{1}, 32))
	b, _ := New(bytes.Repeat([]byte{2}, 32))
	s := []byte("secret")
	if !bytes.Equal(a.Fingerprint(s), a.Fingerprint(s)) {
		t.Error("the same key must give the same fingerprint")
	}
	if bytes.Equal(a.Fingerprint(s), b.Fingerprint(s)) {
		t.Error("different keys must give different fingerprints")
	}
	if _, err := New([]byte("short")); err == nil {
		t.Error("short key: want an error")
	}
}

func TestParseKey(t *testing.T) {
	for _, in := range []string{strings.Repeat("ab", 32), "q83vq83vq83vq83vq83vq83vq83vq83vq83vq83vq80=\n"} {
		k, err := ParseKey(in)
		if err != nil || len(k) != 32 {
			t.Errorf("ParseKey(%q): %d bytes, %v", in, len(k), err)
		}
	}
	if _, err := ParseKey("not a key!"); err == nil {
		t.Error("invalid key: want an error")
	}
}
