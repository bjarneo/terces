package repoconfig

import (
	"encoding/hex"
	"testing"
)

func TestParseAndIgnored(t *testing.T) {
	fp, _ := hex.DecodeString("3f2a9c1b04de5f6a7b8c9d0e1f2a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c")
	c, err := Parse([]byte("ignore:\n  - fingerprint: 3F2A9C1B04DE5F6A7B\n    note: docs example\n  - 0000000000000000\n"))
	if err != nil {
		t.Fatal(err)
	}
	if !c.Ignored(fp) {
		t.Error("a matching prefix must ignore the fingerprint")
	}
	if c.Ignored([]byte{1, 2, 3}) {
		t.Error("an unrelated fingerprint is ignored")
	}
	var nilCfg *Config
	if nilCfg.Ignored(fp) {
		t.Error("a nil config must ignore nothing")
	}
	for _, bad := range []string{"ignore: [abc]", "ignore: [zzzzzzzzzzzzzzzzzzzz]", "ignore: {"} {
		if _, err := Parse([]byte(bad)); err == nil {
			t.Errorf("Parse(%q): want an error", bad)
		}
	}
}
