package safetext

import (
	"testing"
	"unicode/utf8"
)

func TestDisplay(t *testing.T) {
	cases := map[string]string{
		"src/app.go":          "src/app.go",
		"docs/über café.md":   "docs/über café.md",
		"ghp_… (40)":          "ghp_… (40)",
		"caf\xe9.env":         `"caf\xe9.env"`,
		"a\x1b]0;X\a\x1b[2Kb": `"a\x1b]0;X\a\x1b[2Kb"`,
		"dir\nx.env":          `"dir\nx.env"`,
		"tab\there":           `"tab\there"`,
		"evil\u202etxt.exe":   `"evil\u202etxt.exe"`,
		"c1\u009bcontrol":     `"c1\u009bcontrol"`,
		`"quoted"`:            `"\"quoted\""`,
		"":                    "",
	}
	for in, want := range cases {
		got := Display(in)
		if got != want {
			t.Errorf("Display(%q) = %s, want %s", in, got, want)
		}
		if !utf8.ValidString(got) {
			t.Errorf("Display(%q) is not valid UTF-8", in)
		}
	}
}

func TestInline(t *testing.T) {
	cases := map[string]string{
		"git fetch: exit status 128\nfatal: no such repo": "git fetch: exit status 128\nfatal: no such repo",
		"open caf\xe9.env: denied":                        `open caf\xe9.env: denied`,
		"a\x1b[2Kb":                                       `a\x1b[2Kb`,
		"c1\u009bx":                                       `c1\u009bx`,
		`say "hi"`:                                        `say "hi"`,
	}
	for in, want := range cases {
		if got := Inline(in); got != want {
			t.Errorf("Inline(%q) = %q, want %q", in, got, want)
		}
	}
}
