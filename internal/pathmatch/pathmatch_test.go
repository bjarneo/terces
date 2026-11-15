package pathmatch

import "testing"

func TestMatch(t *testing.T) {
	cases := []struct {
		glob string
		path string
		want bool
	}{
		{"vendor/", "vendor/a/b.go", true},
		{"vendor/", "src/vendor/a.go", true},
		{"vendor/", "vendor", false},
		{"node_modules", "web/node_modules/x/index.js", true},
		{"*.min.js", "static/app.min.js", true},
		{"*.min.js", "static/app.js", false},
		{"package-lock.json", "a/b/package-lock.json", true},
		{"/docs/", "docs/readme.md", true},
		{"/docs/", "src/docs/readme.md", false},
		{"test/fixtures/**", "test/fixtures/a/b.txt", true},
		{"test/fixtures/**", "x/test/fixtures/a.txt", false},
		{"**/fixtures/**", "x/test/fixtures/a.txt", true},
		{"**/*.pem", "a/b/c.pem", true},
		{"**/*.pem", "c.pem", true},
		{"src/*.go", "src/main.go", true},
		{"src/*.go", "src/x/main.go", false},
		{"a/**/b", "a/b", true},
		{"a/**/b", "a/x/y/b", true},
		{"*.[ot]tf", "font.ttf", true},
		{"file?.txt", "file1.txt", true},
		{"file?.txt", "file12.txt", false},
	}
	for _, c := range cases {
		p, err := Compile(c.glob)
		if err != nil {
			t.Fatalf("Compile(%q): %v", c.glob, err)
		}
		if got := p.Match(c.path); got != c.want {
			t.Errorf("%q.Match(%q) = %v, want %v (re %s)", c.glob, c.path, got, c.want, p.re)
		}
	}
}

func TestCompileErrors(t *testing.T) {
	for _, g := range []string{"", "/", "[abc"} {
		if _, err := Compile(g); err == nil {
			t.Errorf("Compile(%q) returned no error", g)
		}
	}
}
