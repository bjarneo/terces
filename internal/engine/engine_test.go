package engine

import (
	"bytes"
	"encoding/base64"
	"math/rand/v2"
	"net/url"
	"strings"
	"testing"
	"testing/fstest"

	"terces/internal/rules"
	"terces/internal/testsecret"
)

func TestAutomatonMatchesNaiveSearch(t *testing.T) {
	keywords := []string{"akia", "secret", "sec", "ret", "-----begin", "ghp_", "token", "ken", "a"}
	ac := newAutomaton(keywords)
	rng := rand.New(rand.NewPCG(1, 2))
	alphabet := "aAkKiIsSeEcCrRtToOnN-_bgGhHp "
	for i := 0; i < 2000; i++ {
		n := rng.IntN(60)
		var b strings.Builder
		for j := 0; j < n; j++ {
			b.WriteByte(alphabet[rng.IntN(len(alphabet))])
		}
		text := b.String()
		got := map[int32]bool{}
		ac.scan([]byte(text), func(k int32, _ int) { got[k] = true })
		lower := strings.ToLower(text)
		for k, kw := range keywords {
			want := strings.Contains(lower, kw)
			if got[int32(k)] != want {
				t.Fatalf("text %q keyword %q: got %v, want %v", text, kw, got[int32(k)], want)
			}
		}
	}
}

func TestEntropy(t *testing.T) {
	if e := entropy([]byte("aaaaaaaa")); e != 0 {
		t.Errorf("entropy of one symbol = %v, want 0", e)
	}
	if e := entropy([]byte("abcdabcd")); e != 2 {
		t.Errorf("entropy of four symbols = %v, want 2", e)
	}
	if e := entropy([]byte(testsecret.AWSSecret())); e < 4 {
		t.Errorf("entropy of a random secret = %v, want 4 or more", e)
	}
}

const testRules = `
- id: key-id
  keywords: [KEYID]
  regex: '\b(KEYID[A-Z0-9]{12})\b'
  severity: high
- id: key-secret
  keywords: [keysecret]
  regex: 'keysecret\s*=\s*([A-Za-z0-9]{24})'
  entropy_min: 3.5
  pair_with: key-id
  severity: critical
- id: token
  keywords: [tok_]
  regex: '\btok_[a-z0-9]{20}\b'
  severity: medium
  allow:
    - regex_target: line
      regexes: ['ALLOW-THIS-LINE']
    - condition: and
      regexes: ['^tok_0']
      paths: ['(^|/)examples/']
`

const testAllowlist = `
values: [tok_aaaaaaaaaaaaaaaaaaaa]
regexes: ['(?i)x{4,}']
downgrade_paths: [test/fixtures/]
`

func newTestEngine(t *testing.T) *Engine {
	t.Helper()
	set, err := rules.LoadFS(fstest.MapFS{
		"test.yaml":      {Data: []byte(testRules)},
		"allowlist.yaml": {Data: []byte(testAllowlist)},
	}, "test")
	if err != nil {
		t.Fatal(err)
	}
	return New(set)
}

func ids(ms []Match) []string {
	var out []string
	for _, m := range ms {
		out = append(out, m.Rule.ID)
	}
	return out
}

func TestScanPairing(t *testing.T) {
	e := newTestEngine(t)
	id := "KEYID" + testsecret.Rand("A-Z0-9", 12)
	secret := testsecret.Rand("A-Za-z0-9", 24)

	ms := e.Scan([]byte("keysecret = " + secret))
	if len(ms) != 0 {
		t.Errorf("unpaired secret: got %v, want no match", ids(ms))
	}
	ms = e.Scan([]byte("id=" + id + "\nkeysecret = " + secret + "\n"))
	if got := strings.Join(ids(ms), ","); got != "key-id,key-secret" {
		t.Fatalf("paired secret: got %s", got)
	}
	if ms[1].Line != 2 || string(ms[1].Secret) != secret {
		t.Errorf("secret match: line %d, want 2", ms[1].Line)
	}
}

func TestScanEntropyAndAllowlist(t *testing.T) {
	e := newTestEngine(t)
	id := "KEYID" + testsecret.Rand("A-Z0-9", 12)
	if ms := e.Scan([]byte(id + "\nkeysecret = " + strings.Repeat("ab", 12))); len(ms) != 1 {
		t.Errorf("low entropy secret: got %v, want only key-id", ids(ms))
	}
	if ms := e.Scan([]byte("tok_aaaaaaaaaaaaaaaaaaaa")); len(ms) != 0 {
		t.Errorf("allowlisted value: got %v", ids(ms))
	}
	if ms := e.Scan([]byte("tok_" + "abcxxxx" + testsecret.Rand("a-z0-9", 13))); len(ms) != 0 {
		t.Errorf("placeholder: got %v", ids(ms))
	}
	if ms := e.Scan([]byte("tok_" + testsecret.Rand("a-w0-9", 20) + " # ALLOW-THIS-LINE")); len(ms) != 0 {
		t.Errorf("rule allowlist on line: got %v", ids(ms))
	}
}

func TestApplyPath(t *testing.T) {
	e := newTestEngine(t)
	tok := "tok_0" + testsecret.Rand("a-w1-9", 19)
	ms := e.Scan([]byte(tok))
	if len(ms) != 1 || len(ms[0].PathAllow) != 1 {
		t.Fatalf("got %d matches, want 1 with a pending path allow entry", len(ms))
	}
	m := ms[0]
	if _, reason := e.ApplyPath(m.Rule.ID, m.PathAllow, m.Rule.Sev, "examples/demo.sh"); reason == "" {
		t.Error("examples path: want the AND allowlist entry to drop the match")
	}
	sev, reason := e.ApplyPath(m.Rule.ID, m.PathAllow, m.Rule.Sev, "src/app.sh")
	if reason != "" || sev != rules.SeverityMedium {
		t.Errorf("src path: severity %v reason %q", sev, reason)
	}
	sev, _ = e.ApplyPath(m.Rule.ID, m.PathAllow, m.Rule.Sev, "test/fixtures/a.sh")
	if sev != rules.SeverityLow {
		t.Errorf("fixture path: severity %v, want low", sev)
	}
}

func TestScanDecodesBase64AndURL(t *testing.T) {
	e := newTestEngine(t)
	tok := "tok_" + testsecret.Rand("a-w0-9", 20)
	inner := "config:\n  token: " + tok + "\n"
	b64 := base64.StdEncoding.EncodeToString([]byte(inner))
	ms := e.Scan([]byte("line one\ndata: " + b64 + "\n"))
	if len(ms) != 1 || ms[0].Decoded != "base64" || ms[0].Line != 2 || string(ms[0].Secret) != tok {
		t.Fatalf("base64: got %d matches %+v", len(ms), ms)
	}

	enc := url.QueryEscape("x=1&token=" + tok + "&y=2")
	ms = e.Scan([]byte("redirect=" + enc))
	if len(ms) != 1 || ms[0].Decoded != "url" {
		t.Fatalf("url: got %d matches", len(ms))
	}

	// A plain match and an encoded copy of the same secret give one match.
	ms = e.Scan([]byte(tok + "\n" + b64))
	if len(ms) != 1 || ms[0].Decoded != "" {
		t.Errorf("plain and encoded: got %d matches", len(ms))
	}
}

func TestDecodeSkipsHexAndBinary(t *testing.T) {
	hexRun := strings.Repeat("0123456789abcdef", 4)
	if segs := decodeSegments([]byte(hexRun)); len(segs) != 0 {
		t.Errorf("hex run decoded to %d segments", len(segs))
	}
	random := make([]byte, 60)
	for i := range random {
		random[i] = byte(i * 37)
	}
	if segs := decodeSegments([]byte(base64.StdEncoding.EncodeToString(random))); len(segs) != 0 {
		t.Errorf("binary base64 decoded to %d segments", len(segs))
	}
}

func TestExplain(t *testing.T) {
	e := newTestEngine(t)
	cands, err := e.Explain("key-secret", []byte("keysecret = "+testsecret.Rand("A-Za-z0-9", 24)))
	if err != nil {
		t.Fatal(err)
	}
	if len(cands) != 1 || !strings.HasPrefix(cands[0].Dropped, "unpaired") {
		t.Errorf("got %+v, want one unpaired candidate", cands)
	}
	if _, err := e.Explain("nope", nil); err == nil {
		t.Error("unknown rule: want an error")
	}
}

func TestCacheVersionChanges(t *testing.T) {
	e := newTestEngine(t)
	if e.CacheVersion(1) == e.CacheVersion(2) {
		t.Error("the cache version must depend on the size limit")
	}
	set, err := rules.LoadFS(fstest.MapFS{
		"test.yaml": {Data: []byte(strings.Replace(testRules, "severity: medium", "severity: low", 1))},
	}, "test")
	if err != nil {
		t.Fatal(err)
	}
	if New(set).CacheVersion(1) == e.CacheVersion(1) {
		t.Error("the cache version must depend on the rules")
	}
}

func TestSecretGroupFirstNonEmpty(t *testing.T) {
	set, err := rules.LoadFS(fstest.MapFS{"r.yaml": {Data: []byte(`
- id: alt
  keywords: [alt]
  regex: 'alt=(?:"([a-z]{8})"|([0-9]{8}))'
  severity: low
`)}}, "test")
	if err != nil {
		t.Fatal(err)
	}
	ms := New(set).Scan([]byte("alt=12345678"))
	if len(ms) != 1 || !bytes.Equal(ms[0].Secret, []byte("12345678")) {
		t.Errorf("got %+v, want the second group", ms)
	}
}

func BenchmarkScanNoMatch(b *testing.B) {
	set, err := rules.LoadFS(fstest.MapFS{"test.yaml": {Data: []byte(testRules)}}, "test")
	if err != nil {
		b.Fatal(err)
	}
	e := New(set)
	data := bytes.Repeat([]byte("func main() { fmt.Println(\"hello, world\") }\n"), 2000)
	b.SetBytes(int64(len(data)))
	for b.Loop() {
		e.Scan(data)
	}
}

func TestDroppedMatchesDoNotHideASecret(t *testing.T) {
	e := newTestEngine(t)
	var b strings.Builder
	for i := 0; i < 300; i++ {
		b.WriteString("tok_aaaaaaaaaaaaaaaaaaaa\n")
	}
	tok := "tok_" + testsecret.Rand("a-w0-9", 20)
	b.WriteString(tok + "\n")
	ms := e.Scan([]byte(b.String()))
	if len(ms) != 1 || string(ms[0].Secret) != tok || ms[0].Line != 301 {
		t.Fatalf("got %d matches, want the secret after 300 allowlisted values", len(ms))
	}
}

// Copies of one secret must not use up the match limit and hide a later
// secret. More different secrets than the limit set Info.Capped.
func TestMatchLimitCountsDifferentSecrets(t *testing.T) {
	e := newTestEngine(t)
	first := "tok_" + testsecret.Rand("a-w0-9", 20)
	last := "tok_" + testsecret.Rand("a-w0-9", 20)
	text := strings.Repeat(first+"\n", 300) + last + "\n"
	ms, info := e.ScanStats([]byte(text))
	if len(ms) != 2 || string(ms[1].Secret) != last || info.Capped {
		t.Fatalf("got %d matches, capped %v, want 2 and false", len(ms), info.Capped)
	}
	var b strings.Builder
	for i := 0; i < maxKeptPerRule+5; i++ {
		b.WriteString("tok_" + testsecret.Rand("a-w0-9", 20) + "\n")
	}
	ms, info = e.ScanStats([]byte(b.String()))
	if len(ms) != maxKeptPerRule || !info.Capped {
		t.Errorf("got %d matches, capped %v, want %d and true", len(ms), info.Capped, maxKeptPerRule)
	}
}

// An allowlist entry with regex_target: line sees a bounded part of a long
// line, so many candidates on one minified line cost linear time.
func TestLineAroundIsBounded(t *testing.T) {
	line := []byte(strings.Repeat("a", 100_000) + "MATCH" + strings.Repeat("b", 100_000))
	got := lineAround(line, 100_000, 100_005)
	if len(got) != 2*maxLineContext+5 || !bytes.Contains(got, []byte("MATCH")) {
		t.Errorf("lineAround returned %d bytes, want %d", len(got), 2*maxLineContext+5)
	}
	short := []byte("x\nkey=MATCH # ok\ny")
	if got := string(lineAround(short, 6, 11)); got != "key=MATCH # ok" {
		t.Errorf("lineAround on a short line = %q", got)
	}
}
