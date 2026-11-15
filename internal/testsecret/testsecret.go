// Package testsecret makes fake secrets at test time. Tests use it, so
// that no file in the repository holds a token that other scanners flag.
//
// Expand replaces these placeholders:
//
//	{{rand:<charset>:<n>}}  n random characters from charset, for example A-Z2-7
//	{{dashes}}             five dashes, for PEM headers
//
// The generator uses a fixed seed, so a test run is reproducible. Set
// TESTSECRET_SEED to an integer to try other values.
package testsecret

import (
	"fmt"
	"math/rand/v2"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
)

var (
	mu  sync.Mutex
	rng = rand.New(rand.NewPCG(seed(), 0x5ec2e7))
)

func seed() uint64 {
	if s, err := strconv.ParseUint(os.Getenv("TESTSECRET_SEED"), 10, 64); err == nil {
		return s
	}
	return 20261114
}

var placeholder = regexp.MustCompile(`\{\{(rand:[^:}]+:\d+|dashes)\}\}`)

// Expand replaces the placeholders in a template.
func Expand(tmpl string) string {
	return placeholder.ReplaceAllStringFunc(tmpl, func(m string) string {
		inner := m[2 : len(m)-2]
		if inner == "dashes" {
			return "-----"
		}
		parts := strings.Split(inner, ":")
		n, _ := strconv.Atoi(parts[2])
		return Rand(parts[1], n)
	})
}

// Rand returns n random characters from a charset such as "A-Z0-9+/".
func Rand(charset string, n int) string {
	chars := expandCharset(charset)
	var b strings.Builder
	mu.Lock()
	defer mu.Unlock()
	for i := 0; i < n; i++ {
		b.WriteByte(chars[rng.IntN(len(chars))])
	}
	return b.String()
}

func expandCharset(spec string) []byte {
	var out []byte
	for i := 0; i < len(spec); i++ {
		if i+2 < len(spec) && spec[i+1] == '-' {
			for c := spec[i]; c <= spec[i+2]; c++ {
				out = append(out, c)
			}
			i += 2
			continue
		}
		out = append(out, spec[i])
	}
	if len(out) == 0 {
		panic(fmt.Sprintf("testsecret: empty charset %q", spec))
	}
	return out
}

// AWSKeyID returns a fake AWS access key ID.
func AWSKeyID() string { return "AKIA" + Rand("A-Z2-7", 16) }

// AWSSecret returns a fake AWS secret access key.
func AWSSecret() string { return Rand("A-Za-z0-9/+", 40) }

// GitHubPAT returns a fake classic GitHub personal access token.
func GitHubPAT() string { return "gh" + "p_" + Rand("A-Za-z0-9", 36) }

// PrivateKey returns a fake PEM private key block.
func PrivateKey() string {
	var b strings.Builder
	b.WriteString(Expand("{{dashes}}BEGIN RSA PRIVATE KEY{{dashes}}\n"))
	for i := 0; i < 6; i++ {
		b.WriteString(Rand("A-Za-z0-9+/", 64) + "\n")
	}
	b.WriteString(Expand("{{dashes}}END RSA PRIVATE KEY{{dashes}}\n"))
	return b.String()
}
