package githubapp

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func testKey(t *testing.T) (*rsa.PrivateKey, []byte) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return key, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
}

func verifyJWT(t *testing.T, pub *rsa.PublicKey, tok string) map[string]any {
	t.Helper()
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatalf("JWT has %d parts", len(parts))
	}
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, sum[:], sig); err != nil {
		t.Fatalf("JWT signature: %v", err)
	}
	payload, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatal(err)
	}
	return claims
}

func TestJWT(t *testing.T) {
	key, pemData := testKey(t)
	app, err := New("12345", pemData, "http://unused")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0)
	app.Now = func() time.Time { return now }
	tok, err := app.JWT()
	if err != nil {
		t.Fatal(err)
	}
	claims := verifyJWT(t, &key.PublicKey, tok)
	if claims["iss"] != "12345" {
		t.Errorf("iss = %v", claims["iss"])
	}
	exp := int64(claims["exp"].(float64))
	if exp-now.Unix() > 600 {
		t.Errorf("exp is %d seconds ahead: GitHub allows 600 or less", exp-now.Unix())
	}
}

func TestInstallationsTokensAndPagination(t *testing.T) {
	key, pemData := testKey(t)
	var tokenCalls atomic.Int32
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		switch {
		case r.URL.Path == "/app/installations":
			verifyJWT(t, &key.PublicKey, strings.TrimPrefix(auth, "Bearer "))
			fmt.Fprint(w, `[{"id":7,"account":{"login":"acme","type":"Organization"}}]`)
		case r.URL.Path == "/app/installations/7/access_tokens" && r.Method == http.MethodPost:
			tokenCalls.Add(1)
			fmt.Fprintf(w, `{"token":"tok-7","expires_at":%q}`, time.Now().Add(time.Hour).Format(time.RFC3339))
		case r.URL.Path == "/installation/repositories":
			if auth != "token tok-7" {
				t.Errorf("repositories auth = %q", auth)
			}
			if r.URL.Query().Get("page") == "" {
				w.Header().Set("Link", fmt.Sprintf(`<%s/installation/repositories?per_page=100&page=2>; rel="next"`, srv.URL))
				fmt.Fprint(w, `{"repositories":[{"id":1,"full_name":"acme/a"}]}`)
				return
			}
			fmt.Fprint(w, `{"repositories":[{"id":2,"full_name":"acme/b","archived":true}]}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	app, err := New("1", pemData, srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	insts, err := app.Installations(ctx)
	if err != nil || len(insts) != 1 || insts[0].Account.Login != "acme" {
		t.Fatalf("installations: %+v %v", insts, err)
	}
	repos, err := app.Repositories(ctx, 7)
	if err != nil || len(repos) != 2 || !repos[1].Archived {
		t.Fatalf("repositories: %+v %v", repos, err)
	}
	if _, err := app.Token(ctx, 7); err != nil {
		t.Fatal(err)
	}
	if n := tokenCalls.Load(); n != 1 {
		t.Errorf("token requests = %d, want 1 because of the cache", n)
	}
	if _, err := app.Installation(ctx, 99); !IsNotFound(err) {
		t.Errorf("missing installation: %v", err)
	}
}

func TestRateLimitWait(t *testing.T) {
	now := time.Unix(1000, 0)
	resp := &http.Response{StatusCode: 403, Header: http.Header{}}
	resp.Header.Set("X-RateLimit-Remaining", "0")
	resp.Header.Set("X-RateLimit-Reset", "1030")
	if d, ok := rateLimitWait(resp, now); !ok || d != 31*time.Second {
		t.Errorf("reset header: %v %v", d, ok)
	}
	resp = &http.Response{StatusCode: 403, Header: http.Header{}}
	if _, ok := rateLimitWait(resp, now); ok {
		t.Error("a plain 403 is not a rate limit")
	}
}
