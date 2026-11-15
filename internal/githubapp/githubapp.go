// Package githubapp authenticates as a GitHub App and calls the REST API
// for installations, repositories and check runs.
package githubapp

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// App is a GitHub App client. It is safe for concurrent use.
type App struct {
	// ID is the app ID or the client ID. GitHub accepts both as the JWT issuer.
	ID     string
	Key    *rsa.PrivateKey
	APIURL string
	HTTP   *http.Client
	// Now returns the current time. Tests replace it.
	Now func() time.Time

	mu     sync.Mutex
	tokens map[int64]token
}

type token struct {
	value   string
	expires time.Time
}

// New returns an App for an app ID and a PEM private key.
func New(id string, keyPEM []byte, apiURL string) (*App, error) {
	key, err := ParsePrivateKey(keyPEM)
	if err != nil {
		return nil, err
	}
	return &App{
		ID:     id,
		Key:    key,
		APIURL: strings.TrimSuffix(apiURL, "/"),
		HTTP:   &http.Client{Timeout: 60 * time.Second},
		Now:    time.Now,
		tokens: map[int64]token{},
	}, nil
}

// ParsePrivateKey parses an RSA key in PKCS #1 or PKCS #8 PEM format.
func ParsePrivateKey(data []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("the GitHub App key is not PEM")
	}
	if k, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return k, nil
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse GitHub App key: %w", err)
	}
	rk, ok := k.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("the GitHub App key is not an RSA key")
	}
	return rk, nil
}

// JWT returns a signed app token. It is valid for 9 minutes. The issue
// time is 60 seconds in the past to allow for clock drift.
func (a *App) JWT() (string, error) {
	now := a.Now()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	claims, err := json.Marshal(map[string]any{
		"iat": now.Add(-60 * time.Second).Unix(),
		"exp": now.Add(9 * time.Minute).Unix(),
		"iss": a.ID,
	})
	if err != nil {
		return "", err
	}
	unsigned := header + "." + base64.RawURLEncoding.EncodeToString(claims)
	sum := sha256.Sum256([]byte(unsigned))
	sig, err := rsa.SignPKCS1v15(rand.Reader, a.Key, crypto.SHA256, sum[:])
	if err != nil {
		return "", err
	}
	return unsigned + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// APIError is a non-2xx API response.
type APIError struct {
	Method, Path string
	Status       int
	Message      string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("GitHub API %s %s: %d %s", e.Method, e.Path, e.Status, e.Message)
}

// IsNotFound reports whether err is a 404 response.
func IsNotFound(err error) bool {
	var e *APIError
	return errors.As(err, &e) && e.Status == http.StatusNotFound
}

// do sends one request. It waits and retries when GitHub reports a rate
// limit. It returns the Link header for pagination.
func (a *App) do(ctx context.Context, method, path, auth string, body, out any) (string, error) {
	var payload []byte
	if body != nil {
		var err error
		if payload, err = json.Marshal(body); err != nil {
			return "", err
		}
	}
	url := path
	if !strings.HasPrefix(path, "http") {
		url = a.APIURL + path
	}
	for attempt := 0; ; attempt++ {
		req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewReader(payload))
		if err != nil {
			return "", err
		}
		req.Header.Set("Accept", "application/vnd.github+json")
		req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
		req.Header.Set("User-Agent", "terces")
		req.Header.Set("Authorization", auth)
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err := a.HTTP.Do(req)
		if err != nil {
			return "", err
		}
		data, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
		resp.Body.Close()
		if err != nil {
			return "", err
		}
		if wait, ok := rateLimitWait(resp, a.Now()); ok && attempt < 3 {
			select {
			case <-ctx.Done():
				return "", ctx.Err()
			case <-time.After(wait):
			}
			continue
		}
		if resp.StatusCode >= 300 {
			var msg struct {
				Message string `json:"message"`
			}
			_ = json.Unmarshal(data, &msg)
			return "", &APIError{Method: method, Path: path, Status: resp.StatusCode, Message: msg.Message}
		}
		if out != nil && len(data) > 0 {
			if err := json.Unmarshal(data, out); err != nil {
				return "", fmt.Errorf("decode %s %s: %w", method, path, err)
			}
		}
		return resp.Header.Get("Link"), nil
	}
}

// rateLimitWait returns the wait time for a rate-limited response. It
// waits 15 minutes or less.
func rateLimitWait(resp *http.Response, now time.Time) (time.Duration, bool) {
	if resp.StatusCode != http.StatusForbidden && resp.StatusCode != http.StatusTooManyRequests {
		return 0, false
	}
	var wait time.Duration
	if s := resp.Header.Get("Retry-After"); s != "" {
		if n, err := strconv.Atoi(s); err == nil {
			wait = time.Duration(n) * time.Second
		}
	} else if resp.Header.Get("X-RateLimit-Remaining") == "0" {
		if n, err := strconv.ParseInt(resp.Header.Get("X-RateLimit-Reset"), 10, 64); err == nil {
			wait = time.Unix(n, 0).Sub(now) + time.Second
		}
	} else {
		return 0, false
	}
	if wait < time.Second {
		wait = time.Second
	}
	if wait > 15*time.Minute {
		wait = 15 * time.Minute
	}
	return wait, true
}

var nextLink = regexp.MustCompile(`<([^>]+)>;\s*rel="next"`)

// paginate calls fn for each page of a list endpoint.
func (a *App) paginate(ctx context.Context, path, auth string, page func(data json.RawMessage) error) error {
	url := path
	for url != "" {
		var raw json.RawMessage
		link, err := a.do(ctx, http.MethodGet, url, auth, nil, &raw)
		if err != nil {
			return err
		}
		if err := page(raw); err != nil {
			return err
		}
		url = ""
		if m := nextLink.FindStringSubmatch(link); m != nil {
			url = m[1]
		}
	}
	return nil
}

// Account is the org or user that installed the app.
type Account struct {
	Login string `json:"login"`
	Type  string `json:"type"`
}

// Installation is one installation of the app, normally one per org.
type Installation struct {
	ID          int64   `json:"id"`
	Account     Account `json:"account"`
	SuspendedAt *string `json:"suspended_at"`
}

// Installations lists all installations of the app.
func (a *App) Installations(ctx context.Context) ([]Installation, error) {
	jwt, err := a.JWT()
	if err != nil {
		return nil, err
	}
	var out []Installation
	err = a.paginate(ctx, "/app/installations?per_page=100", "Bearer "+jwt, func(data json.RawMessage) error {
		var page []Installation
		if err := json.Unmarshal(data, &page); err != nil {
			return err
		}
		out = append(out, page...)
		return nil
	})
	return out, err
}

// Installation returns one installation.
func (a *App) Installation(ctx context.Context, id int64) (*Installation, error) {
	jwt, err := a.JWT()
	if err != nil {
		return nil, err
	}
	var inst Installation
	if _, err := a.do(ctx, http.MethodGet, fmt.Sprintf("/app/installations/%d", id), "Bearer "+jwt, nil, &inst); err != nil {
		return nil, err
	}
	return &inst, nil
}

// Token returns an installation access token. It reuses a cached token
// until 5 minutes before it expires.
func (a *App) Token(ctx context.Context, installationID int64) (string, error) {
	a.mu.Lock()
	t, ok := a.tokens[installationID]
	a.mu.Unlock()
	if ok && a.Now().Before(t.expires.Add(-5*time.Minute)) {
		return t.value, nil
	}
	jwt, err := a.JWT()
	if err != nil {
		return "", err
	}
	var resp struct {
		Token     string    `json:"token"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	path := fmt.Sprintf("/app/installations/%d/access_tokens", installationID)
	if _, err := a.do(ctx, http.MethodPost, path, "Bearer "+jwt, nil, &resp); err != nil {
		return "", err
	}
	a.mu.Lock()
	a.tokens[installationID] = token{value: resp.Token, expires: resp.ExpiresAt}
	a.mu.Unlock()
	return resp.Token, nil
}

// Repository is the subset of the GitHub repository object that the
// scanner uses.
type Repository struct {
	ID            int64   `json:"id"`
	Name          string  `json:"name"`
	FullName      string  `json:"full_name"`
	Owner         Account `json:"owner"`
	Private       bool    `json:"private"`
	Archived      bool    `json:"archived"`
	Disabled      bool    `json:"disabled"`
	HasWiki       bool    `json:"has_wiki"`
	DefaultBranch string  `json:"default_branch"`
}

// Repositories lists the repositories that an installation can see.
func (a *App) Repositories(ctx context.Context, installationID int64) ([]Repository, error) {
	tok, err := a.Token(ctx, installationID)
	if err != nil {
		return nil, err
	}
	var out []Repository
	err = a.paginate(ctx, "/installation/repositories?per_page=100", "token "+tok, func(data json.RawMessage) error {
		var page struct {
			Repositories []Repository `json:"repositories"`
		}
		if err := json.Unmarshal(data, &page); err != nil {
			return err
		}
		out = append(out, page.Repositories...)
		return nil
	})
	return out, err
}

// Repository returns one repository by its full name, as the installation
// sees it.
func (a *App) Repository(ctx context.Context, installationID int64, fullName string) (*Repository, error) {
	tok, err := a.Token(ctx, installationID)
	if err != nil {
		return nil, err
	}
	var r Repository
	if _, err := a.do(ctx, http.MethodGet, "/repos/"+fullName, "token "+tok, nil, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// Annotation marks one line in a check run.
type Annotation struct {
	Path            string `json:"path"`
	StartLine       int    `json:"start_line"`
	EndLine         int    `json:"end_line"`
	AnnotationLevel string `json:"annotation_level"`
	Title           string `json:"title,omitempty"`
	Message         string `json:"message"`
}

// CheckOutput is the output section of a check run.
type CheckOutput struct {
	Title       string       `json:"title"`
	Summary     string       `json:"summary"`
	Annotations []Annotation `json:"annotations,omitempty"`
}

// CheckRun is the body of a check run request.
type CheckRun struct {
	Name       string       `json:"name,omitempty"`
	HeadSHA    string       `json:"head_sha,omitempty"`
	Status     string       `json:"status,omitempty"`
	Conclusion string       `json:"conclusion,omitempty"`
	Output     *CheckOutput `json:"output,omitempty"`
}

// MaxAnnotations is the API limit of annotations per request.
const MaxAnnotations = 50

// CreateCheckRun creates a check run and returns its ID.
func (a *App) CreateCheckRun(ctx context.Context, installationID int64, fullName string, run CheckRun) (int64, error) {
	tok, err := a.Token(ctx, installationID)
	if err != nil {
		return 0, err
	}
	var resp struct {
		ID int64 `json:"id"`
	}
	_, err = a.do(ctx, http.MethodPost, "/repos/"+fullName+"/check-runs", "token "+tok, run, &resp)
	return resp.ID, err
}

// UpdateCheckRun updates a check run. Annotations add to the annotations
// of earlier updates.
func (a *App) UpdateCheckRun(ctx context.Context, installationID int64, fullName string, id int64, run CheckRun) error {
	tok, err := a.Token(ctx, installationID)
	if err != nil {
		return err
	}
	_, err = a.do(ctx, http.MethodPatch, fmt.Sprintf("/repos/%s/check-runs/%d", fullName, id), "token "+tok, run, nil)
	return err
}
