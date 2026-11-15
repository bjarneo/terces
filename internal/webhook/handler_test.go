package webhook

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

type fakeQueue struct {
	jobs []struct {
		kind, key string
		payload   []byte
	}
}

func (q *fakeQueue) Enqueue(_ context.Context, kind, key string, payload any) (bool, error) {
	data, _ := json.Marshal(payload)
	q.jobs = append(q.jobs, struct {
		kind, key string
		payload   []byte
	}{kind, key, data})
	return true, nil
}

func sign(secret, body []byte) string {
	m := hmac.New(sha256.New, secret)
	m.Write(body)
	return "sha256=" + hex.EncodeToString(m.Sum(nil))
}

func deliver(h http.Handler, event string, body []byte, sig string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/webhook", bytes.NewReader(body))
	req.Header.Set("X-GitHub-Event", event)
	req.Header.Set("X-GitHub-Delivery", "d-1")
	req.Header.Set("X-Hub-Signature-256", sig)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestVerifySignature(t *testing.T) {
	secret := []byte("s3cret")
	body := []byte(`{"a":1}`)
	if !VerifySignature(secret, body, sign(secret, body)) {
		t.Error("valid signature rejected")
	}
	for _, bad := range []string{"", "sha256=", "sha1=abc", sign([]byte("other"), body), sign(secret, []byte(`{"a":2}`))} {
		if VerifySignature(secret, body, bad) {
			t.Errorf("invalid signature %q accepted", bad)
		}
	}
	if VerifySignature(nil, body, sign(nil, body)) {
		t.Error("an empty secret must reject all deliveries")
	}
}

func TestHandlerRoutesEvents(t *testing.T) {
	secret := []byte("s3cret")
	q := &fakeQueue{}
	h := &Handler{Secret: secret, Queue: q}

	push := []byte(`{"ref":"refs/heads/main","after":"abc","installation":{"id":5},
		"repository":{"id":42,"name":"api","full_name":"acme/api","owner":{"login":"acme"}}}`)
	if rec := deliver(h, "push", push, sign(secret, push)); rec.Code != http.StatusAccepted {
		t.Fatalf("push: status %d", rec.Code)
	}
	if rec := deliver(h, "push", push, sign([]byte("wrong"), push)); rec.Code != http.StatusUnauthorized {
		t.Fatalf("bad signature: status %d", rec.Code)
	}
	pr := []byte(`{"action":"synchronize","installation":{"id":5},
		"repository":{"id":42,"name":"api","full_name":"acme/api","owner":{"login":"acme"}},
		"pull_request":{"number":9,"head":{"sha":"h1"},"base":{"sha":"b1","ref":"main"}}}`)
	deliver(h, "pull_request", pr, sign(secret, pr))
	closed := []byte(`{"action":"closed","repository":{"id":42},"pull_request":{"number":9}}`)
	deliver(h, "pull_request", closed, sign(secret, closed))
	added := []byte(`{"action":"added","installation":{"id":5},
		"repositories_added":[{"id":43,"name":"web","full_name":"acme/web"}],
		"repositories_removed":[{"id":44,"name":"old","full_name":"acme/old"}]}`)
	deliver(h, "installation_repositories", added, sign(secret, added))
	ping := []byte(`{}`)
	if rec := deliver(h, "ping", ping, sign(secret, ping)); rec.Code != http.StatusOK {
		t.Fatalf("ping: status %d", rec.Code)
	}

	want := []string{KindScanRepo, KindScanPR, KindScanRepo, KindRepoUpdate}
	if len(q.jobs) != len(want) {
		t.Fatalf("got %d jobs, want %d", len(q.jobs), len(want))
	}
	for i, k := range want {
		if q.jobs[i].kind != k {
			t.Errorf("job %d: kind %s, want %s", i, q.jobs[i].kind, k)
		}
	}
	var p RepoJob
	if err := json.Unmarshal(q.jobs[1].payload, &p); err != nil {
		t.Fatal(err)
	}
	if p.PR == nil || p.PR.HeadSHA != "h1" || p.PR.BaseRef != "main" || p.InstallationID != 5 {
		t.Errorf("pull request payload: %+v", p)
	}
	if err := json.Unmarshal(q.jobs[2].payload, &p); err != nil || p.Repo.Owner.Login != "acme" || p.Repo.Name != "web" {
		t.Errorf("added repository payload: %+v %v", p.Repo, err)
	}
}
