// Package webhook receives GitHub webhooks, queues jobs and runs them.
package webhook

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"terces/internal/githubapp"
	"terces/internal/pipeline"
)

// Job kinds.
const (
	KindSyncInstallation = "sync_installation"
	KindScanRepo         = "scan_repo"
	KindScanPR           = "scan_pr"
	KindRepoUpdate       = "repo_update"
	KindReconcile        = "reconcile"
	KindDigest           = "digest"
)

// maxBody is the largest webhook body that GitHub sends, plus a margin.
const maxBody = 26 << 20

// Queue adds jobs.
type Queue interface {
	Enqueue(ctx context.Context, kind, dedupeKey string, payload any) (bool, error)
}

// Handler verifies and routes GitHub webhooks. It only queues jobs, so it
// answers fast.
type Handler struct {
	Secret []byte
	Queue  Queue
	Log    *slog.Logger
}

// VerifySignature checks the X-Hub-Signature-256 header against the body.
func VerifySignature(secret, body []byte, header string) bool {
	sig, ok := strings.CutPrefix(header, "sha256=")
	if !ok || len(secret) == 0 {
		return false
	}
	got, err := hex.DecodeString(sig)
	if err != nil {
		return false
	}
	m := hmac.New(sha256.New, secret)
	m.Write(body)
	return hmac.Equal(got, m.Sum(nil))
}

// RepoJob is the payload of scan and update jobs.
type RepoJob struct {
	Action         string                `json:"action,omitempty"`
	InstallationID int64                 `json:"installation_id"`
	Repo           githubapp.Repository  `json:"repo"`
	PR             *pipeline.PullRequest `json:"pr,omitempty"`
}

// InstallationJob is the payload of sync jobs.
type InstallationJob struct {
	InstallationID int64 `json:"installation_id"`
}

type event struct {
	Action       string `json:"action"`
	Installation *struct {
		ID      int64             `json:"id"`
		Account githubapp.Account `json:"account"`
	} `json:"installation"`
	Repository *githubapp.Repository `json:"repository"`
	// push
	Ref     string `json:"ref"`
	After   string `json:"after"`
	Deleted bool   `json:"deleted"`
	// pull_request
	PullRequest *struct {
		Number int `json:"number"`
		Head   struct {
			SHA string `json:"sha"`
		} `json:"head"`
		Base struct {
			SHA string `json:"sha"`
			Ref string `json:"ref"`
		} `json:"base"`
	} `json:"pull_request"`
	Changes *struct {
		Base json.RawMessage `json:"base"`
	} `json:"changes"`
	// installation_repositories
	RepositoriesAdded   []githubapp.Repository `json:"repositories_added"`
	RepositoriesRemoved []githubapp.Repository `json:"repositories_removed"`
}

func (h *Handler) log() *slog.Logger {
	if h.Log != nil {
		return h.Log
	}
	return slog.Default()
}

// ServeHTTP handles one webhook delivery.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBody+1))
	if err != nil || len(body) > maxBody {
		http.Error(w, "body too large or unreadable", http.StatusRequestEntityTooLarge)
		return
	}
	if !VerifySignature(h.Secret, body, r.Header.Get("X-Hub-Signature-256")) {
		h.log().Warn("webhook signature mismatch", "delivery", r.Header.Get("X-GitHub-Delivery"), "remote", r.RemoteAddr)
		http.Error(w, "signature mismatch", http.StatusUnauthorized)
		return
	}
	name := r.Header.Get("X-GitHub-Event")
	delivery := r.Header.Get("X-GitHub-Delivery")
	if name == "ping" {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "pong")
		return
	}
	var ev event
	if err := json.Unmarshal(body, &ev); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	n, err := h.route(r.Context(), name, &ev)
	if err != nil {
		h.log().Error("queue webhook job", "event", name, "delivery", delivery, "err", err)
		http.Error(w, "queue error", http.StatusInternalServerError)
		return
	}
	h.log().Info("webhook", "event", name, "action", ev.Action, "delivery", delivery, "jobs", n)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	fmt.Fprintf(w, "{\"queued\":%d}\n", n)
}

// route turns one event into jobs. It returns the number of new jobs.
func (h *Handler) route(ctx context.Context, name string, ev *event) (int, error) {
	inst := int64(0)
	if ev.Installation != nil {
		inst = ev.Installation.ID
	}
	n := 0
	add := func(kind, key string, payload any) error {
		ok, err := h.Queue.Enqueue(ctx, kind, key, payload)
		if ok {
			n++
		}
		return err
	}
	repoKey := func(id int64) string { return strconv.FormatInt(id, 10) }

	switch name {
	case "installation":
		switch ev.Action {
		case "created", "deleted", "unsuspend", "new_permissions_accepted":
			return n, add(KindSyncInstallation, repoKey(inst), InstallationJob{InstallationID: inst})
		}
	case "installation_repositories":
		for _, repo := range ev.RepositoriesAdded {
			if repo.FullName != "" {
				repo.Owner.Login, repo.Name, _ = strings.Cut(repo.FullName, "/")
			}
			if err := add(KindScanRepo, repoKey(repo.ID), RepoJob{InstallationID: inst, Repo: repo}); err != nil {
				return n, err
			}
		}
		for _, repo := range ev.RepositoriesRemoved {
			if err := add(KindRepoUpdate, "", RepoJob{Action: "removed", InstallationID: inst, Repo: repo}); err != nil {
				return n, err
			}
		}
	case "push":
		if ev.Repository == nil || ev.Deleted {
			return n, nil
		}
		return n, add(KindScanRepo, repoKey(ev.Repository.ID), RepoJob{InstallationID: inst, Repo: *ev.Repository})
	case "pull_request":
		if ev.Repository == nil || ev.PullRequest == nil {
			return n, nil
		}
		switch ev.Action {
		case "opened", "synchronize", "reopened":
		case "edited":
			if ev.Changes == nil || len(ev.Changes.Base) == 0 {
				return n, nil
			}
		default:
			return n, nil
		}
		pr := &pipeline.PullRequest{
			Number:  ev.PullRequest.Number,
			BaseSHA: ev.PullRequest.Base.SHA,
			BaseRef: ev.PullRequest.Base.Ref,
			HeadSHA: ev.PullRequest.Head.SHA,
		}
		key := fmt.Sprintf("%d:%d:%s:%s", ev.Repository.ID, pr.Number, pr.BaseSHA, pr.HeadSHA)
		return n, add(KindScanPR, key, RepoJob{InstallationID: inst, Repo: *ev.Repository, PR: pr})
	case "repository":
		if ev.Repository == nil {
			return n, nil
		}
		switch ev.Action {
		case "created", "deleted", "archived", "unarchived", "renamed", "transferred", "edited", "publicized", "privatized":
			return n, add(KindRepoUpdate, "", RepoJob{Action: ev.Action, InstallationID: inst, Repo: *ev.Repository})
		}
	}
	return n, nil
}
