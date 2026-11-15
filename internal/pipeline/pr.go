package pipeline

import (
	"context"
	"fmt"
	"strings"

	"terces/internal/fingerprint"
	"terces/internal/githubapp"
	"terces/internal/scanner"
	"terces/internal/store"
)

// PullRequest identifies the commits of one pull request event.
type PullRequest struct {
	Number  int    `json:"number"`
	BaseSHA string `json:"base_sha"`
	BaseRef string `json:"base_ref"`
	HeadSHA string `json:"head_sha"`
}

// PRResult is the outcome of a pull request check.
type PRResult struct {
	Findings   []scanner.Finding
	Conclusion string
}

// CheckPullRequest scans the commits of a pull request and reports the
// result as a check run. A new open secret makes the check fail. When the
// scan fails, the check also fails, so that a required check never
// passes without a scan.
func (sw *Pipeline) CheckPullRequest(ctx context.Context, r *store.Repo, pr PullRequest) (*PRResult, error) {
	if sw.GitHub == nil {
		return nil, fmt.Errorf("pull request checks need the GitHub App configuration")
	}
	runID, err := sw.GitHub.CreateCheckRun(ctx, r.InstallationID, r.FullName(), githubapp.CheckRun{
		Name:    CheckName,
		HeadSHA: pr.HeadSHA,
		Status:  "in_progress",
		Output:  &githubapp.CheckOutput{Title: "Scan in progress", Summary: "terces scans the new commits of this pull request."},
	})
	if err != nil {
		return nil, fmt.Errorf("create check run: %w", err)
	}
	res, scanErr := sw.scanPullRequest(ctx, r, pr)
	if scanErr != nil {
		_ = sw.GitHub.UpdateCheckRun(context.WithoutCancel(ctx), r.InstallationID, r.FullName(), runID, githubapp.CheckRun{
			Status:     "completed",
			Conclusion: "failure",
			Output: &githubapp.CheckOutput{
				Title:   "Scan error",
				Summary: "The secret scan failed. terces retries the scan. Push a new commit to start a new scan.",
			},
		})
		return nil, scanErr
	}
	if err := sw.reportCheck(ctx, r, runID, res); err != nil {
		return nil, fmt.Errorf("update check run: %w", err)
	}

	// Store the findings and send alerts. The pull request refs are part
	// of the mirror, so the incremental repository scan covers them.
	if _, err := sw.ScanRepo(ctx, r.ID, false); err != nil {
		sw.log().Error("repository scan after pull request check failed", "repo", r.FullName(), "err", err)
	}
	return res, nil
}

func (sw *Pipeline) scanPullRequest(ctx context.Context, r *store.Repo, pr PullRequest) (*PRResult, error) {
	if err := sw.FetchRepo(ctx, r); err != nil {
		return nil, fmt.Errorf("fetch: %w", err)
	}
	unlock := sw.locks.lock(r.ID)
	defer unlock()

	g := sw.Mirrors.Git(sw.Mirrors.RepoPath(r.ID))
	base := pr.BaseSHA
	if _, err := g.Run(ctx, "cat-file", "-e", base+"^{commit}"); err != nil && pr.BaseRef != "" {
		// A force push to the base branch can remove the old base commit.
		base = "refs/heads/" + pr.BaseRef
	}
	findings, _, err := sw.Scanner.ScanRange(ctx, g, base, pr.HeadSHA, scanner.RangeOptions{Cache: sw.Store})
	if err != nil {
		return nil, err
	}

	// A fingerprint that a person marked as revoked, false positive or
	// ignored does not fail the check.
	if len(findings) > 0 {
		fps := make([][]byte, len(findings))
		for i := range findings {
			fps[i] = findings[i].Fingerprint
		}
		states, err := sw.Store.SecretStates(ctx, fps)
		if err != nil {
			return nil, err
		}
		kept := findings[:0]
		for _, f := range findings {
			if st, ok := states[string(f.Fingerprint)]; ok && st != store.StateOpen {
				continue
			}
			kept = append(kept, f)
		}
		findings = kept
	}
	scanner.SortFindings(findings)
	res := &PRResult{Findings: findings, Conclusion: "success"}
	if len(findings) > 0 {
		res.Conclusion = "failure"
	}
	return res, nil
}

func (sw *Pipeline) reportCheck(ctx context.Context, r *store.Repo, runID int64, res *PRResult) error {
	out := &githubapp.CheckOutput{Title: "No new secrets", Summary: "terces found no new secrets in this pull request."}
	var anns []githubapp.Annotation
	if len(res.Findings) > 0 {
		out.Title = fmt.Sprintf("%d new secret%s", len(res.Findings), plural(len(res.Findings)))
		var b strings.Builder
		b.WriteString("terces found new secrets in the commits of this pull request.\n\n")
		b.WriteString("Treat each secret as compromised, even after you remove it from the branch. ")
		b.WriteString("The commits stay readable on GitHub. Revoke the secret first, then remove it.\n\n")
		b.WriteString("| Severity | Rule | Location | Preview | Fingerprint |\n|---|---|---|---|---|\n")
		for _, f := range res.Findings {
			fmt.Fprintf(&b, "| %s | `%s` | `%s:%d` | `%s` | `%s` |\n",
				f.Severity, f.RuleID, strings.ReplaceAll(f.Path, "|", "\\|"), f.Line, f.Preview, fingerprint.Short(f.Fingerprint))
			line := f.Line
			if line < 1 {
				line = 1
			}
			anns = append(anns, githubapp.Annotation{
				Path:            f.Path,
				StartLine:       line,
				EndLine:         line,
				AnnotationLevel: "failure",
				Title:           "Secret: " + f.RuleID,
				Message:         fmt.Sprintf("%s secret (%s), preview %s, fingerprint %s. Revoke it, then remove it.", f.Severity, f.RuleID, f.Preview, fingerprint.Short(f.Fingerprint)),
			})
		}
		out.Summary = b.String()
		if len(out.Summary) > 60000 {
			out.Summary = out.Summary[:60000] + "\n\nThe list is too long. Run `terces findings list` for all findings."
		}
	}

	first := anns
	if len(first) > githubapp.MaxAnnotations {
		first = first[:githubapp.MaxAnnotations]
	}
	out.Annotations = first
	if err := sw.GitHub.UpdateCheckRun(ctx, r.InstallationID, r.FullName(), runID, githubapp.CheckRun{
		Status: "completed", Conclusion: res.Conclusion, Output: out,
	}); err != nil {
		return err
	}
	for i := githubapp.MaxAnnotations; i < len(anns); i += githubapp.MaxAnnotations {
		end := i + githubapp.MaxAnnotations
		if end > len(anns) {
			end = len(anns)
		}
		more := *out
		more.Annotations = anns[i:end]
		if err := sw.GitHub.UpdateCheckRun(ctx, r.InstallationID, r.FullName(), runID, githubapp.CheckRun{Output: &more}); err != nil {
			return err
		}
	}
	return nil
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}
