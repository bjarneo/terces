package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"terces/internal/fingerprint"
	"terces/internal/rules"
	"terces/internal/scanner"
	"terces/internal/store"
)

// MaxListed is the number of findings that one alert lists in full.
const MaxListed = 10

// Slack posts messages to an incoming webhook.
type Slack struct {
	WebhookURL string
	GitHubURL  string
	HTTP       *http.Client
	// MinSeverity is the lowest severity that an alert includes.
	MinSeverity rules.Severity
}

// NewSlack returns a Slack client that alerts on high and critical findings.
func NewSlack(webhookURL, githubURL string) *Slack {
	return &Slack{
		WebhookURL:  webhookURL,
		GitHubURL:   strings.TrimSuffix(githubURL, "/"),
		HTTP:        &http.Client{Timeout: 20 * time.Second},
		MinSeverity: rules.SeverityHigh,
	}
}

// escape escapes the characters that Slack mrkdwn uses for links.
func escape(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(s)
}

func (s *Slack) post(ctx context.Context, text string) error {
	body, err := json.Marshal(map[string]any{"text": text, "unfurl_links": false, "unfurl_media": false})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.WebhookURL, bytes.NewReader(body))
	if err != nil {
		// The parse error contains the URL, which is a secret.
		return fmt.Errorf("post to Slack: the webhook URL is not valid")
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.HTTP.Do(req)
	if err != nil {
		// The error text can contain the webhook URL, which is a secret.
		return fmt.Errorf("post to Slack: request failed")
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode >= 300 {
		return fmt.Errorf("post to Slack: %d %s", resp.StatusCode, strings.TrimSpace(string(data)))
	}
	return nil
}

// RepoRef names the repository of an alert.
type RepoRef struct {
	Org, Name string
}

// NewFindings posts one message for the new secrets of one repository
// scan. owners can be nil. It lists MaxListed findings or fewer and
// counts the rest. It posts nothing when no finding reaches MinSeverity.
func (s *Slack) NewFindings(ctx context.Context, repo RepoRef, findings []scanner.Finding, owners *Codeowners) error {
	var list []scanner.Finding
	for _, f := range findings {
		if f.Severity >= s.MinSeverity {
			list = append(list, f)
		}
	}
	if len(list) == 0 {
		return nil
	}
	scanner.SortFindings(list)
	full := repo.Org + "/" + repo.Name
	var b strings.Builder
	fmt.Fprintf(&b, ":rotating_light: *%d new secret%s in %s*\n", len(list), plural(len(list)), escape(full))
	b.WriteString("Treat each secret as compromised. Revoke it, then resolve the finding with `terces findings resolve`.\n")
	for i, f := range list {
		if i == MaxListed {
			fmt.Fprintf(&b, "…and %d more. Run `terces findings list --repo %s`.\n", len(list)-MaxListed, escape(full))
			break
		}
		loc := fmt.Sprintf("%s:%d", f.Path, f.Line)
		if link := s.commitLink(full, f); link != "" {
			loc = fmt.Sprintf("<%s|%s>", link, escape(loc))
		} else {
			loc = escape(loc)
		}
		fmt.Fprintf(&b, "• *%s* `%s` %s `%s`", f.Severity, escape(f.RuleID), loc, escape(f.Preview))
		who := ""
		if o := owners.Owners(strings.TrimPrefix(f.Path, "wiki:")); len(o) > 0 && !strings.HasPrefix(f.Path, "wiki:") {
			who = "owners " + strings.Join(o, " ")
		} else if f.AuthorEmail != "" {
			who = "author " + f.AuthorEmail
		}
		if who != "" {
			fmt.Fprintf(&b, ", %s", escape(who))
		}
		fmt.Fprintf(&b, ", fingerprint `%s`\n", fingerprint.Short(f.Fingerprint))
	}
	return s.post(ctx, b.String())
}

func (s *Slack) commitLink(full string, f scanner.Finding) string {
	if s.GitHubURL == "" || f.CommitSHA == "" {
		return ""
	}
	if strings.HasPrefix(f.Path, "wiki:") {
		return fmt.Sprintf("%s/%s/wiki", s.GitHubURL, full)
	}
	return fmt.Sprintf("%s/%s/commit/%s", s.GitHubURL, full, f.CommitSHA)
}

// Digest posts the weekly digest of open findings.
func (s *Slack) Digest(ctx context.Context, d *store.Digest) error {
	var b strings.Builder
	fmt.Fprintf(&b, ":broom: *terces weekly digest: %d open finding%s*\n", d.Open, plural(d.Open))
	if d.Open == 0 {
		b.WriteString("No open findings.\n")
		return s.post(ctx, b.String())
	}
	b.WriteString("*By age:* ")
	var parts []string
	for _, a := range d.ByAge {
		parts = append(parts, fmt.Sprintf("%s: %d", a.Label, a.Count))
	}
	b.WriteString(strings.Join(parts, ", ") + "\n")

	b.WriteString("*By severity:* ")
	parts = parts[:0]
	for _, sev := range []string{"critical", "high", "medium", "low"} {
		if n := d.BySeverity[sev]; n > 0 {
			parts = append(parts, fmt.Sprintf("%s: %d", sev, n))
		}
	}
	b.WriteString(strings.Join(parts, ", ") + "\n")

	orgs := make([]string, 0, len(d.ByOrg))
	for o := range d.ByOrg {
		orgs = append(orgs, o)
	}
	sort.Slice(orgs, func(i, j int) bool { return d.ByOrg[orgs[i]] > d.ByOrg[orgs[j]] })
	b.WriteString("*By org:* ")
	parts = parts[:0]
	for _, o := range orgs {
		parts = append(parts, fmt.Sprintf("%s: %d", escape(o), d.ByOrg[o]))
	}
	b.WriteString(strings.Join(parts, ", ") + "\n")

	if len(d.Oldest) > 0 {
		b.WriteString("*Oldest open critical and high findings:*\n")
		for _, x := range d.Oldest {
			age := int(d.GeneratedAt.Sub(x.FirstSeenAt).Hours() / 24)
			fmt.Fprintf(&b, "• %d days, *%s* `%s` `%s` in %s, fingerprint `%s`\n",
				age, x.Severity, escape(x.RuleID), escape(x.Preview), escape(strings.Join(x.Repos, ", ")), x.FPHex[:12])
		}
	}
	return s.post(ctx, b.String())
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}
