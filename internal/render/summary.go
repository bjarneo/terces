package render

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"terces/internal/rules"
	"terces/internal/safetext"
	"terces/internal/scanner"
)

// Count is one row of a breakdown.
type Count struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

// Summary counts the findings of a scan.
type Summary struct {
	Findings int `json:"findings"`
	// Secrets counts different secrets. One secret can have many
	// locations.
	Secrets    int            `json:"secrets"`
	BySeverity map[string]int `json:"by_severity"`
	ByRule     []Count        `json:"by_rule"`
	ByRepo     []Count        `json:"by_repo,omitempty"`
	Gaps       int            `json:"gaps"`
	Stats      *scanner.Stats `json:"-"`
}

// maxBreakdown is the number of rows in each breakdown.
const maxBreakdown = 10

// Summarize counts the findings of groups.
func Summarize(groups []RepoFindings, st *scanner.Stats) *Summary {
	s := &Summary{BySeverity: map[string]int{}, Stats: st}
	fps := map[string]bool{}
	byRule, byRepo := map[string]int{}, map[string]int{}
	for _, g := range groups {
		for _, f := range g.Findings {
			s.Findings++
			fps[string(f.Fingerprint)] = true
			s.BySeverity[f.Severity.String()]++
			byRule[f.RuleID]++
			if g.Repo != "" {
				byRepo[g.Repo]++
			}
		}
	}
	s.Secrets = len(fps)
	s.ByRule = top(byRule)
	s.ByRepo = top(byRepo)
	if st != nil {
		s.Gaps = st.SkippedSize + st.Capped
	}
	return s
}

// Top returns the counts of m, largest first, at most 10 of them.
func Top(m map[string]int) []Count { return top(m) }

func top(m map[string]int) []Count {
	out := make([]Count, 0, len(m))
	for k, v := range m {
		out = append(out, Count{k, v})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Name < out[j].Name
	})
	if len(out) > maxBreakdown {
		out = out[:maxBreakdown]
	}
	return out
}

// severities lists the severities from the most severe.
var severities = []string{
	rules.SeverityCritical.String(), rules.SeverityHigh.String(),
	rules.SeverityMedium.String(), rules.SeverityLow.String(),
}

func (s *Summary) severityLine() string {
	var parts []string
	for _, sev := range severities {
		parts = append(parts, fmt.Sprintf("%d %s", s.BySeverity[sev], sev))
	}
	return strings.Join(parts, ", ")
}

// SummaryText writes the summary as plain text.
func SummaryText(w io.Writer, s *Summary) error {
	var b strings.Builder
	fmt.Fprintf(&b, "Summary: %d finding%s, %d different secret%s.\n", s.Findings, plural(s.Findings), s.Secrets, plural(s.Secrets))
	fmt.Fprintf(&b, "  Severity: %s.\n", s.severityLine())
	writeTextBreakdown(&b, "Top rules", s.ByRule)
	writeTextBreakdown(&b, "Top repositories", s.ByRepo)
	if s.Gaps > 0 {
		fmt.Fprintf(&b, "  Not scanned in full: %d blob%s.\n", s.Gaps, plural(s.Gaps))
	}
	_, err := io.WriteString(w, b.String())
	return err
}

func writeTextBreakdown(b *strings.Builder, title string, cs []Count) {
	if len(cs) == 0 {
		return
	}
	fmt.Fprintf(b, "  %s:\n", title)
	width := 0
	for _, c := range cs {
		width = max(width, len(safetext.Display(c.Name)))
	}
	for _, c := range cs {
		fmt.Fprintf(b, "    %-*s  %d\n", width, safetext.Display(c.Name), c.Count)
	}
}

// SummaryMarkdown writes the summary as Markdown.
func SummaryMarkdown(b *strings.Builder, s *Summary) {
	fmt.Fprintf(b, "**%d finding%s, %d different secret%s.** Severity: %s.\n\n", s.Findings, plural(s.Findings), s.Secrets, plural(s.Secrets), s.severityLine())
	if len(s.ByRule) > 0 {
		var rows [][]string
		for _, c := range s.ByRule {
			rows = append(rows, []string{Code(c.Name), fmt.Sprint(c.Count)})
		}
		Table(b, []string{"Top rules", "Findings"}, rows)
		b.WriteString("\n")
	}
	if len(s.ByRepo) > 0 {
		var rows [][]string
		for _, c := range s.ByRepo {
			rows = append(rows, []string{Code(c.Name), fmt.Sprint(c.Count)})
		}
		Table(b, []string{"Top repositories", "Findings"}, rows)
		b.WriteString("\n")
	}
	if s.Gaps > 0 {
		fmt.Fprintf(b, "Not scanned in full: %d blob%s. See the list below.\n\n", s.Gaps, plural(s.Gaps))
	}
}
