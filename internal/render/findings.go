package render

import (
	"fmt"
	"io"
	"strconv"
	"strings"

	"terces/internal/fingerprint"
	"terces/internal/scanner"
)

// RepoFindings is the findings of one repository. Repo is empty for a scan
// of a directory, a range or a local clone.
type RepoFindings struct {
	Repo     string
	Findings []scanner.Finding
}

// FindingsMarkdown writes scan findings as a Markdown report: a summary,
// one table of findings, then the gaps and warnings of the scan.
func FindingsMarkdown(w io.Writer, groups []RepoFindings, st *scanner.Stats, opts ReportOptions) error {
	var b strings.Builder
	total, withRepo := 0, false
	for _, g := range groups {
		total += len(g.Findings)
		withRepo = withRepo || g.Repo != ""
	}
	title := "terces"
	if opts.Target != "" {
		title += " " + Code(opts.Target)
	}
	switch total {
	case 0:
		fmt.Fprintf(&b, "## %s: no findings\n\n", title)
	case 1:
		fmt.Fprintf(&b, "## %s: 1 finding\n\n", title)
	default:
		fmt.Fprintf(&b, "## %s: %d findings\n\n", title, total)
	}
	if total > 0 {
		b.WriteString("Each finding is a secret that can be live. Revoke it first, then remove it from the code.\n\n")
		SummaryMarkdown(&b, Summarize(groups, st))
	}
	if total > 0 && !opts.SummaryOnly {
		headers := []string{"Severity", "Rule", "Preview", "Location", "Commit", "Fingerprint"}
		if withRepo {
			headers = append([]string{"Repository"}, headers...)
		}
		var rows [][]string
		for _, g := range groups {
			scanner.SortFindings(g.Findings)
			for _, f := range g.Findings {
				loc := f.Path + ":" + strconv.Itoa(f.Line)
				if f.Decoded != "" {
					loc += " (" + f.Decoded + ")"
				}
				commit := f.CommitSHA
				if len(commit) > 12 {
					commit = commit[:12]
				}
				row := []string{f.Severity.String(), Code(f.RuleID), Code(f.Preview), Code(loc), Code(commit), Code(fingerprint.Short(f.Fingerprint))}
				if withRepo {
					row = append([]string{Code(g.Repo)}, row...)
				}
				rows = append(rows, row)
			}
		}
		Table(&b, headers, rows)
		b.WriteString("\n")
	}
	if st != nil {
		writeGaps(&b, st)
		for _, warn := range st.Warnings {
			b.WriteString("> Warning: " + Code(warn) + "\n\n")
		}
		b.WriteString("Scan: " + st.Summary() + "\n")
	}
	_, err := io.WriteString(w, b.String())
	return err
}

func writeGaps(b *strings.Builder, st *scanner.Stats) {
	if len(st.Gaps) == 0 {
		return
	}
	n := st.SkippedSize + st.Capped
	fmt.Fprintf(b, "### %d blob%s not scanned in full\n\n", n, plural(n))
	b.WriteString("A blob above the size limit gets no scan. In a blob at the match limit, a rule found more secrets than the report shows.\n\n")
	var rows [][]string
	for _, g := range st.Gaps {
		size := ""
		if g.Size > 0 {
			size = strconv.FormatInt(g.Size, 10)
		}
		rows = append(rows, []string{Code(g.Path), Code(g.Blob), g.Reason, size})
	}
	Table(b, []string{"Path", "Blob", "Reason", "Size"}, rows)
	if n > len(st.Gaps) {
		fmt.Fprintf(b, "\nThe table shows the first %d.\n", len(st.Gaps))
	}
	b.WriteString("\n")
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}
