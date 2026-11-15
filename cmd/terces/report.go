package main

import (
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"terces/internal/render"
	"terces/internal/store"
)

func newReportCmd(a *app) *cobra.Command {
	var asCSV, toSlack bool
	var org string
	out := &scanOutput{}
	cmd := &cobra.Command{
		Use:   "report",
		Short: "Report the open findings by org, repository, rule and age",
		Long: "Report the open findings by org, repository, rule and age. A secret in\n" +
			"more than one repository counts one time in each repository.\n" +
			"With --slack, the command posts the weekly digest to Slack.",
		Example: "  terces report\n" +
			"  terces report --format csv > open-findings.csv\n" +
			"  terces report --format markdown > open-findings.md\n" +
			"  terces report --slack",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if out.asJSON && asCSV {
				return errors.New("use --json or --csv, not both")
			}
			if asCSV {
				out.format = render.CSV
			}
			format, err := out.resolve(render.Text, render.JSON, render.CSV, render.Markdown, render.HTML)
			if err != nil {
				return err
			}
			db, err := a.store(cmd.Context())
			if err != nil {
				return err
			}
			if toSlack {
				sl, err := a.slack()
				if err != nil {
					return err
				}
				if sl == nil {
					return fmt.Errorf("no Slack webhook: set %sSLACK_WEBHOOK_URL or --slack-webhook-url-file", envPrefix)
				}
				d, err := db.Digest(cmd.Context())
				if err != nil {
					return err
				}
				if err := sl.Digest(cmd.Context(), d); err != nil {
					return err
				}
				fmt.Fprintln(cmd.ErrOrStderr(), "posted the digest to Slack")
				return nil
			}
			rows, err := db.Report(cmd.Context(), org)
			if err != nil {
				return err
			}
			switch format {
			case render.JSON:
				if rows == nil {
					rows = []store.ReportRow{}
				}
				return writeJSON(cmd.OutOrStdout(), rows)
			case render.Markdown:
				var b strings.Builder
				total := 0
				var cells [][]string
				for _, r := range rows {
					total += r.Open
					cells = append(cells, []string{render.Code(r.Org), render.Code(r.Repo), render.Code(r.RuleID), r.Severity,
						strconv.Itoa(r.Open), r.OldestSeen.Format("2006-01-02"), strconv.Itoa(r.MaxAgeDays)})
				}
				fmt.Fprintf(&b, "## terces: %d open finding location%s\n\n", total, plural(total))
				if len(cells) > 0 {
					render.Table(&b, []string{"Org", "Repository", "Rule", "Severity", "Open", "Oldest", "Age in days"}, cells)
				}
				_, err := io.WriteString(cmd.OutOrStdout(), b.String())
				return err
			case render.HTML:
				r := &render.HTMLReport{
					Title: "terces report: open findings",
					Empty: "No open findings.",
					Columns: []render.Column{{Name: "Org", Kind: "code"}, {Name: "Repository", Kind: "code"}, {Name: "Rule", Kind: "code"},
						{Name: "Severity", Kind: "severity"}, {Name: "Open", Kind: "number"}, {Name: "Oldest", Kind: "text"}, {Name: "Age in days", Kind: "number"}},
				}
				total := 0
				bySev, byRepo := map[string]int{}, map[string]int{}
				for _, row := range rows {
					total += row.Open
					bySev[row.Severity] += row.Open
					byRepo[row.Org+"/"+row.Repo] += row.Open
					r.Rows = append(r.Rows, []string{row.Org, row.Repo, row.RuleID, row.Severity, strconv.Itoa(row.Open),
						row.OldestSeen.Format("2006-01-02"), strconv.Itoa(row.MaxAgeDays)})
				}
				r.Subtitle = fmt.Sprintf("%d open finding location%s in %d group%s. A secret in more than one repository counts one time in each repository.",
					total, plural(total), len(rows), plural(len(rows)))
				r.Cards = append(r.Cards, render.Card{Label: "open locations", Value: total})
				for _, sev := range []string{"critical", "high", "medium", "low"} {
					r.Cards = append(r.Cards, render.Card{Label: sev, Value: bySev[sev], Kind: sev})
				}
				r.Breakdowns = []render.Breakdown{{Title: "Top repositories", Rows: render.Top(byRepo)}}
				return render.WriteHTML(cmd.OutOrStdout(), r)
			case render.CSV:
				w := csv.NewWriter(cmd.OutOrStdout())
				_ = w.Write([]string{"org", "repo", "rule", "severity", "open", "oldest_first_seen_at", "max_age_days"})
				for _, r := range rows {
					_ = w.Write([]string{r.Org, r.Repo, r.RuleID, r.Severity, strconv.Itoa(r.Open),
						r.OldestSeen.UTC().Format("2006-01-02T15:04:05Z"), strconv.Itoa(r.MaxAgeDays)})
				}
				w.Flush()
				return w.Error()
			}
			t := newTable(cmd.OutOrStdout(), "ORG", "REPO", "RULE", "SEVERITY", "OPEN", "OLDEST", "AGE (DAYS)")
			total := 0
			for _, r := range rows {
				total += r.Open
				t.row(r.Org, r.Repo, r.RuleID, r.Severity, strconv.Itoa(r.Open), r.OldestSeen.Format("2006-01-02"), strconv.Itoa(r.MaxAgeDays))
			}
			if err := t.flush(); err != nil {
				return err
			}
			fmt.Fprintf(cmd.ErrOrStderr(), "%d open finding locations in %d groups\n", total, len(rows))
			return nil
		},
	}
	cmd.Flags().StringVar(&out.format, "format", render.Text, "output format: text, json, csv, markdown or html")
	cmd.Flags().BoolVar(&out.asJSON, "json", false, "write JSON. This is short for --format json")
	cmd.Flags().BoolVar(&asCSV, "csv", false, "write CSV. This is short for --format csv")
	cmd.Flags().BoolVar(&toSlack, "slack", false, "post the weekly digest to Slack")
	cmd.Flags().StringVar(&org, "org", "", "only this org")
	return cmd
}
