package main

import (
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"terces/internal/render"
	"terces/internal/rules"
	"terces/internal/safetext"
	"terces/internal/store"
)

func newFindingsCmd(a *app) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "findings",
		Short: "List, show and resolve stored findings",
	}
	cmd.AddCommand(newFindingsListCmd(a), newFindingsShowCmd(a), newFindingsResolveCmd(a))
	return cmd
}

func newFindingsListCmd(a *app) *cobra.Command {
	var f store.ListFilter
	var severity string
	out := &scanOutput{}
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List stored findings. Each row is one secret with all its locations",
		Example: "  terces findings list --state open --severity high\n" +
			"  terces findings list --org my-org --json",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			format, err := out.resolve(render.Text, render.JSON, render.Markdown, render.HTML)
			if err != nil {
				return err
			}
			if f.State != "" && !store.ValidState(f.State) {
				return fmt.Errorf("--state %q: use open, revoked, false_positive or ignored", f.State)
			}
			if severity != "" {
				sev, err := rules.ParseSeverity(severity)
				if err != nil {
					return err
				}
				f.MinSeverity = sev
			}
			db, err := a.store(cmd.Context())
			if err != nil {
				return err
			}
			// Ask for one more row, so that a cut list is visible.
			limit := f.Limit
			f.Limit = limit + 1
			list, err := db.ListSecrets(cmd.Context(), f)
			if err != nil {
				return err
			}
			truncated := len(list) > limit
			if truncated {
				list = list[:limit]
			}
			switch format {
			case render.JSON:
				if list == nil {
					list = []store.Secret{}
				}
				return writeJSON(cmd.OutOrStdout(), map[string]any{"findings": list, "truncated": truncated})
			case render.Markdown:
				var b strings.Builder
				fmt.Fprintf(&b, "## terces: %d finding%s\n\n", len(list), plural(len(list)))
				var rows [][]string
				for _, s := range list {
					rows = append(rows, []string{render.Code(s.FPHex[:12]), s.Severity, s.State, render.Code(s.RuleID),
						render.Code(s.Preview), fmt.Sprint(s.Locations), render.Code(repoList(s.Repos)), s.FirstSeenAt.Format("2006-01-02")})
				}
				if len(rows) > 0 {
					render.Table(&b, []string{"Fingerprint", "Severity", "State", "Rule", "Preview", "Locations", "Repositories", "First seen"}, rows)
				}
				if truncated {
					fmt.Fprintf(&b, "\nThe list shows the first %d findings. More findings match.\n", limit)
				}
				_, err := io.WriteString(cmd.OutOrStdout(), b.String())
				return err
			case render.HTML:
				r := &render.HTMLReport{
					Title:    "terces findings",
					Subtitle: fmt.Sprintf("%d finding%s. Each row is one secret with all its locations.", len(list), plural(len(list))),
					Empty:    "No findings match the filter.",
					Columns: []render.Column{{Name: "Fingerprint", Kind: "code"}, {Name: "Severity", Kind: "severity"}, {Name: "State", Kind: "text"},
						{Name: "Rule", Kind: "code"}, {Name: "Preview", Kind: "code"}, {Name: "Locations", Kind: "number"},
						{Name: "Repositories", Kind: "code"}, {Name: "First seen", Kind: "text"}},
				}
				bySev := map[string]int{}
				for _, s := range list {
					bySev[s.Severity]++
					r.Rows = append(r.Rows, []string{s.FPHex[:12], s.Severity, s.State, s.RuleID, s.Preview,
						fmt.Sprint(s.Locations), strings.Join(s.Repos, ", "), s.FirstSeenAt.Format("2006-01-02")})
				}
				r.Cards = append(r.Cards, render.Card{Label: "findings", Value: len(list)})
				for _, sev := range []string{"critical", "high", "medium", "low"} {
					r.Cards = append(r.Cards, render.Card{Label: sev, Value: bySev[sev], Kind: sev})
				}
				if truncated {
					r.Notices = append(r.Notices, fmt.Sprintf("The list shows the first %d findings. More findings match. Use --limit to show more.", limit))
				}
				return render.WriteHTML(cmd.OutOrStdout(), r)
			}
			t := newTable(cmd.OutOrStdout(), "FINGERPRINT", "SEVERITY", "STATE", "RULE", "PREVIEW", "LOCATIONS", "REPOS", "FIRST SEEN")
			for _, s := range list {
				t.row(s.FPHex[:12], s.Severity, s.State, s.RuleID, s.Preview, fmt.Sprint(s.Locations), repoList(s.Repos), s.FirstSeenAt.Format("2006-01-02"))
			}
			if err := t.flush(); err != nil {
				return err
			}
			if truncated {
				fmt.Fprintf(cmd.ErrOrStderr(), "The list shows the first %d findings. More findings match. Use --limit to show more.\n", limit)
			} else {
				fmt.Fprintf(cmd.ErrOrStderr(), "%d finding%s\n", len(list), plural(len(list)))
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&f.Org, "org", "", "only findings with a location in this org")
	cmd.Flags().StringVar(&f.Repo, "repo", "", "only findings with a location in this repository, as org/repo")
	cmd.Flags().StringVar(&f.State, "state", "", "only findings in this state: open, revoked, false_positive or ignored")
	cmd.Flags().StringVar(&severity, "severity", "", "only findings with this severity or a higher one")
	cmd.Flags().StringVar(&f.RuleID, "rule", "", "only findings of this rule")
	cmd.Flags().IntVar(&f.Limit, "limit", 1000, "maximum number of rows. The command tells you when more findings match")
	cmd.Flags().StringVar(&out.format, "format", render.Text, "output format: text, json, markdown or html")
	cmd.Flags().BoolVar(&out.asJSON, "json", false, "write JSON. This is short for --format json")
	return cmd
}

// repoList joins repository names, with a count after the third one.
func repoList(repos []string) string {
	if len(repos) > 3 {
		return strings.Join(repos[:3], ",") + fmt.Sprintf(" and %d more", len(repos)-3)
	}
	return strings.Join(repos, ",")
}

func newFindingsShowCmd(a *app) *cobra.Command {
	out := &scanOutput{}
	cmd := &cobra.Command{
		Use:   "show <fingerprint-prefix>",
		Short: "Show one finding and all its locations. The audit log records each call",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			format, err := out.resolve(render.Text, render.JSON, render.Markdown)
			if err != nil {
				return err
			}
			db, err := a.store(cmd.Context())
			if err != nil {
				return err
			}
			fp, err := db.ResolveFingerprint(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			s, locs, err := db.GetSecret(cmd.Context(), fp)
			if err != nil {
				return err
			}
			if err := db.Audit(cmd.Context(), a.actor, "show", fp, map[string]any{"locations": len(locs)}); err != nil {
				return fmt.Errorf("write audit log: %w", err)
			}
			switch format {
			case render.JSON:
				if locs == nil {
					locs = []store.Location{}
				}
				return writeJSON(cmd.OutOrStdout(), map[string]any{"finding": s, "locations": locs})
			case render.Markdown:
				var b strings.Builder
				fmt.Fprintf(&b, "## Finding %s\n\n", render.Code(s.FPHex[:12]))
				render.Table(&b, []string{"Field", "Value"}, [][]string{
					{"Fingerprint", render.Code(s.FPHex)},
					{"Rule", render.Code(s.RuleID)},
					{"Severity", s.Severity},
					{"Preview", render.Code(s.Preview)},
					{"State", s.State},
					{"First seen", s.FirstSeenAt.Format(time.RFC3339)},
				})
				fmt.Fprintf(&b, "\n### %d location%s\n\n", len(locs), plural(len(locs)))
				var rows [][]string
				for _, l := range locs {
					rows = append(rows, []string{render.Code(l.Org + "/" + l.Repo), render.Code(fmt.Sprintf("%s:%d", l.Path, l.Line)), l.Severity, render.Code(shortCommit(l.CommitSHA))})
				}
				if len(rows) > 0 {
					render.Table(&b, []string{"Repository", "Location", "Severity", "Commit"}, rows)
				}
				_, err := io.WriteString(cmd.OutOrStdout(), b.String())
				return err
			}
			w := cmd.OutOrStdout()
			fmt.Fprintf(w, "Fingerprint:  %s\n", s.FPHex)
			fmt.Fprintf(w, "Rule:         %s\n", s.RuleID)
			fmt.Fprintf(w, "Severity:     %s\n", s.Severity)
			fmt.Fprintf(w, "Preview:      %s\n", safetext.Inline(s.Preview))
			fmt.Fprintf(w, "State:        %s\n", s.State)
			fmt.Fprintf(w, "First seen:   %s\n", s.FirstSeenAt.Format(time.RFC3339))
			if s.IntroducedAt != nil {
				fmt.Fprintf(w, "Introduced:   %s\n", s.IntroducedAt.Format(time.RFC3339))
			}
			if s.ResolvedAt != nil {
				fmt.Fprintf(w, "Resolved:     %s by %s\n", s.ResolvedAt.Format(time.RFC3339), safetext.Inline(s.ResolvedBy))
			}
			if s.ResolvedNote != "" {
				fmt.Fprintf(w, "Note:         %s\n", safetext.Inline(s.ResolvedNote))
			}
			fmt.Fprintf(w, "\n%d location%s in %d repositor%s:\n\n", len(locs), plural(len(locs)), len(s.Repos), pluralY(len(s.Repos)))
			t := newTable(w, "REPO", "LOCATION", "SEVERITY", "COMMIT", "AUTHOR", "COMMITTED")
			for _, l := range locs {
				commit, when := "", ""
				if len(l.CommitSHA) >= 12 {
					commit = l.CommitSHA[:12]
				}
				if l.CommittedAt != nil {
					when = l.CommittedAt.Format("2006-01-02")
				}
				t.row(l.Org+"/"+l.Repo, fmt.Sprintf("%s:%d", l.Path, l.Line), l.Severity, commit, l.AuthorEmail, when)
			}
			return t.flush()
		},
	}
	cmd.Flags().StringVar(&out.format, "format", render.Text, "output format: text, json or markdown")
	cmd.Flags().BoolVar(&out.asJSON, "json", false, "write JSON. This is short for --format json")
	return cmd
}

func newFindingsResolveCmd(a *app) *cobra.Command {
	var state, note string
	cmd := &cobra.Command{
		Use:   "resolve <fingerprint-prefix>",
		Short: "Set the state of a finding. The audit log records each change",
		Long: "Set the state of a finding. The states are open, revoked, false_positive\n" +
			"and ignored. The change applies to all locations of the secret, in all\n" +
			"repositories. The audit log records the actor, the old state and the note.",
		Example: `  terces findings resolve 3f2a9c1b04de --state revoked --note "rotated in AWS console"`,
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if !store.ValidState(state) {
				return fmt.Errorf("--state %q: use open, revoked, false_positive or ignored", state)
			}
			if state != store.StateOpen && strings.TrimSpace(note) == "" {
				return errors.New("--note is required: say how the secret was handled")
			}
			db, err := a.store(cmd.Context())
			if err != nil {
				return err
			}
			fp, err := db.ResolveFingerprint(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			if err := db.Resolve(cmd.Context(), fp, state, a.actor, note); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "%x is now %s\n", fp[:6], state)
			return nil
		},
	}
	cmd.Flags().StringVar(&state, "state", "", "new state: open, revoked, false_positive or ignored")
	cmd.Flags().StringVar(&note, "note", "", "how the secret was handled")
	_ = cmd.MarkFlagRequired("state")
	return cmd
}
