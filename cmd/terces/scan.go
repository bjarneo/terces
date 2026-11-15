package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"terces/internal/fingerprint"
	"terces/internal/mirror"
	"terces/internal/pipeline"
	"terces/internal/render"
	"terces/internal/safetext"
	"terces/internal/scanner"
)

// scanOutput holds the output flags of the scan and findings commands.
type scanOutput struct {
	format  string
	asJSON  bool
	summary bool
	// target names what a scan covered, for the report title.
	target string
}

// resolve returns the output format. --json is short for --format json.
func (o *scanOutput) resolve(allowed ...string) (string, error) {
	f := o.format
	if o.asJSON {
		f = render.JSON
	}
	if len(allowed) == 0 {
		allowed = []string{render.Text, render.JSON, render.Markdown, render.HTML, render.SARIF}
	}
	if err := render.CheckFormat(f, allowed...); err != nil {
		return "", err
	}
	if o.summary && f == render.SARIF {
		return "", errors.New("--summary does not work with --format sarif")
	}
	return f, nil
}

func (o *scanOutput) report() render.ReportOptions {
	return render.ReportOptions{SummaryOnly: o.summary, Target: o.target}
}

func newScanCmd(a *app) *cobra.Command {
	var staged bool
	out := &scanOutput{}
	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Scan repositories, directories, staged changes or commit ranges",
		Long: "Scan repositories, directories, staged changes or commit ranges.\n\n" +
			"Use --staged in a pre-commit hook. It scans the staged changes of the\n" +
			"repository in the current directory and reports only new secrets.",
		Example: "  terces scan --staged\n" +
			"  terces scan path ./config\n" +
			"  terces scan range origin/main..HEAD\n" +
			"  terces scan repo my-org/my-repo",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if !staged {
				return cmd.Help()
			}
			format, err := out.resolve()
			if err != nil {
				return err
			}
			sc, err := a.scanner(false)
			if err != nil {
				return err
			}
			findings, st, err := sc.ScanStaged(cmd.Context(), &mirror.Git{})
			if err != nil {
				return err
			}
			// A hook stays silent when the staged changes are clean.
			if len(findings) == 0 && format == render.Text {
				return nil
			}
			out.target = "staged changes"
			if err := writeFindings(cmd.OutOrStdout(), cmd.ErrOrStderr(), format, out, sc, findings, st); err != nil {
				return err
			}
			if len(findings) == 0 {
				return nil
			}
			w := cmd.ErrOrStderr()
			fmt.Fprintln(w, "\nThe staged changes contain new secrets. Remove them from the files and stage the files again.")
			fmt.Fprintln(w, "If a secret was pushed before, revoke it. Removing it from the files does not make it safe.")
			if sc.Hasher.Ephemeral() {
				fmt.Fprintln(w, "If a finding is a false positive, check it and commit with `git commit --no-verify`.\n"+
					"The fingerprints above are valid for this run only, because "+envPrefix+"HMAC_KEY is not set.")
			} else {
				fmt.Fprintln(w, "If a finding is a false positive, add its full fingerprint to .terces.yaml.")
			}
			return errFindings
		},
	}
	cmd.Flags().BoolVar(&staged, "staged", false, "scan the staged changes of the repository in the current directory")
	cmd.PersistentFlags().StringVar(&out.format, "format", render.Text, "output format: text, json, markdown, html or sarif")
	cmd.PersistentFlags().BoolVar(&out.asJSON, "json", false, "write JSON. This is short for --format json")
	cmd.PersistentFlags().BoolVar(&out.summary, "summary", false, "write only the summary: the counts by severity, rule and repository")
	cmd.AddCommand(
		newScanPathCmd(a, out),
		newScanRangeCmd(a, out),
		newScanHistoryCmd(a, out),
		newScanRepoCmd(a, out),
		newScanOrgCmd(a, out),
	)
	return cmd
}

func newScanPathCmd(a *app, out *scanOutput) *cobra.Command {
	return &cobra.Command{
		Use:   "path <dir>",
		Short: "Scan the files in a local directory. The command does not use git",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			format, err := out.resolve()
			if err != nil {
				return err
			}
			info, err := os.Stat(args[0])
			if err != nil {
				return err
			}
			if !info.IsDir() {
				return fmt.Errorf("%s is not a directory", args[0])
			}
			sc, err := a.scanner(false)
			if err != nil {
				return err
			}
			findings, st, err := sc.ScanDir(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			// Name the directory, not its full path: a shared report must
			// not show the home directory of the person who ran it.
			out.target = args[0]
			if abs, err := filepath.Abs(args[0]); err == nil {
				out.target = filepath.Base(abs)
			}
			return findingsResult(cmd, format, out, sc, findings, st)
		},
	}
}

func newScanRangeCmd(a *app, out *scanOutput) *cobra.Command {
	var gitDir string
	cmd := &cobra.Command{
		Use:   "range <base>..<head>",
		Short: "Scan the commits in a range and report only new secrets",
		Long: "Scan the blobs that the commits in base..head add, including blobs of\n" +
			"intermediate commits. A secret that also exists on the base side is not new.\n" +
			"The command reads .terces.yaml at base, so that a change cannot\n" +
			"ignore its own secret.",
		Example: "  terces scan range origin/main..HEAD\n" +
			"  terces scan range --git-dir /data/mirrors/123/repo.git 4f1c2e..9ab3d0",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			format, err := out.resolve()
			if err != nil {
				return err
			}
			base, head, ok := strings.Cut(args[0], "..")
			if !ok || base == "" || head == "" || strings.HasPrefix(head, ".") {
				return fmt.Errorf("use the form <base>..<head>")
			}
			sc, err := a.scanner(false)
			if err != nil {
				return err
			}
			findings, st, err := sc.ScanRange(cmd.Context(), localGit(gitDir), base, head, scanner.RangeOptions{})
			if err != nil {
				return err
			}
			out.target = args[0]
			return findingsResult(cmd, format, out, sc, findings, st)
		},
	}
	cmd.Flags().StringVar(&gitDir, "git-dir", "", "repository to scan. The default is the current directory")
	return cmd
}

func newScanHistoryCmd(a *app, out *scanOutput) *cobra.Command {
	var gitDir string
	cmd := &cobra.Command{
		Use:   "history",
		Short: "Scan the full history of a local repository. The command does not use the database",
		Long: "Scan every blob that the refs of a local repository reach. The command\n" +
			"does not use the database or GitHub. Use it for a one-time audit of a clone.",
		Example: "  git clone --mirror https://github.com/my-org/my-repo.git\n" +
			"  terces scan history --git-dir my-repo.git",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			format, err := out.resolve()
			if err != nil {
				return err
			}
			sc, err := a.scanner(false)
			if err != nil {
				return err
			}
			g := localGit(gitDir)
			// A hostile clone can hold a broken or huge config. Ignore it,
			// which can only add findings.
			cfg, cfgErr := scanner.LoadConfig(cmd.Context(), g, "HEAD")
			findings, st, err := sc.ScanHistory(cmd.Context(), g, scanner.HistoryOptions{Config: cfg})
			if err != nil {
				return err
			}
			if cfgErr != nil {
				st.Warn(cfgErr.Error() + ". The scan ignores the file")
			}
			out.target = gitDir
			if gitDir == "" {
				out.target = "history"
			}
			return findingsResult(cmd, format, out, sc, findings, st)
		},
	}
	cmd.Flags().StringVar(&gitDir, "git-dir", "", "repository to scan. The default is the current directory")
	return cmd
}

func newScanRepoCmd(a *app, out *scanOutput) *cobra.Command {
	var full bool
	cmd := &cobra.Command{
		Use:   "repo <org>/<repo>",
		Short: "Scan the mirror of one repository and store the findings",
		Long: "Scan the mirror of one repository and its wiki, and store the findings.\n" +
			"The first scan covers the full history. A later scan covers only the\n" +
			"commits after the last scan. Use --full to scan the full history again.\n" +
			"Blobs that an earlier scan read with the same rules come from the cache.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			format, err := out.resolve()
			if err != nil {
				return err
			}
			org, name, ok := strings.Cut(args[0], "/")
			if !ok || org == "" || name == "" {
				return fmt.Errorf("use the form <org>/<repo>")
			}
			sw, err := a.pipeline(cmd.Context(), false)
			if err != nil {
				return err
			}
			r, err := sw.Store.FindRepo(cmd.Context(), org, name)
			if err != nil {
				return fmt.Errorf("%s/%s: %w. Run `terces sync` first", org, name, err)
			}
			res, err := sw.ScanRepo(cmd.Context(), r.ID, full)
			if err != nil {
				return err
			}
			out.target = r.FullName()
			return repoResults(cmd, format, out, sw.Scanner, []*pipeline.ScanResult{res})
		},
	}
	cmd.Flags().BoolVar(&full, "full", false, "scan the full history, not only the commits after the last scan")
	return cmd
}

func newScanOrgCmd(a *app, out *scanOutput) *cobra.Command {
	var full bool
	cmd := &cobra.Command{
		Use:   "org <org>",
		Short: "Scan the mirrors of all repositories in an org and store the findings",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			// GitHub takes one SARIF file for each repository.
			if f, _ := out.resolve(); f == render.SARIF {
				return errors.New("--format sarif needs one repository: use `terces scan repo <org>/<repo> --format sarif`")
			}
			format, err := out.resolve(render.Text, render.JSON, render.Markdown, render.HTML)
			if err != nil {
				return err
			}
			sw, err := a.pipeline(cmd.Context(), false)
			if err != nil {
				return err
			}
			repos, err := sw.Store.ListRepos(cmd.Context(), args[0], false)
			if err != nil {
				return err
			}
			if len(repos) == 0 {
				return fmt.Errorf("no repositories for org %s: run `terces sync` first", args[0])
			}
			var results []*pipeline.ScanResult
			failed := 0
			for _, r := range repos {
				res, err := sw.ScanRepo(cmd.Context(), r.ID, full)
				if err != nil {
					if cmd.Context().Err() != nil {
						return err
					}
					failed++
					a.log.Error("scan failed", "repo", r.FullName(), "err", err)
					continue
				}
				results = append(results, res)
			}
			out.target = args[0]
			err = repoResults(cmd, format, out, sw.Scanner, results)
			if failed > 0 && (err == nil || err == errFindings) {
				return fmt.Errorf("%d of %d repositories failed to scan", failed, len(repos))
			}
			return err
		},
	}
	cmd.Flags().BoolVar(&full, "full", false, "scan the full history, not only the commits after the last scan")
	return cmd
}

func findingsResult(cmd *cobra.Command, format string, o *scanOutput, sc *scanner.Scanner, findings []scanner.Finding, st *scanner.Stats) error {
	if err := writeFindings(cmd.OutOrStdout(), cmd.ErrOrStderr(), format, o, sc, findings, st); err != nil {
		return err
	}
	if len(findings) > 0 {
		return errFindings
	}
	return nil
}

// writeFindings writes findings in a format. In text and SARIF, the
// summary, the gaps and the warnings go to errOut. In Markdown and HTML,
// they are part of the report.
func writeFindings(out, errOut io.Writer, format string, o *scanOutput, sc *scanner.Scanner, findings []scanner.Finding, st *scanner.Stats) error {
	scanner.SortFindings(findings)
	groups := []render.RepoFindings{{Findings: findings}}
	switch format {
	case render.JSON:
		if findings == nil {
			findings = []scanner.Finding{}
		}
		v := map[string]any{"summary": render.Summarize(groups, st), "stats": st}
		if !o.summary {
			v["findings"] = findings
		}
		return writeJSON(out, v)
	case render.Markdown:
		return render.FindingsMarkdown(out, groups, st, o.report())
	case render.HTML:
		return render.FindingsHTML(out, groups, st, o.report())
	case render.SARIF:
		if err := render.SARIFLog(out, findings, sc.Engine.Rules(), sarifOptions(sc)); err != nil {
			return err
		}
	default:
		if o.summary {
			if err := render.SummaryText(out, render.Summarize(groups, st)); err != nil {
				return err
			}
			break
		}
		if len(findings) > 0 {
			// A directory scan has no commits, so it gets no commit column.
			withCommit := false
			for _, f := range findings {
				withCommit = withCommit || f.CommitSHA != ""
			}
			headers := []string{"SEVERITY", "RULE", "PREVIEW", "LOCATION", "FINGERPRINT"}
			if withCommit {
				headers = []string{"SEVERITY", "RULE", "PREVIEW", "LOCATION", "COMMIT", "FINGERPRINT"}
			}
			t := newTable(out, headers...)
			for _, f := range findings {
				if withCommit {
					t.row(f.Severity.String(), f.RuleID, f.Preview, location(f), shortCommit(f.CommitSHA), fingerprint.Short(f.Fingerprint))
				} else {
					t.row(f.Severity.String(), f.RuleID, f.Preview, location(f), fingerprint.Short(f.Fingerprint))
				}
			}
			if err := t.flush(); err != nil {
				return err
			}
			fmt.Fprintln(errOut)
			_ = render.SummaryText(errOut, render.Summarize(groups, st))
		}
	}
	writeGaps(errOut, st)
	fmt.Fprintf(errOut, "%d finding%s. %s\n", len(findings), plural(len(findings)), st.Summary())
	return nil
}

func sarifOptions(sc *scanner.Scanner) render.SARIFOptions {
	return render.SARIFOptions{ToolVersion: version, StableFingerprints: !sc.Hasher.Ephemeral()}
}

func location(f scanner.Finding) string {
	loc := fmt.Sprintf("%s:%d", safetext.Display(f.Path), f.Line)
	if f.Decoded != "" {
		loc += " (" + f.Decoded + ")"
	}
	return loc
}

func shortCommit(sha string) string {
	if len(sha) >= 12 {
		return sha[:12]
	}
	return sha
}

// writeGaps writes the warnings and the blobs that the scan did not read
// in full.
func writeGaps(w io.Writer, st *scanner.Stats) {
	for _, msg := range st.Warnings {
		fmt.Fprintln(w, "warning:", safetext.Inline(msg))
	}
	if len(st.Gaps) == 0 {
		return
	}
	n := st.SkippedSize + st.Capped
	fmt.Fprintf(w, "warning: %d blob%s not scanned in full. A blob above --max-blob-size gets no scan. At the match limit, a rule found more secrets than the output shows.\n", n, plural(n))
	t := newTable(w, "PATH", "BLOB", "REASON", "SIZE")
	for _, g := range st.Gaps {
		size := ""
		if g.Size > 0 {
			size = fmt.Sprint(g.Size)
		}
		t.row(safetext.Display(g.Path), g.Blob, g.Reason, size)
	}
	_ = t.flush()
	if n > len(st.Gaps) {
		fmt.Fprintf(w, "The list shows the first %d. Use --format json for the counts.\n", len(st.Gaps))
	}
}

func repoResults(cmd *cobra.Command, format string, o *scanOutput, sc *scanner.Scanner, results []*pipeline.ScanResult) error {
	total := 0
	st := &scanner.Stats{}
	var groups []render.RepoFindings
	for _, r := range results {
		total += len(r.Findings)
		st.Add(r.Stats)
		scanner.SortFindings(r.Findings)
		groups = append(groups, render.RepoFindings{Repo: r.Repo.FullName(), Findings: r.Findings})
	}
	switch format {
	case render.JSON:
		type repoOut struct {
			Repo         string            `json:"repo"`
			Findings     []scanner.Finding `json:"findings"`
			NewSecrets   int               `json:"new_secrets"`
			NewLocations int               `json:"new_locations"`
			Stats        *scanner.Stats    `json:"stats"`
		}
		outs := []repoOut{}
		for _, r := range results {
			fs := r.Findings
			if fs == nil || o.summary {
				fs = []scanner.Finding{}
			}
			outs = append(outs, repoOut{r.Repo.FullName(), fs, len(r.NewSecrets), r.NewLocations, r.Stats})
		}
		if err := writeJSON(cmd.OutOrStdout(), map[string]any{"summary": render.Summarize(groups, st), "repositories": outs}); err != nil {
			return err
		}
	case render.Markdown:
		if err := render.FindingsMarkdown(cmd.OutOrStdout(), groups, st, o.report()); err != nil {
			return err
		}
	case render.HTML:
		if err := render.FindingsHTML(cmd.OutOrStdout(), groups, st, o.report()); err != nil {
			return err
		}
	case render.SARIF:
		var fs []scanner.Finding
		for _, r := range results {
			fs = append(fs, r.Findings...)
		}
		if err := render.SARIFLog(cmd.OutOrStdout(), fs, sc.Engine.Rules(), sarifOptions(sc)); err != nil {
			return err
		}
	default:
		if o.summary {
			if err := render.SummaryText(cmd.OutOrStdout(), render.Summarize(groups, st)); err != nil {
				return err
			}
		} else if total > 0 {
			t := newTable(cmd.OutOrStdout(), "REPO", "SEVERITY", "RULE", "PREVIEW", "LOCATION", "COMMIT", "FINGERPRINT")
			for _, r := range results {
				for _, f := range r.Findings {
					t.row(r.Repo.FullName(), f.Severity.String(), f.RuleID, f.Preview, location(f), shortCommit(f.CommitSHA), fingerprint.Short(f.Fingerprint))
				}
			}
			if err := t.flush(); err != nil {
				return err
			}
			fmt.Fprintln(cmd.ErrOrStderr())
			_ = render.SummaryText(cmd.ErrOrStderr(), render.Summarize(groups, st))
		}
	}
	if format != render.JSON {
		if format == render.Text || format == render.SARIF {
			writeGaps(cmd.ErrOrStderr(), st)
		}
		newSecrets := 0
		for _, r := range results {
			newSecrets += len(r.NewSecrets)
		}
		fmt.Fprintf(cmd.ErrOrStderr(), "%d repositor%s, %d finding%s in this scan, %d new secret%s. %s\n",
			len(results), pluralY(len(results)), total, plural(total), newSecrets, plural(newSecrets), st.Summary())
	}
	if total > 0 {
		return errFindings
	}
	return nil
}

// localGit returns a Git for a local repository. A directory with HEAD and
// objects/ in it is a bare repository, also without the .git suffix.
func localGit(dir string) *mirror.Git {
	g := &mirror.Git{Dir: dir}
	if dir == "" {
		return g
	}
	_, headErr := os.Stat(filepath.Join(dir, "HEAD"))
	objects, objErr := os.Stat(filepath.Join(dir, "objects"))
	g.Bare = headErr == nil && objErr == nil && objects.IsDir()
	return g
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

func pluralY(n int) string {
	if n == 1 {
		return "y"
	}
	return "ies"
}

func pluralEs(n int) string {
	if n == 1 {
		return ""
	}
	return "es"
}
