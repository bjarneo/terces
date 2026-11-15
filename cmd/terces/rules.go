package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"terces/internal/engine"
	"terces/internal/fingerprint"
	"terces/internal/mirror"
	"terces/internal/rules"
)

func newRulesCmd(a *app) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "rules",
		Short: "List, test and import detection rules",
	}
	cmd.AddCommand(newRulesListCmd(a), newRulesTestCmd(a), newRulesImportCmd())
	return cmd
}

func newRulesListCmd(a *app) *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List the loaded rules",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			set, err := a.rules()
			if err != nil {
				return err
			}
			if asJSON {
				return writeJSON(cmd.OutOrStdout(), set.Rules)
			}
			t := newTable(cmd.OutOrStdout(), "ID", "SEVERITY", "KEYWORDS", "FILE")
			for _, r := range set.Rules {
				t.row(r.ID, r.Sev.String(), strings.Join(r.Keywords, ","), r.File)
			}
			if err := t.flush(); err != nil {
				return err
			}
			sum := set.Hash()
			sc, err := a.scanner(false)
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.ErrOrStderr(), "%d rules from %s, rules hash %x, cache version %d\n",
				len(set.Rules), set.Source, sum[:6], sc.Version())
			return nil
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "write JSON")
	return cmd
}

func newRulesTestCmd(a *app) *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "test <rule-id> <file>",
		Short: "Show every match of one rule in a file, and the reason for each dropped match",
		Long: "Show every match of one rule in a file, and the reason for each dropped match.\n" +
			"The output shows a preview of each secret, never the full value.\n" +
			"The command exits with 1 when the rule reports a finding.",
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			set, err := a.rules()
			if err != nil {
				return err
			}
			data, err := os.ReadFile(args[1])
			if err != nil {
				return err
			}
			if mirror.IsBinary(data) {
				fmt.Fprintln(cmd.ErrOrStderr(), "warning: the file is binary. The scanner skips binary files.")
			}
			eng := engine.New(set)
			cands, err := eng.Explain(args[0], data)
			if err != nil {
				return err
			}
			type row struct {
				Line    int     `json:"line"`
				Preview string  `json:"preview"`
				Entropy float64 `json:"entropy"`
				Decoded string  `json:"decoded,omitempty"`
				Result  string  `json:"result"`
			}
			var rows []row
			kept := 0
			for _, c := range cands {
				res := "finding"
				if c.Dropped != "" {
					res = "dropped: " + c.Dropped
				} else {
					sev, reason := eng.ApplyPath(c.Rule.ID, c.PathAllow, c.Rule.Sev, args[1])
					if reason != "" {
						res = "dropped: " + reason
					} else {
						kept++
						res = "finding, severity " + sev.String()
					}
				}
				rows = append(rows, row{c.Line, fingerprint.Preview(c.Secret), c.Entropy, c.Decoded, res})
				clear(c.Secret)
			}
			if asJSON {
				if err := writeJSON(cmd.OutOrStdout(), rows); err != nil {
					return err
				}
			} else {
				t := newTable(cmd.OutOrStdout(), "LINE", "PREVIEW", "ENTROPY", "DECODED", "RESULT")
				for _, r := range rows {
					t.row(fmt.Sprint(r.Line), r.Preview, fmt.Sprintf("%.2f", r.Entropy), r.Decoded, r.Result)
				}
				if err := t.flush(); err != nil {
					return err
				}
				fmt.Fprintf(cmd.ErrOrStderr(), "%d match%s, %d finding%s\n", len(rows), pluralEs(len(rows)), kept, plural(kept))
			}
			if kept > 0 {
				return errFindings
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "write JSON")
	return cmd
}

func newRulesImportCmd() *cobra.Command {
	var exclude []string
	var output string
	cmd := &cobra.Command{
		Use:   "import-gitleaks <gitleaks.toml>",
		Short: "Convert a gitleaks config to the terces rule format",
		Long: "Convert a gitleaks config to the terces rule format.\n" +
			"The command does not convert rules that match file paths only.\n\n" +
			"Example:\n" +
			"  terces rules import-gitleaks gitleaks.toml \\\n" +
			"    --exclude aws-access-token,private-key -o rules/gitleaks.yaml",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			data, err := os.ReadFile(args[0])
			if err != nil {
				return err
			}
			out, notes, err := rules.ConvertGitleaks(data, rules.ConvertOptions{Exclude: exclude})
			if err != nil {
				return err
			}
			for _, n := range notes {
				fmt.Fprintln(cmd.ErrOrStderr(), "note:", n)
			}
			if output == "" || output == "-" {
				_, err = cmd.OutOrStdout().Write(out)
				return err
			}
			return os.WriteFile(output, out, 0o644)
		},
	}
	cmd.Flags().StringSliceVar(&exclude, "exclude", nil, "rule IDs to leave out")
	cmd.Flags().StringVarP(&output, "output", "o", "", "output file. The default is stdout")
	return cmd
}
