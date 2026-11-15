package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"terces/internal/pipeline"
)

func newSyncCmd(a *app) *cobra.Command {
	var org string
	var scan, asJSON bool
	var concurrency int
	cmd := &cobra.Command{
		Use:   "sync",
		Short: "Discover installations and repositories, and update the mirrors",
		Long: "Discover the GitHub App installations and their repositories, update the\n" +
			"repository table and fetch the mirrors. A repository that the app can no\n" +
			"longer see keeps its findings, but sync stops fetching it.",
		Example: "  terces sync\n" +
			"  terces sync --org my-org --scan",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			sw, err := a.pipeline(cmd.Context(), true)
			if err != nil {
				return err
			}
			sw.Concurrency = concurrency
			sum, err := sw.Sync(cmd.Context(), pipeline.SyncOptions{Org: org, Scan: scan})
			if sum != nil {
				if asJSON {
					if jerr := writeJSON(cmd.OutOrStdout(), sum); jerr != nil {
						return jerr
					}
				} else {
					fmt.Fprintf(cmd.OutOrStdout(), "%d installations, %d repositories, %d fetched, %d fetch errors, %d removed\n",
						sum.Installations, sum.Repos, sum.Fetched, sum.FetchErrors, sum.Removed)
					if scan {
						fmt.Fprintf(cmd.OutOrStdout(), "%d scanned, %d scan errors, %d findings, %d new secrets\n",
							sum.Scanned, sum.ScanErrors, sum.Findings, sum.NewSecrets)
					}
				}
			}
			if err != nil {
				return err
			}
			if sum.FetchErrors > 0 || sum.ScanErrors > 0 {
				return fmt.Errorf("%d fetch errors and %d scan errors", sum.FetchErrors, sum.ScanErrors)
			}
			if scan && sum.Findings > 0 {
				return errFindings
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&org, "org", "", "sync only this org")
	cmd.Flags().BoolVar(&scan, "scan", false, "run an incremental scan of each repository after its fetch")
	cmd.Flags().IntVar(&concurrency, "concurrency", 4, "number of repositories to fetch at the same time")
	cmd.Flags().BoolVar(&asJSON, "json", false, "write JSON")
	return cmd
}
