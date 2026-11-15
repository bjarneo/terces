package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

func newMigrateCmd(a *app) *cobra.Command {
	return &cobra.Command{
		Use:   "migrate",
		Short: "Create or update the database schema",
		Long: "Create or update the database schema. Run it with a role that can\n" +
			"create tables. The scanner and the CLI can then use roles with fewer rights.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			db, err := a.store(cmd.Context())
			if err != nil {
				return err
			}
			applied, err := db.Migrate(cmd.Context())
			for _, name := range applied {
				fmt.Fprintln(cmd.OutOrStdout(), "applied", name)
			}
			if err != nil {
				return err
			}
			if len(applied) == 0 {
				fmt.Fprintln(cmd.OutOrStdout(), "the schema is up to date")
			}
			return nil
		},
	}
}
