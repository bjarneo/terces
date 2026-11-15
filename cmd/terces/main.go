// Command terces scans GitHub repositories for secrets.
//
// Exit codes: 0 means no findings, 1 means findings, 2 means an error.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	"terces/internal/safetext"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

// errFindings makes the process exit with code 1.
var errFindings = errors.New("findings")

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	a := &app{}
	root := newRootCmd(a)
	err := root.ExecuteContext(ctx)
	a.close()
	switch {
	case err == nil:
		os.Exit(0)
	case errors.Is(err, errFindings):
		os.Exit(1)
	default:
		fmt.Fprintln(os.Stderr, "terces:", safetext.Inline(err.Error()))
		os.Exit(2)
	}
}

func newRootCmd(a *app) *cobra.Command {
	root := &cobra.Command{
		Use:           "terces",
		Short:         "Scan GitHub repositories for secrets",
		Long:          "terces scans the full git history of GitHub repositories for secrets.\nIt runs as a CLI, as a pre-commit hook and as a webhook service.\n\nExit codes: 0 means no findings, 1 means findings, 2 means an error.",
		SilenceErrors: true,
		SilenceUsage:  true,
		Version:       version,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			return a.setup()
		},
	}
	a.bindFlags(root)
	root.AddCommand(
		newSyncCmd(a),
		newScanCmd(a),
		newFindingsCmd(a),
		newReportCmd(a),
		newRulesCmd(a),
		newServeCmd(a),
		newMigrateCmd(a),
	)
	return root
}
