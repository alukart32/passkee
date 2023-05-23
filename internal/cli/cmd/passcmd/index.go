package passcmd

import (
	"github.com/spf13/cobra"
)

func indexCmd() *cobra.Command {
	cmd := cobra.Command{
		Use:   "list",
		Short: "List all credential records names",
	}
	cmd.RunE = runIndexE
	return &cmd
}

func runIndexE(cmd *cobra.Command, args []string) error {

	return nil
}
