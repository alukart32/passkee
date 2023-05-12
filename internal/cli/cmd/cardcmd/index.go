package cardcmd

import (
	"github.com/spf13/cobra"
)

func indexCmd() *cobra.Command {
	cmd := cobra.Command{
		Use:   "list",
		Short: "List all credit card records name",
	}
	cmd.RunE = indexE
	return &cmd
}

func indexE(cmd *cobra.Command, args []string) error {

	return nil
}
