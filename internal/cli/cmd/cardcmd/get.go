package cardcmd

import (
	"github.com/spf13/cobra"
)

func getCmd() *cobra.Command {
	cmd := cobra.Command{
		Use:   "get [--n name]",
		Short: "Get credit card from vault",
	}
	cmd.RunE = getE

	cmd.Flags().StringVarP(&name, "name", "n", "", "Record name")
	cmd.MarkFlagRequired("name")

	return &cmd
}

func getE(cmd *cobra.Command, args []string) error {
	return nil
}
