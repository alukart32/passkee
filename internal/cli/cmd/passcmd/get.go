package passcmd

import (
	"github.com/spf13/cobra"
)

func getCmd() *cobra.Command {
	cmd := cobra.Command{
		Use:   "get [--n name]",
		Short: "Get credential from vault",
	}

	cmd.RunE = runGetE

	cmd.Flags().StringVarP(&name, "name", "n", "", "Record name")
	cmd.MarkFlagRequired("name")

	return &cmd
}

func runGetE(cmd *cobra.Command, args []string) error {
	return nil
}
