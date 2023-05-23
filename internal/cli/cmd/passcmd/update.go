package passcmd

import (
	"github.com/spf13/cobra"
)

func updateCmd() *cobra.Command {
	cmd := cobra.Command{
		Use:   "update [--n name]([notes]) value",
		Short: "Update credential record",
	}

	cmd.RunE = runUpdateE

	cmd.Flags().StringVarP(&name, "name", "n", "", "Record name")
	cmd.MarkFlagRequired("name")
	cmd.Flags().StringVarP(&notes, "notes", "", "", "Notes of the record")

	return &cmd
}

func runUpdateE(cmd *cobra.Command, args []string) error {
	return nil
}
