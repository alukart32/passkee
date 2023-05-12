package bincmd

import (
	"github.com/spf13/cobra"
)

func updateCmd() *cobra.Command {
	cmd := cobra.Command{
		Use:   "update [--n name]([-notes]) filepath",
		Short: "Update binary record",
	}
	cmd.RunE = updateE

	cmd.Flags().StringVarP(&name, "name", "n", "", "Record name")
	cmd.MarkFlagRequired("name")
	cmd.Flags().StringVarP(&notes, "notes", "", "", "Notes of the record")

	return &cmd
}

func updateE(cmd *cobra.Command, args []string) error {
	_, _ = cmd.Flags().GetString("name")

	return nil
}
