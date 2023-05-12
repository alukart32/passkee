package cardcmd

import "github.com/spf13/cobra"

func deleteCmd() *cobra.Command {
	cmd := cobra.Command{
		Use:   "delete [--n name]",
		Short: "Delete credit card from vault",
	}
	cmd.RunE = delete

	cmd.Flags().StringVarP(&name, "name", "n", "", "Record name")
	cmd.MarkFlagRequired("name")

	return &cmd
}

func delete(cmd *cobra.Command, args []string) error {
	return nil
}
