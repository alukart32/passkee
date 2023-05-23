package textcmd

import "github.com/spf13/cobra"

func deleteCmd() *cobra.Command {
	cmd := cobra.Command{
		Use:   "delete [--n name]",
		Short: "Delete binary data from vault",
	}
	cmd.RunE = deleteE

	cmd.Flags().StringVarP(&name, "name", "n", "", "Record name")
	cmd.MarkFlagRequired("name")

	return &cmd
}

func deleteE(cmd *cobra.Command, args []string) error {
	return nil
}
