package passcmd

import "github.com/spf13/cobra"

func deleteCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "delete [--n name]",
		Short: "Delete credential from vault",
	}

	cmd.RunE = runDeleteE

	cmd.Flags().StringVarP(&name, "name", "n", "", "Record name")
	cmd.MarkFlagRequired("name")

	return cmd
}

func runDeleteE(cmd *cobra.Command, args []string) error {
	return nil
}
