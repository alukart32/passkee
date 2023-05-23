package cardcmd

import (
	"github.com/spf13/cobra"
)

func addCmd() *cobra.Command {
	cmd := cobra.Command{
		Use:   "add [--n name]([-notes]) value",
		Short: "Put a new credit card in vault",
		Example: `add --t credit_card --n demo_card -notes DemoBank
	4960148153718504:02/2025:906:owner_name`,
		Args: func(cmd *cobra.Command, args []string) error {
			if err := cobra.ExactArgs(1)(cmd, args); err != nil {
				return err
			}
			return nil
		},
	}
	cmd.RunE = addE

	cmd.Flags().StringVarP(&name, "name", "n", "", "Name of the new record")
	cmd.MarkFlagRequired("name")
	cmd.Flags().StringVarP(&notes, "notes", "", "", "Extra notes")

	return &cmd
}

var name, notes string

func addE(cmd *cobra.Command, args []string) error {

	return nil
}
