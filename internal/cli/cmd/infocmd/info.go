package infocmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var versionTag, buildTag string

var Cmd = &cobra.Command{
	Use:   "build-info",
	Short: "CLI build info",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("Build\n  ver : %v\n  data: %s",
			versionTag, buildTag)
	},
}
