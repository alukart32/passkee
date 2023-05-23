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
		fmt.Printf("Build info:\n\tversion: %v\n\tbuild data: %s",
			versionTag, buildTag)
	},
}
