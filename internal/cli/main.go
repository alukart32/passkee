// Package cli provides the passkee cli application entrypoint.
package cli

import (
	"os"

	"github.com/alukart32/yandex/practicum/passkee/internal/cli/cmd"
)

// Execute launches the cli application.
func Execute() {
	err := cmd.Root.Execute()
	if err != nil {
		os.Exit(1)
	}
}
