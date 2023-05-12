package cli

import (
	"os"

	"github.com/alukart32/yandex/practicum/passkee/internal/cli/cmd"
)

func Execute() {
	err := cmd.Root.Execute()
	if err != nil {
		os.Exit(1)
	}
}
