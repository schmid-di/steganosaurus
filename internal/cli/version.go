package cli

import (
	"fmt"
	"runtime"
	"runtime/debug"

	"github.com/spf13/cobra"
)

// version is set at build time:
//
//	go build -ldflags "-X github.com/schmid-di/steganosaurus/internal/cli.version=v0.1.0"
var version = ""

// Version returns the build version, falling back to the module version
// recorded by `go install` and finally to "dev".
func Version() string {
	if version != "" {
		return version
	}
	if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
		return bi.Main.Version
	}
	return "dev"
}

func newVersionCmd(a *app) *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the version",
		Args:  cobra.NoArgs,
		Run: func(*cobra.Command, []string) {
			fmt.Fprintf(a.stdout, "steganosaurus %s (%s, %s/%s)\n", Version(), runtime.Version(), runtime.GOOS, runtime.GOARCH)
		},
	}
}
