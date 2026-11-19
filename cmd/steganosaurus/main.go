// Command steganosaurus finds hidden data in files.
package main

import (
	"os"

	"github.com/schmid-di/steganosaurus/internal/cli"
)

func main() {
	os.Exit(cli.Execute(os.Args[1:], os.Stdout, os.Stderr))
}
