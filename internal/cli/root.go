// Package cli implements the steganosaurus command line interface.
package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"

	"github.com/spf13/cobra"
)

// Exit codes as defined in docs/SPEC.md.
const (
	ExitOK        = 0
	ExitError     = 1
	ExitFlagFound = 2
)

// globalOptions are flags shared by all subcommands.
type globalOptions struct {
	outDir      string
	jsonOut     bool
	flagFormats []string
	stopOnFlag  bool
	depth       int
	wordlist    string
	jobs        int
	verbose     bool
	quiet       bool
	noColor     bool
}

// app carries state through a single CLI invocation.
type app struct {
	opts     globalOptions
	stdout   io.Writer
	stderr   io.Writer
	exitCode int
}

func newRootCmd(a *app) *cobra.Command {
	root := &cobra.Command{
		Use:   "steganosaurus",
		Short: "Steganography analysis for CTF players",
		Long: `steganosaurus finds hidden data in files.

Run 'steganosaurus scan <file>' to let it triage a file automatically: it
detects the file type, runs every applicable analysis, recurses into
extracted data and highlights flags such as THM{...} or HTB{...}.`,
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.SetOut(a.stdout)
	root.SetErr(a.stderr)

	f := root.PersistentFlags()
	f.StringVarP(&a.opts.outDir, "out", "o", "", "output directory for artifacts (default ./<file>_steg/)")
	f.BoolVar(&a.opts.jsonOut, "json", false, "machine-readable JSON output on stdout")
	f.StringArrayVar(&a.opts.flagFormats, "flag-format", nil, "additional flag regex (repeatable)")
	f.BoolVar(&a.opts.stopOnFlag, "stop-on-flag", false, "stop at the first flag found")
	f.IntVar(&a.opts.depth, "depth", 3, "maximum recursion depth into extracted data")
	f.StringVarP(&a.opts.wordlist, "wordlist", "w", "", "wordlist for password attacks")
	f.IntVarP(&a.opts.jobs, "jobs", "j", runtime.NumCPU(), "number of analyzers running in parallel")
	f.BoolVarP(&a.opts.verbose, "verbose", "v", false, "show all findings and full details")
	f.BoolVarP(&a.opts.quiet, "quiet", "q", false, "print only flags")
	f.BoolVar(&a.opts.noColor, "no-color", false, "disable colored output")
	root.MarkFlagsMutuallyExclusive("verbose", "quiet")

	root.AddCommand(newScanCmd(a), newVersionCmd(a))
	return root
}

// Execute runs the CLI and returns the process exit code.
func Execute(args []string, stdout, stderr io.Writer) int {
	a := &app{stdout: stdout, stderr: stderr}
	root := newRootCmd(a)
	root.SetArgs(args)
	if err := root.Execute(); err != nil {
		var ue usageError
		if errors.As(err, &ue) {
			fmt.Fprintf(stderr, "Error: %v\nRun '%s --help' for usage.\n", err, root.CommandPath())
		} else {
			fmt.Fprintf(stderr, "Error: %v\n", err)
		}
		return ExitError
	}
	return a.exitCode
}

// usageError marks errors caused by wrong invocation.
type usageError struct{ error }

// colorEnabled follows the NO_COLOR convention and disables colors when
// the output is not a terminal.
func (a *app) colorEnabled() bool {
	if a.opts.noColor || os.Getenv("NO_COLOR") != "" {
		return false
	}
	f, ok := a.stdout.(*os.File)
	if !ok {
		return false
	}
	st, err := f.Stat()
	return err == nil && st.Mode()&os.ModeCharDevice != 0
}
