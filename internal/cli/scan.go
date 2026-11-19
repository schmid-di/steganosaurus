package cli

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/schmid-di/steganosaurus/internal/analyzer"
	"github.com/schmid-di/steganosaurus/internal/engine"
	"github.com/schmid-di/steganosaurus/internal/flag"
	"github.com/schmid-di/steganosaurus/internal/report"
)

func newScanCmd(a *app) *cobra.Command {
	return &cobra.Command{
		Use:   "scan <file>",
		Short: "Triage a file with all applicable analyses",
		Example: `  steganosaurus scan challenge.png
  steganosaurus scan -q --stop-on-flag image.jpg
  steganosaurus scan --flag-format 'DUCTF\{[^}]+\}' --json audio.wav`,
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				return usageError{fmt.Errorf("scan expects exactly one file, got %d", len(args))}
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			return a.runScan(cmd.Context(), args[0])
		},
	}
}

func (a *app) runScan(ctx context.Context, path string) error {
	matcher, err := flag.NewMatcher(a.opts.flagFormats...)
	if err != nil {
		return usageError{err}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	if ctx == nil {
		ctx = context.Background()
	}
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt)
	defer stop()

	eng := engine.New(engine.Options{
		MaxDepth:   a.opts.depth,
		Jobs:       a.opts.jobs,
		StopOnFlag: a.opts.stopOnFlag,
		Matcher:    matcher,
	}, analyzer.All()...)

	res, runErr := eng.Run(ctx, filepath.Base(path), data)
	if res == nil {
		return runErr
	}

	outDir := a.opts.outDir
	if outDir == "" {
		outDir = filepath.Base(path) + "_steg"
	}
	if err := report.WriteOutputDir(outDir, res, Version()); err != nil {
		return err
	}

	if a.opts.jsonOut {
		if err := report.WriteJSON(a.stdout, res, Version()); err != nil {
			return err
		}
	} else {
		report.WriteTerminal(a.stdout, res, report.TermOptions{
			Color:     a.colorEnabled(),
			Verbose:   a.opts.verbose,
			Quiet:     a.opts.quiet,
			Threshold: report.DefaultThreshold,
			OutDir:    outDir + string(filepath.Separator),
		})
	}

	if runErr != nil {
		return fmt.Errorf("scan interrupted: %w", runErr)
	}
	if len(res.Flags) > 0 {
		a.exitCode = ExitFlagFound
	}
	return nil
}
