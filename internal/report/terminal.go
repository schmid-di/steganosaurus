package report

import (
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/schmid-di/steganosaurus/internal/engine"
)

// TermOptions controls the human-readable output.
type TermOptions struct {
	Color     bool
	Verbose   bool // show all findings and full details
	Quiet     bool // print only flags, one per line
	Threshold int  // findings below this score are hidden unless Verbose
	OutDir    string
}

// DefaultThreshold hides purely informational findings.
const DefaultThreshold = engine.ScoreLow

const maxDetailLines = 6

type painter struct{ on bool }

func (p painter) wrap(code, s string) string {
	if !p.on {
		return s
	}
	return "\x1b[" + code + "m" + s + "\x1b[0m"
}
func (p painter) bold(s string) string   { return p.wrap("1", s) }
func (p painter) dim(s string) string    { return p.wrap("2", s) }
func (p painter) red(s string) string    { return p.wrap("1;31", s) }
func (p painter) green(s string) string  { return p.wrap("1;32", s) }
func (p painter) yellow(s string) string { return p.wrap("33", s) }
func (p painter) cyan(s string) string   { return p.wrap("36", s) }

func (p painter) score(n int) string {
	s := fmt.Sprintf("%3d", n)
	switch {
	case n >= engine.ScoreHigh:
		return p.red(s)
	case n >= engine.ScoreMedium:
		return p.yellow(s)
	case n >= engine.ScoreLow:
		return p.cyan(s)
	}
	return p.dim(s)
}

// WriteTerminal renders res for humans.
func WriteTerminal(w io.Writer, res *engine.Result, o TermOptions) {
	p := painter{on: o.Color}

	if o.Quiet {
		for _, f := range res.Flags {
			fmt.Fprintln(w, f.Value)
		}
		return
	}

	t := res.Target
	fmt.Fprintf(w, "%s %s %s %s %s %s\n\n",
		p.bold("steganosaurus"), p.dim("·"), p.bold(t.Name), p.dim("·"),
		strings.ToUpper(string(t.Type)), p.dim("· "+humanSize(t.Size)+" · sha256 "+t.SHA256[:12]+"…"))

	if len(res.Flags) > 0 {
		fmt.Fprintln(w, p.green(fmt.Sprintf("FLAGS (%d)", len(res.Flags))))
		for _, f := range res.Flags {
			fmt.Fprintf(w, "  %s %s\n", p.green("★"), p.bold(f.Value))
			where := f.Analyzer
			if f.Location != "" {
				where += ", " + f.Location
			}
			fmt.Fprintf(w, "    %s %s\n", chain(p, f.Provenance), p.dim("("+where+")"))
		}
		fmt.Fprintln(w)
	}

	var shown []engine.Finding
	for _, f := range res.Findings {
		if o.Verbose || f.Score >= o.Threshold {
			shown = append(shown, f)
		}
	}
	hidden := len(res.Findings) - len(shown)

	header := fmt.Sprintf("FINDINGS (%d)", len(shown))
	if hidden > 0 {
		header = fmt.Sprintf("FINDINGS (%d of %d, -v shows all)", len(shown), len(res.Findings))
	}
	fmt.Fprintln(w, p.bold(header))
	if len(shown) == 0 {
		fmt.Fprintln(w, p.dim("  No notable findings."))
	}
	for _, f := range shown {
		writeFinding(w, p, f, o.Verbose)
	}

	if len(res.Errors) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, p.yellow(fmt.Sprintf("ANALYZER ERRORS (%d)", len(res.Errors))))
		for _, e := range res.Errors {
			fmt.Fprintf(w, "  %s on %s: %s\n", e.Analyzer, chain(p, e.Provenance), e.Error)
		}
	}

	fmt.Fprintln(w)
	summary := fmt.Sprintf("Analyzed %d %s in %s · %d %s · %d %s",
		res.Inputs, plural(res.Inputs, "input", "inputs"), humanDuration(res.Duration),
		len(res.Flags), plural(len(res.Flags), "flag", "flags"),
		len(res.Artifacts), plural(len(res.Artifacts), "artifact", "artifacts"))
	if res.Stopped {
		summary += " · stopped at first flag"
	}
	fmt.Fprintln(w, summary)
	if o.OutDir != "" {
		fmt.Fprintf(w, "Output: %s\n", o.OutDir)
	}
}

func writeFinding(w io.Writer, p painter, f engine.Finding, verbose bool) {
	const indent = "             "
	fmt.Fprintf(w, "  %s  %-9s %s\n", p.score(f.Score), f.Analyzer, f.Title)

	var meta []string
	if len(f.Provenance) > 1 {
		meta = append(meta, "in "+f.Provenance[len(f.Provenance)-1])
	}
	if f.Location != "" {
		meta = append(meta, f.Location)
	}
	if len(meta) > 0 {
		fmt.Fprintln(w, indent+p.dim(strings.Join(meta, " · ")))
	}

	if f.Detail != "" {
		lines := strings.Split(strings.TrimRight(f.Detail, "\n"), "\n")
		if !verbose && len(lines) > maxDetailLines {
			more := len(lines) - maxDetailLines
			lines = append(lines[:maxDetailLines], p.dim(fmt.Sprintf("… %d more lines (-v)", more)))
		}
		for _, l := range lines {
			fmt.Fprintln(w, indent+l)
		}
	}
	if f.Artifact != nil {
		target := f.Artifact.Path
		if target == "" {
			target = ArtifactFileName(f.Artifact)
		}
		fmt.Fprintf(w, "%s%s %s\n", indent, p.cyan("→"), target)
	}
}

func chain(p painter, prov []string) string {
	return strings.Join(prov, p.dim(" › "))
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

func humanDuration(d time.Duration) string {
	if d < time.Millisecond {
		return d.Round(time.Microsecond).String()
	}
	return d.Round(time.Millisecond).String()
}

func humanSize(n int) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := unit, 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}
