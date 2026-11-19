package engine

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"runtime"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/schmid-di/steganosaurus/internal/detect"
	"github.com/schmid-di/steganosaurus/internal/flag"
)

// Options configures a scan.
type Options struct {
	// MaxDepth limits recursion into artifacts. Inputs deeper than MaxDepth
	// are still searched for flags but not handed to analyzers.
	MaxDepth int
	// Jobs is the number of analyzers running concurrently (default: NumCPU).
	Jobs int
	// StopOnFlag cancels the scan as soon as a flag is found.
	StopOnFlag bool
	// Matcher finds flags. Required.
	Matcher *flag.Matcher
}

// Engine runs a set of analyzers.
type Engine struct {
	opts      Options
	analyzers []Analyzer
}

// New returns an engine using the given analyzers.
func New(opts Options, analyzers ...Analyzer) *Engine {
	if opts.Jobs <= 0 {
		opts.Jobs = runtime.NumCPU()
	}
	if opts.MaxDepth < 0 {
		opts.MaxDepth = 0
	}
	return &Engine{opts: opts, analyzers: analyzers}
}

// task is one analyzer applied to one input.
type task struct {
	in       *Input
	a        Analyzer
	findings []Finding
	err      error
}

// scan holds the mutable state of a single Run.
type scan struct {
	e         *Engine
	res       *Result
	cancel    context.CancelFunc
	rootHash  string
	artifacts map[string]*Artifact // by SHA-256
	flags     map[string]bool
}

// Run analyzes data, recursing breadth-first into extracted artifacts.
// Analyzer failures are recorded in Result.Errors and never abort the scan.
func (e *Engine) Run(ctx context.Context, name string, data []byte) (*Result, error) {
	if e.opts.Matcher == nil {
		return nil, fmt.Errorf("engine: no flag matcher configured")
	}
	start := time.Now()
	parent := ctx
	ctx, cancel := context.WithCancel(parent)
	defer cancel()

	rootHash := hash(data)
	root := &Input{Name: name, Data: data, Type: detect.Detect(data), Provenance: []string{name}, Matcher: e.opts.Matcher}
	s := &scan{
		e:        e,
		cancel:   cancel,
		rootHash: rootHash,
		res: &Result{
			Target:    Target{Name: name, Size: len(data), Type: root.Type, SHA256: rootHash},
			Flags:     []FlagHit{},
			Findings:  []Finding{},
			Artifacts: []*Artifact{},
		},
		artifacts: map[string]*Artifact{},
		flags:     map[string]bool{},
	}

	for level := []*Input{root}; len(level) > 0 && ctx.Err() == nil; {
		level = s.runLevel(ctx, level)
	}

	// A cancelled parent (e.g. Ctrl+C) is reported; stopping on a flag is not an error.
	return s.finish(start), parent.Err()
}

// runLevel analyzes all inputs of one recursion level and returns the
// inputs of the next level.
func (s *scan) runLevel(ctx context.Context, level []*Input) []*Input {
	var tasks []*task
	for _, in := range level {
		s.res.Inputs++
		s.rawFlagScan(in)
		if in.Depth > s.e.opts.MaxDepth {
			continue
		}
		for _, a := range s.e.analyzers {
			if a.Supports(in.Type) {
				tasks = append(tasks, &task{in: in, a: a})
			}
		}
	}
	if ctx.Err() != nil {
		return nil
	}

	s.execute(ctx, tasks)

	var next []*Input
	for _, t := range tasks {
		if t.err != nil {
			s.res.Errors = append(s.res.Errors, AnalyzerError{
				Analyzer: t.a.Name(), Provenance: t.in.Provenance, Error: t.err.Error(),
			})
		}
		for _, f := range t.findings {
			if child := s.collect(t.in, t.a, f); child != nil {
				next = append(next, child)
			}
		}
	}
	return next
}

// execute runs tasks concurrently, limited to Options.Jobs.
func (s *scan) execute(ctx context.Context, tasks []*task) {
	sem := make(chan struct{}, s.e.opts.Jobs)
	var wg sync.WaitGroup
	for _, t := range tasks {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			if ctx.Err() != nil {
				return
			}
			t.findings, t.err = safeAnalyze(ctx, t.a, t.in)
			if s.e.opts.StopOnFlag && s.containsFlag(t.findings) {
				s.cancel()
			}
		}()
	}
	wg.Wait()
}

// safeAnalyze turns analyzer panics into errors so that one broken parser
// cannot take down the whole scan.
func safeAnalyze(ctx context.Context, a Analyzer, in *Input) (fs []Finding, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic: %v", r)
		}
	}()
	return a.Analyze(ctx, in)
}

func (s *scan) containsFlag(fs []Finding) bool {
	for _, f := range fs {
		if len(f.Flags) > 0 || len(s.e.opts.Matcher.FindString(f.Title+"\n"+f.Detail)) > 0 {
			return true
		}
		if f.Artifact != nil && len(s.e.opts.Matcher.Find(f.Artifact.Data)) > 0 {
			return true
		}
	}
	return false
}

// rawFlagScan searches the raw bytes of an input for flags.
func (s *scan) rawFlagScan(in *Input) {
	for _, m := range s.e.opts.Matcher.Locate(in.Data) {
		loc := fmt.Sprintf("offset 0x%X", m.Offset)
		s.res.Findings = append(s.res.Findings, Finding{
			Analyzer:   "flag",
			Title:      "Flag in raw data",
			Detail:     m.Value,
			Score:      ScoreFlag,
			Location:   loc,
			Flags:      []string{m.Value},
			Provenance: in.Provenance,
		})
		s.addFlag(m.Value, "flag", loc, in.Provenance)
	}
}

// collect post-processes a finding and returns a new input if the finding
// carries a previously unseen artifact.
func (s *scan) collect(in *Input, a Analyzer, f Finding) *Input {
	f.Analyzer = a.Name()
	f.Provenance = in.Provenance
	f.Score = min(max(f.Score, 0), ScoreFlag)

	for _, v := range s.e.opts.Matcher.FindString(f.Title + "\n" + f.Detail) {
		if !slices.Contains(f.Flags, v) {
			f.Flags = append(f.Flags, v)
		}
	}
	for _, v := range f.Flags {
		s.addFlag(v, f.Analyzer, f.Location, in.Provenance)
	}
	if len(f.Flags) > 0 {
		f.Score = ScoreFlag
	}

	var child *Input
	if f.Artifact != nil {
		h := hash(f.Artifact.Data)
		if h == s.rootHash {
			// Extracting the scanned file itself; nothing new to look at.
			f.Artifact = nil
		} else if existing, ok := s.artifacts[h]; ok {
			f.Artifact = existing
		} else {
			art := f.Artifact
			art.Seq = len(s.res.Artifacts) + 1
			art.Analyzer = f.Analyzer
			art.Name = sanitizeName(art.Name)
			art.Size = len(art.Data)
			art.SHA256 = h
			art.Type = detect.Detect(art.Data)
			s.artifacts[h] = art
			s.res.Artifacts = append(s.res.Artifacts, art)
			child = &Input{
				Name:       art.Name,
				Data:       art.Data,
				Type:       art.Type,
				Depth:      in.Depth + 1,
				Provenance: append(slices.Clone(in.Provenance), f.Analyzer+":"+art.Name),
				Matcher:    in.Matcher,
			}
		}
	}
	s.res.Findings = append(s.res.Findings, f)
	return child
}

func (s *scan) addFlag(v, analyzer, loc string, prov []string) {
	if s.flags[v] {
		return
	}
	s.flags[v] = true
	s.res.Flags = append(s.res.Flags, FlagHit{Value: v, Analyzer: analyzer, Location: loc, Provenance: prov})
	if s.e.opts.StopOnFlag {
		s.res.Stopped = true
		s.cancel()
	}
}

func (s *scan) finish(start time.Time) *Result {
	slices.SortStableFunc(s.res.Findings, func(a, b Finding) int { return b.Score - a.Score })
	s.res.Duration = time.Since(start)
	return s.res
}

func hash(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// sanitizeName makes an analyzer-provided artifact name safe to use as a
// file name: no path separators, no control characters, bounded length.
func sanitizeName(name string) string {
	name = strings.Map(func(r rune) rune {
		switch {
		case r == '/' || r == '\\' || r == ':' || r < 0x20 || r == 0x7f:
			return '_'
		}
		return r
	}, name)
	name = strings.Trim(name, ". ")
	if len(name) > 100 {
		name = strings.ToValidUTF8(name[:100], "")
	}
	if name == "" {
		name = "artifact.bin"
	}
	return name
}
