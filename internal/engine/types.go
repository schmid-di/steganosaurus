// Package engine schedules analyzers, recurses into extracted artifacts,
// tracks provenance and collects findings and flags.
package engine

import (
	"context"
	"time"

	"github.com/schmid-di/steganosaurus/internal/detect"
	"github.com/schmid-di/steganosaurus/internal/flag"
)

// Analyzer inspects one input and reports findings.
//
// Analyzers must be free of side effects (no file system writes) and must be
// safe for concurrent use. Extracted data is returned via Finding.Artifact;
// the engine scans it recursively.
type Analyzer interface {
	// Name is a short identifier such as "meta" or "lsb".
	Name() string
	// Supports reports whether the analyzer applies to the given file type.
	Supports(ft detect.FileType) bool
	// Analyze inspects in. It should honour ctx cancellation for long work.
	Analyze(ctx context.Context, in *Input) ([]Finding, error)
}

// Input is a piece of data to analyze: the scanned file or an artifact.
type Input struct {
	Name       string
	Data       []byte
	Type       detect.FileType
	Depth      int      // 0 for the scanned file
	Provenance []string // chain from the scanned file to this input
	// Matcher is the scan's flag matcher; analyzers may use it to judge
	// candidates (e.g. accept a decoding only if it reveals a flag).
	Matcher *flag.Matcher
}

// HasFlag reports whether b contains a flag according to in.Matcher.
func (in *Input) HasFlag(b []byte) bool {
	return in.Matcher != nil && len(in.Matcher.Find(b)) > 0
}

// Artifact is data extracted by an analyzer. Analyzers set Name and Data;
// the engine fills in the remaining fields.
type Artifact struct {
	Seq      int             `json:"seq"`
	Analyzer string          `json:"analyzer"`
	Name     string          `json:"name"`
	Type     detect.FileType `json:"type"`
	Size     int             `json:"size"`
	SHA256   string          `json:"sha256"`
	Path     string          `json:"path,omitempty"` // set when written to disk
	Data     []byte          `json:"-"`
}

// Finding is a single result of an analyzer.
type Finding struct {
	Analyzer   string    `json:"analyzer"`
	Title      string    `json:"title"`
	Detail     string    `json:"detail,omitempty"`
	Score      int       `json:"score"`              // relevance 0–100
	Location   string    `json:"location,omitempty"` // offset, chunk, LSB parameters …
	Artifact   *Artifact `json:"artifact,omitempty"`
	Flags      []string  `json:"flags,omitempty"`
	Provenance []string  `json:"provenance"`
}

// Score thresholds used across analyzers.
const (
	ScoreInfo   = 5
	ScoreLow    = 20
	ScoreMedium = 50
	ScoreHigh   = 80
	ScoreFlag   = 100
)

// FlagHit is a flag found anywhere during the scan.
type FlagHit struct {
	Value      string   `json:"value"`
	Analyzer   string   `json:"analyzer"`
	Location   string   `json:"location,omitempty"`
	Provenance []string `json:"provenance"`
}

// AnalyzerError records a non-fatal analyzer failure.
type AnalyzerError struct {
	Analyzer   string   `json:"analyzer"`
	Provenance []string `json:"provenance"`
	Error      string   `json:"error"`
}

// Target describes the scanned file.
type Target struct {
	Name   string          `json:"name"`
	Size   int             `json:"size"`
	Type   detect.FileType `json:"type"`
	SHA256 string          `json:"sha256"`
}

// Result is the outcome of a scan.
type Result struct {
	Target    Target          `json:"target"`
	Flags     []FlagHit       `json:"flags"`
	Findings  []Finding       `json:"findings"` // sorted by score, highest first
	Artifacts []*Artifact     `json:"artifacts"`
	Errors    []AnalyzerError `json:"errors,omitempty"`
	Inputs    int             `json:"inputs_analyzed"`
	Stopped   bool            `json:"stopped_early"`
	Duration  time.Duration   `json:"-"`
}
