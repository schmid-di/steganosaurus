package engine

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/schmid-di/steganosaurus/internal/detect"
	"github.com/schmid-di/steganosaurus/internal/flag"
)

// unwrap simulates nested containers: data after a "WRAP:" prefix is stored
// with every byte incremented, so the payload is only readable after
// unwrapping each level.
type unwrap struct{ calls atomic.Int32 }

func (*unwrap) Name() string                  { return "unwrap" }
func (*unwrap) Supports(detect.FileType) bool { return true }
func (u *unwrap) Analyze(_ context.Context, in *Input) ([]Finding, error) {
	u.calls.Add(1)
	rest, ok := bytes.CutPrefix(in.Data, []byte("WRAP:"))
	if !ok {
		return nil, nil
	}
	inner := make([]byte, len(rest))
	for i, b := range rest {
		inner[i] = b - 1
	}
	return []Finding{{Title: "wrapped data", Score: ScoreMedium, Artifact: &Artifact{Name: "inner.bin", Data: inner}}}, nil
}

// wrap is the inverse of unwrap, applied n times.
func wrap(s string, n int) []byte {
	data := []byte(s)
	for range n {
		next := []byte("WRAP:")
		for _, b := range data {
			next = append(next, b+1)
		}
		data = next
	}
	return data
}

// static returns fixed findings.
type static struct {
	name     string
	findings []Finding
	err      error
}

func (s *static) Name() string                { return s.name }
func (*static) Supports(detect.FileType) bool { return true }
func (s *static) Analyze(context.Context, *Input) ([]Finding, error) {
	// Return copies so the engine may modify them.
	return slices.Clone(s.findings), s.err
}

type panicker struct{}

func (panicker) Name() string                                       { return "panicker" }
func (panicker) Supports(detect.FileType) bool                      { return true }
func (panicker) Analyze(context.Context, *Input) ([]Finding, error) { panic("boom") }

func newEngine(t *testing.T, opts Options, as ...Analyzer) *Engine {
	t.Helper()
	m, err := flag.NewMatcher()
	if err != nil {
		t.Fatal(err)
	}
	opts.Matcher = m
	return New(opts, as...)
}

func TestRecursionAndProvenance(t *testing.T) {
	e := newEngine(t, Options{MaxDepth: 5}, &unwrap{})
	res, err := e.Run(context.Background(), "chall.png", wrap("THM{deep}", 3))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Flags) != 1 || res.Flags[0].Value != "THM{deep}" {
		t.Fatalf("flags = %+v", res.Flags)
	}
	want := []string{"chall.png", "unwrap:inner.bin", "unwrap:inner.bin", "unwrap:inner.bin"}
	if !slices.Equal(res.Flags[0].Provenance, want) {
		t.Errorf("provenance = %q, want %q", res.Flags[0].Provenance, want)
	}
	if len(res.Artifacts) != 3 {
		t.Errorf("artifacts = %d, want 3", len(res.Artifacts))
	}
	for i, a := range res.Artifacts {
		if a.Seq != i+1 || a.SHA256 == "" || a.Size != len(a.Data) {
			t.Errorf("artifact %d not filled in: %+v", i, a)
		}
	}
	if res.Inputs != 4 {
		t.Errorf("inputs = %d, want 4", res.Inputs)
	}
}

func TestDepthLimitStillFindsFlags(t *testing.T) {
	u := &unwrap{}
	e := newEngine(t, Options{MaxDepth: 1}, u)
	res, err := e.Run(context.Background(), "x", wrap("HTB{limit}", 3))
	if err != nil {
		t.Fatal(err)
	}
	// Depth 0 and 1 are analyzed, depth 2 is only flag-scanned.
	if got := u.calls.Load(); got != 2 {
		t.Errorf("analyzer calls = %d, want 2", got)
	}
	if len(res.Flags) != 0 {
		t.Errorf("flag at depth 3 must not be reached with MaxDepth 1, got %+v", res.Flags)
	}

	res, _ = newEngine(t, Options{MaxDepth: 1}, &unwrap{}).Run(context.Background(), "x", wrap("HTB{edge}", 2))
	if len(res.Flags) != 1 {
		t.Errorf("flag in artifact beyond depth limit should still be found, got %+v", res.Flags)
	}
}

func TestArtifactDedup(t *testing.T) {
	art := func() *Artifact { return &Artifact{Name: "same.bin", Data: []byte("payload")} }
	a := &static{name: "a", findings: []Finding{{Title: "a", Artifact: art()}}}
	b := &static{name: "b", findings: []Finding{{Title: "b", Artifact: art()}}}
	res, err := newEngine(t, Options{}, a, b).Run(context.Background(), "x", []byte("root"))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Artifacts) != 1 {
		t.Errorf("artifacts = %d, want 1", len(res.Artifacts))
	}
}

func TestArtifactEqualToRootIsDropped(t *testing.T) {
	a := &static{name: "a", findings: []Finding{{Title: "self", Artifact: &Artifact{Name: "self", Data: []byte("root")}}}}
	res, _ := newEngine(t, Options{}, a).Run(context.Background(), "x", []byte("root"))
	if len(res.Artifacts) != 0 || res.Findings[0].Artifact != nil {
		t.Errorf("artifact identical to root should be dropped: %+v", res)
	}
}

func TestErrorsAndPanicsAreRecorded(t *testing.T) {
	failing := &static{name: "failing", err: errors.New("bad chunk")}
	ok := &static{name: "ok", findings: []Finding{{Title: "still works", Score: ScoreLow}}}
	res, err := newEngine(t, Options{}, failing, panicker{}, ok).Run(context.Background(), "x", []byte("data"))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Errors) != 2 {
		t.Fatalf("errors = %+v, want 2", res.Errors)
	}
	if !strings.Contains(res.Errors[1].Error, "panic: boom") {
		t.Errorf("panic not recorded: %+v", res.Errors[1])
	}
	if len(res.Findings) != 1 || res.Findings[0].Title != "still works" {
		t.Errorf("findings = %+v", res.Findings)
	}
}

func TestFlagsInFindingTextAndScoring(t *testing.T) {
	a := &static{name: "meta", findings: []Finding{
		{Title: "boring", Score: ScoreInfo},
		{Title: "EXIF comment", Detail: "flag{in_exif}", Score: ScoreLow},
		{Title: "out of range", Score: 500},
	}}
	res, _ := newEngine(t, Options{}, a).Run(context.Background(), "x", []byte("data"))
	if len(res.Flags) != 1 || res.Flags[0].Analyzer != "meta" {
		t.Fatalf("flags = %+v", res.Flags)
	}
	scores := []int{}
	for _, f := range res.Findings {
		scores = append(scores, f.Score)
	}
	if !slices.Equal(scores, []int{100, 100, 5}) {
		t.Errorf("scores = %v, want sorted and clamped [100 100 5]", scores)
	}
	if res.Findings[0].Title != "EXIF comment" {
		t.Errorf("stable sort expected flag finding first, got %q", res.Findings[0].Title)
	}
}

func TestStopOnFlag(t *testing.T) {
	u := &unwrap{}
	res, err := newEngine(t, Options{StopOnFlag: true}, u).Run(context.Background(), "x", []byte("CTF{early} WRAP:"))
	if err != nil {
		t.Fatalf("stop on flag must not be an error: %v", err)
	}
	if !res.Stopped {
		t.Error("expected Stopped")
	}
	if u.calls.Load() != 0 {
		t.Error("analyzers should not run after a raw flag hit")
	}
}

func TestParentCancellationIsReported(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := newEngine(t, Options{}, &unwrap{}).Run(ctx, "x", []byte("data"))
	if !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want context.Canceled", err)
	}
}

func TestSanitizeName(t *testing.T) {
	tests := map[string]string{
		"../../etc/passwd": "_.._etc_passwd",
		"a\\b:c":           "a_b_c",
		"":                 "artifact.bin",
		"..":               "artifact.bin",
		"ok.zip":           "ok.zip",
	}
	for in, want := range tests {
		if got := sanitizeName(in); got != want {
			t.Errorf("sanitizeName(%q) = %q, want %q", in, got, want)
		}
	}
}
