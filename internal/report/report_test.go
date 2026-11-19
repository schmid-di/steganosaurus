package report

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/schmid-di/steganosaurus/internal/detect"
	"github.com/schmid-di/steganosaurus/internal/engine"
)

func sampleResult() *engine.Result {
	art := &engine.Artifact{Seq: 1, Analyzer: "carve", Name: "hidden.zip", Type: detect.ZIP, Size: 3, SHA256: "abc", Data: []byte("zip")}
	prov := []string{"chall.png"}
	return &engine.Result{
		Target: engine.Target{Name: "chall.png", Size: 2048, Type: detect.PNG, SHA256: strings.Repeat("ab", 32)},
		Flags:  []engine.FlagHit{{Value: "THM{x}", Analyzer: "flag", Location: "offset 0x10", Provenance: prov}},
		Findings: []engine.Finding{
			{Analyzer: "flag", Title: "Flag in raw data", Detail: "THM{x}", Score: 100, Provenance: prov},
			{Analyzer: "carve", Title: "ZIP after IEND", Score: 80, Artifact: art, Provenance: prov},
			{Analyzer: "filetype", Title: "File type: PNG", Score: 5, Provenance: prov},
		},
		Artifacts: []*engine.Artifact{art},
		Inputs:    2,
		Duration:  1500 * time.Microsecond,
	}
}

func TestJSON(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteJSON(&buf, sampleResult(), "test"); err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if doc["schema_version"] != float64(SchemaVersion) || doc["tool"] != "steganosaurus" || doc["duration_ms"] != 1.5 {
		t.Errorf("header fields wrong: %v", doc)
	}
	for _, key := range []string{"target", "flags", "findings", "artifacts", "inputs_analyzed"} {
		if _, ok := doc[key]; !ok {
			t.Errorf("missing key %q", key)
		}
	}
	if strings.Contains(buf.String(), `"Data"`) {
		t.Error("artifact data must not be serialized")
	}
}

func TestWriteOutputDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "out")
	res := sampleResult()
	if err := WriteOutputDir(dir, res, "test"); err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(dir, "001_carve_hidden.zip")
	if res.Artifacts[0].Path != want {
		t.Errorf("path = %q, want %q", res.Artifacts[0].Path, want)
	}
	if b, err := os.ReadFile(want); err != nil || string(b) != "zip" {
		t.Errorf("artifact content = %q, %v", b, err)
	}
	if _, err := os.Stat(filepath.Join(dir, ReportFile)); err != nil {
		t.Error(err)
	}
}

func TestTerminal(t *testing.T) {
	var buf bytes.Buffer
	WriteTerminal(&buf, sampleResult(), TermOptions{Threshold: DefaultThreshold, OutDir: "out/"})
	out := buf.String()
	for _, want := range []string{"FLAGS (1)", "THM{x}", "FINDINGS (2 of 3, -v shows all)", "ZIP after IEND", "→ 001_carve_hidden.zip", "Output: out/"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "File type: PNG") {
		t.Error("informational finding should be hidden without -v")
	}
	if strings.Contains(out, "\x1b[") {
		t.Error("no ANSI codes expected when color is off")
	}
}

func TestTerminalVerboseAndQuiet(t *testing.T) {
	var buf bytes.Buffer
	WriteTerminal(&buf, sampleResult(), TermOptions{Verbose: true, Color: true})
	if !strings.Contains(buf.String(), "File type: PNG") || !strings.Contains(buf.String(), "\x1b[") {
		t.Error("verbose colored output expected")
	}

	buf.Reset()
	WriteTerminal(&buf, sampleResult(), TermOptions{Quiet: true})
	if buf.String() != "THM{x}\n" {
		t.Errorf("quiet output = %q", buf.String())
	}
}

func TestHumanSize(t *testing.T) {
	for n, want := range map[int]string{0: "0 B", 1023: "1023 B", 1024: "1.0 KiB", 1536: "1.5 KiB", 5 << 20: "5.0 MiB"} {
		if got := humanSize(n); got != want {
			t.Errorf("humanSize(%d) = %q, want %q", n, got, want)
		}
	}
}
