package report

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/schmid-di/steganosaurus/internal/engine"
)

// ReportFile is the name of the JSON report inside the output directory.
const ReportFile = "report.json"

// WriteOutputDir writes all artifacts of res to dir, sets their Path and
// stores report.json next to them. The scanned file itself is never touched.
func WriteOutputDir(dir string, res *engine.Result, version string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create output directory: %w", err)
	}
	for _, a := range res.Artifacts {
		p := filepath.Join(dir, ArtifactFileName(a))
		if err := os.WriteFile(p, a.Data, 0o644); err != nil {
			return fmt.Errorf("write artifact: %w", err)
		}
		a.Path = p
	}

	f, err := os.Create(filepath.Join(dir, ReportFile))
	if err != nil {
		return fmt.Errorf("write report: %w", err)
	}
	if err := WriteJSON(f, res, version); err != nil {
		f.Close()
		return fmt.Errorf("write report: %w", err)
	}
	return f.Close()
}

// ArtifactFileName names an artifact after its sequence number and origin,
// e.g. "003_lsb_b0_rgb_lsb.bin".
func ArtifactFileName(a *engine.Artifact) string {
	return fmt.Sprintf("%03d_%s_%s", a.Seq, a.Analyzer, a.Name)
}
