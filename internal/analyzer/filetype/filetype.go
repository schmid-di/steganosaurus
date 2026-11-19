// Package filetype reports the detected file type and flags files whose
// extension does not match their content (a classic CTF trick).
package filetype

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/schmid-di/steganosaurus/internal/detect"
	"github.com/schmid-di/steganosaurus/internal/engine"
)

// Analyzer implements engine.Analyzer.
type Analyzer struct{}

// New returns the file type analyzer.
func New() *Analyzer { return &Analyzer{} }

// Name implements engine.Analyzer.
func (*Analyzer) Name() string { return "filetype" }

// Supports implements engine.Analyzer. It applies to every input.
func (*Analyzer) Supports(detect.FileType) bool { return true }

// Analyze implements engine.Analyzer.
func (*Analyzer) Analyze(_ context.Context, in *engine.Input) ([]engine.Finding, error) {
	if in.Type == detect.Unknown {
		return []engine.Finding{{
			Title:  "Unknown file type",
			Detail: "No known magic bytes at the start of the data. The header may be corrupted or the data may be encoded.",
			Score:  engine.ScoreLow,
		}}, nil
	}

	out := []engine.Finding{{
		Title: "File type: " + strings.ToUpper(string(in.Type)),
		Score: engine.ScoreInfo,
	}}
	if detect.ExtensionMismatch(in.Type, in.Name) {
		out = append(out, engine.Finding{
			Title: fmt.Sprintf("Extension %q does not match content (%s)",
				filepath.Ext(in.Name), strings.ToUpper(string(in.Type))),
			Detail: fmt.Sprintf("The file is actually %s. Try opening it with a matching tool or extension (%s).",
				strings.ToUpper(string(in.Type)), strings.Join(in.Type.Extensions(), ", ")),
			Score: engine.ScoreMedium,
		})
	}
	return out, nil
}
