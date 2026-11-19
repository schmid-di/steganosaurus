// Package report renders scan results for terminals and machines and writes
// artifacts to disk. It is the only place with output side effects.
package report

import (
	"encoding/json"
	"io"

	"github.com/schmid-di/steganosaurus/internal/engine"
)

// SchemaVersion is incremented on incompatible changes to the JSON output.
const SchemaVersion = 1

// Document is the top-level JSON output.
type Document struct {
	SchemaVersion int    `json:"schema_version"`
	Tool          string `json:"tool"`
	Version       string `json:"version"`
	*engine.Result
	DurationMS float64 `json:"duration_ms"`
}

// NewDocument wraps a result for JSON output.
func NewDocument(res *engine.Result, version string) Document {
	return Document{
		SchemaVersion: SchemaVersion,
		Tool:          "steganosaurus",
		Version:       version,
		Result:        res,
		DurationMS:    float64(res.Duration.Microseconds()) / 1000,
	}
}

// WriteJSON writes res as indented JSON.
func WriteJSON(w io.Writer, res *engine.Result, version string) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(NewDocument(res, version))
}
