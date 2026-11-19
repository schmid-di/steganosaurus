// Package analyzer holds the registry of all built-in analyzers. Each
// analyzer lives in its own sub-package and implements engine.Analyzer.
package analyzer

import (
	"github.com/schmid-di/steganosaurus/internal/analyzer/filetype"
	"github.com/schmid-di/steganosaurus/internal/engine"
)

// All returns every built-in analyzer used by `steganosaurus scan`.
func All() []engine.Analyzer {
	return []engine.Analyzer{
		filetype.New(),
	}
}
