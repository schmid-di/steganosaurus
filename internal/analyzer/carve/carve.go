// Package carve finds and extracts embedded or appended files: data hidden
// after a file's real end (after PNG IEND, JPEG EOI, …), files concatenated
// together and the contents of archives. Extracted data is returned as
// artifacts so the engine scans it recursively.
package carve

import (
	"bytes"
	"context"
	"fmt"
	"strings"

	"github.com/schmid-di/steganosaurus/internal/detect"
	"github.com/schmid-di/steganosaurus/internal/engine"
)

// Limits guarding against decompression bombs and pathological inputs.
const (
	maxEntrySize    = 100 << 20 // 100 MiB per extracted file
	maxArchiveFiles = 2000
	maxCarved       = 200 // embedded files reported per input
	minCarveSize    = 16  // ignore tiny signature coincidences
)

// Analyzer implements engine.Analyzer.
type Analyzer struct{}

// New returns the carving analyzer.
func New() *Analyzer { return &Analyzer{} }

// Name implements engine.Analyzer.
func (*Analyzer) Name() string { return "carve" }

// Supports implements engine.Analyzer. Carving applies to every input.
func (*Analyzer) Supports(detect.FileType) bool { return true }

// Analyze implements engine.Analyzer.
func (a *Analyzer) Analyze(ctx context.Context, in *engine.Input) ([]engine.Finding, error) {
	var out []engine.Finding

	// 1. Trailing data after the host file's declared end.
	if trailing := a.trailing(in); trailing != nil {
		out = append(out, trailing...)
	}

	// 2. Signature scan for files embedded anywhere in the data. The host
	//    file itself (offset 0) and its trailer (handled above) are skipped.
	out = append(out, a.embedded(ctx, in)...)

	// 3. Archive contents.
	if arc := archiveEntries(ctx, in); arc != nil {
		out = append(out, arc...)
	}
	return out, nil
}

// trailing reports data after the host file's real end.
func (a *Analyzer) trailing(in *engine.Input) []engine.Finding {
	sig, ok := signatureFor(in.Type)
	if !ok {
		return nil
	}
	end := sig.end(in.Data)
	if end <= 0 || end >= len(in.Data) {
		return nil
	}
	extra := in.Data[end:]
	// Ignore a short run of padding zeros.
	if bytes.Count(extra, []byte{0}) == len(extra) {
		return nil
	}
	if len(extra) < minCarveSize && detect.Detect(extra) == detect.Unknown {
		return nil
	}
	childType := detect.Detect(extra)
	name, score, detail := "trailing.bin", 60, fmt.Sprintf(
		"%d bytes follow the %s data (which ends at offset 0x%X). Data after a file's real end is a very common hiding place.",
		len(extra), bold(in.Type), end)
	if childType != detect.Unknown {
		name = "trailing." + extName(childType)
		score = 75
		detail = fmt.Sprintf("A %s file is appended after the %s data (host ends at offset 0x%X).",
			bold(childType), bold(in.Type), end)
	}
	return []engine.Finding{{
		Title:    fmt.Sprintf("Appended data after %s end (%d bytes)", bold(in.Type), len(extra)),
		Detail:   detail,
		Score:    score,
		Location: fmt.Sprintf("offset 0x%X", end),
		Artifact: &engine.Artifact{Name: name, Data: bytes.Clone(extra)},
	}}
}

// embedded scans for file signatures beyond the start of the data.
func (a *Analyzer) embedded(ctx context.Context, in *engine.Input) []engine.Finding {
	var out []engine.Finding
	found := 0
	// Everything at or beyond the host's real end is already reported as
	// trailing data (and scanned recursively), so stop the signature scan
	// there to avoid reporting the same bytes twice.
	limit := len(in.Data)
	if sig, ok := signatureFor(in.Type); ok {
		if end := sig.end(in.Data); end > 0 && end < limit {
			limit = end
		}
	}
	for _, sig := range signatures {
		if found >= maxCarved {
			break
		}
		search := 1
		for found < maxCarved && search < len(in.Data) {
			if ctx.Err() != nil {
				return out
			}
			rel := bytes.Index(in.Data[search:], sig.magic)
			if rel < 0 {
				break
			}
			pos := search + rel
			search = pos + 1
			start := pos - sig.back
			if start <= 0 || start >= limit {
				continue
			}
			if f, adv := a.tryCarve(in, sig, start); f != nil {
				out = append(out, *f)
				found++
				if adv > start {
					search = adv
				}
			}
		}
	}
	return out
}

// tryCarve validates a candidate embedded file at start. It returns a
// finding and the offset past the carved file (to skip its interior).
func (a *Analyzer) tryCarve(in *engine.Input, sig signature, start int) (*engine.Finding, int) {
	region := in.Data[start:]
	if detect.Detect(region) != sig.typ {
		return nil, 0 // magic matched by chance mid-stream
	}
	n := sig.end(region)
	if n < 0 {
		if sig.strict {
			return nil, 0
		}
		n = len(region)
	}
	if n < minCarveSize || n > len(region) {
		return nil, 0
	}
	data := bytes.Clone(region[:n])
	return &engine.Finding{
		Title:    fmt.Sprintf("Embedded %s (%d bytes)", bold(sig.typ), n),
		Detail:   fmt.Sprintf("A %s file is embedded at offset 0x%X inside the %s data.", bold(sig.typ), start, bold(in.Type)),
		Score:    65,
		Location: fmt.Sprintf("offset 0x%X", start),
		Artifact: &engine.Artifact{Name: fmt.Sprintf("embedded_0x%X.%s", start, sig.ext), Data: data},
	}, start + n
}

func extName(t detect.FileType) string {
	if sig, ok := signatureFor(t); ok {
		return sig.ext
	}
	return "bin"
}

func bold(t detect.FileType) string { return strings.ToUpper(string(t)) }
