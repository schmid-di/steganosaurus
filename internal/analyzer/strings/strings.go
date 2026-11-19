// Package strings extracts printable ASCII and UTF-16 strings, decodes
// encoded candidates and highlights strings that look like CTF hints.
package strings

import (
	"bytes"
	"context"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"unicode/utf16"

	"github.com/schmid-di/steganosaurus/internal/analyzer/textutil"
	"github.com/schmid-di/steganosaurus/internal/decode"
	"github.com/schmid-di/steganosaurus/internal/detect"
	"github.com/schmid-di/steganosaurus/internal/engine"
)

// Defaults.
const (
	DefaultMinLen = 6
	// maxTextPreview is the largest text input whose full content is shown.
	maxTextPreview = 4096
	// maxWholeDecode is the largest text input decoded as a whole.
	maxWholeDecode = 1 << 20
	maxListed      = 50
)

// Analyzer implements engine.Analyzer.
type Analyzer struct {
	MinLen int
}

// New returns the strings analyzer with default settings.
func New() *Analyzer { return &Analyzer{MinLen: DefaultMinLen} }

// Name implements engine.Analyzer.
func (*Analyzer) Name() string { return "strings" }

// Supports implements engine.Analyzer. Strings apply to every input.
func (*Analyzer) Supports(detect.FileType) bool { return true }

// String is an extracted string.
type String struct {
	Offset   int
	Value    string
	Encoding string // "ascii", "utf16le", "utf16be"
}

// hint marks strings a challenge author may have left for the player.
var hint = regexp.MustCompile(`(?i)\b(pass(word|wd|phrase)?|secret|flag|hint|hidden|steg\w*|key|user(name)?|login|creds?|credentials?)\b\s*[:=]|(?i)\b(password|passphrase|secret|hidden|steghide|stegseek|outguess|zsteg)\b`)

// Analyze implements engine.Analyzer.
func (a *Analyzer) Analyze(ctx context.Context, in *engine.Input) ([]engine.Finding, error) {
	minLen := a.MinLen
	if minLen <= 0 {
		minLen = DefaultMinLen
	}
	var out []engine.Finding
	dec := textutil.NewDecoder(in)

	// Text inputs (e.g. a note extracted from a ZIP) are shown and decoded as a whole.
	isText := in.Type == detect.Unknown && decode.Printable(in.Data) >= 0.95
	if isText {
		out = append(out, textFindings(in, dec)...)
	}

	strs := Extract(in.Data, minLen)
	hints := 0
	for i, s := range strs {
		if i%256 == 0 && ctx.Err() != nil {
			return out, ctx.Err()
		}
		loc := fmt.Sprintf("offset 0x%X", s.Offset)
		if s.Encoding != "ascii" {
			loc += " (" + s.Encoding + ")"
		}
		out = append(out, dec.Decode("String", loc, s.Value)...)
		if !isText && hint.MatchString(s.Value) && decode.Printable([]byte(s.Value)) == 1 && hints < 20 {
			hints++
			out = append(out, engine.Finding{
				Title:    "Interesting string: " + textutil.OneLine(s.Value, 80),
				Detail:   detailIfLong(s.Value),
				Score:    40,
				Location: loc,
			})
		}
	}

	if len(strs) > 0 && !isText {
		out = append(out, summary(strs, minLen))
	}
	return out, nil
}

func textFindings(in *engine.Input, dec *textutil.Decoder) []engine.Finding {
	var out []engine.Finding
	text := string(in.Data)
	if len(in.Data) <= maxTextPreview {
		score := 30
		if hint.MatchString(text) {
			score = 60
		}
		out = append(out, engine.Finding{
			Title:  fmt.Sprintf("Text content (%d bytes)", len(in.Data)),
			Detail: textutil.Truncate(text, maxTextPreview),
			Score:  score,
		})
	}
	// Multi-line encodings (e.g. Base64 wrapped at 76 columns) only decode as a whole.
	if len(in.Data) <= maxWholeDecode {
		joined := strings.Join(strings.Fields(text), "")
		if joined != strings.TrimSpace(text) {
			out = append(out, dec.Decode("Text (whitespace removed)", "", joined)...)
		}
	}
	return out
}

func detailIfLong(s string) string {
	if len([]rune(s)) <= 80 {
		return ""
	}
	return textutil.Truncate(s, 1000)
}

func summary(strs []String, minLen int) engine.Finding {
	// List the longest strings: they carry the most information.
	sorted := slices.Clone(strs)
	slices.SortStableFunc(sorted, func(a, b String) int { return len(b.Value) - len(a.Value) })
	if len(sorted) > maxListed {
		sorted = sorted[:maxListed]
	}
	slices.SortFunc(sorted, func(a, b String) int { return a.Offset - b.Offset })
	lines := make([]string, len(sorted))
	for i, s := range sorted {
		lines[i] = fmt.Sprintf("0x%08X  %s", s.Offset, textutil.OneLine(s.Value, 160))
	}
	detail := strings.Join(lines, "\n")
	if len(strs) > maxListed {
		detail = fmt.Sprintf("(longest %d of %d)\n", maxListed, len(strs)) + detail
	}
	return engine.Finding{
		Title:  fmt.Sprintf("%d strings (min. length %d)", len(strs), minLen),
		Detail: detail,
		Score:  engine.ScoreInfo,
	}
}

// Extract returns printable ASCII strings and UTF-16 (LE and BE) strings
// of at least minLen characters, ordered by offset.
func Extract(data []byte, minLen int) []String {
	out := extractASCII(data, minLen)
	out = append(out, extractUTF16(data, minLen, false)...)
	out = append(out, extractUTF16(data, minLen, true)...)
	slices.SortStableFunc(out, func(a, b String) int { return a.Offset - b.Offset })
	return out
}

func isStringByte(c byte) bool { return c >= 0x20 && c < 0x7f || c == '\t' }

func extractASCII(data []byte, minLen int) []String {
	var out []String
	start := -1
	for i := 0; i <= len(data); i++ {
		if i < len(data) && isStringByte(data[i]) {
			if start < 0 {
				start = i
			}
			continue
		}
		if start >= 0 && i-start >= minLen {
			out = append(out, String{Offset: start, Value: string(bytes.TrimSpace(data[start:i])), Encoding: "ascii"})
		}
		start = -1
	}
	return out
}

func extractUTF16(data []byte, minLen int, bigEndian bool) []String {
	var out []String
	var run []uint16
	start := -1
	flush := func() {
		if start >= 0 && len(run) >= minLen {
			enc := "utf16le"
			if bigEndian {
				enc = "utf16be"
			}
			out = append(out, String{Offset: start, Value: strings.TrimSpace(string(utf16.Decode(run))), Encoding: enc})
		}
		run, start = run[:0], -1
	}
	for _, phase := range []int{0, 1} {
		for i := phase; i+1 < len(data); i += 2 {
			lo, hi := data[i], data[i+1]
			if bigEndian {
				lo, hi = hi, lo
			}
			if hi == 0 && isStringByte(lo) {
				if start < 0 {
					start = i
				}
				run = append(run, uint16(lo))
				continue
			}
			flush()
		}
		flush()
	}
	return out
}
