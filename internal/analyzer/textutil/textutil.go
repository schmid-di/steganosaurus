// Package textutil holds helpers shared by text-oriented analyzers.
package textutil

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/schmid-di/steganosaurus/internal/decode"
	"github.com/schmid-di/steganosaurus/internal/engine"
)

// Scores for decoded content.
const (
	ScoreDecodedText = 70
	ScoreDecodedFile = 75
)

// encodedRun finds substrings that may be encoded data inside longer text,
// e.g. the Base64 part of "key: ZmxhZ3t4fQ==".
var encodedRun = regexp.MustCompile(`[A-Za-z0-9+/=_\-]{8,}|<~[!-uz\s]+~>`)

// valuePart isolates the value after a "key = " / "key: " prefix. In the
// Base64/Base32/Base58 alphabets '=' only pads at the end and ':' never
// appears, so an internal '=' or ':' always separates a label from its data.
var valuePart = regexp.MustCompile(`^[\w .\-]{1,32}[:=]\s*([A-Za-z0-9+/][A-Za-z0-9+/=_\-]{7,})$`)

// Candidates returns s plus encoded-looking substrings of s.
func Candidates(s string) []string {
	s = strings.TrimSpace(s)
	out := []string{s}
	seen := map[string]bool{s: true}
	add := func(c string) {
		if len(c) >= 8 && !seen[c] {
			seen[c] = true
			out = append(out, c)
		}
	}
	for _, m := range encodedRun.FindAllString(s, -1) {
		add(m)
		if sub := valuePart.FindStringSubmatch(m); sub != nil {
			add(sub[1])
		}
	}
	// Also handle "key: value" where the separator is a space run.
	if sub := valuePart.FindStringSubmatch(s); sub != nil {
		add(sub[1])
	}
	return out
}

// Decoder runs decoding chains and suppresses duplicate results within one
// analyzer run.
type Decoder struct {
	in   *engine.Input
	seen map[string]bool
}

// NewDecoder returns a decoder for one input.
func NewDecoder(in *engine.Input) *Decoder {
	return &Decoder{in: in, seen: map[string]bool{}}
}

// Decode tries s and its encoded substrings. label describes where the
// value came from (e.g. `EXIF Artist`), location is passed through.
func (d *Decoder) Decode(label, location, s string) []engine.Finding {
	var out []engine.Finding
	for _, c := range Candidates(s) {
		if d.seen[c] {
			continue
		}
		d.seen[c] = true
		res, ok := decode.Chain(c, d.in.HasFlag)
		if !ok || d.seen["\x00final:"+string(res.Final)] {
			continue
		}
		d.seen["\x00final:"+string(res.Final)] = true
		out = append(out, Finding(label, location, res))
	}
	return out
}

// Finding turns a decoding result into a finding. Decoded files become
// artifacts so that the engine scans them recursively.
func Finding(label, location string, res decode.Result) engine.Finding {
	title := fmt.Sprintf("%s decodes via %s", label, res.Decoders())
	detail := "input:  " + Truncate(res.Input, 120)
	if res.FileType != "" && res.FileType != "unknown" {
		return engine.Finding{
			Title:    fmt.Sprintf("%s → %s file", title, strings.ToUpper(string(res.FileType))),
			Detail:   detail,
			Score:    ScoreDecodedFile,
			Location: location,
			Artifact: &engine.Artifact{Name: "decoded." + string(res.FileType), Data: res.Final},
		}
	}
	score := ScoreDecodedText
	if decode.HintScore(res.Final) > 0 {
		score += 10
	}
	return engine.Finding{
		Title:    title,
		Detail:   detail + "\noutput: " + Truncate(string(res.Final), 500),
		Score:    score,
		Location: location,
	}
}

// Truncate shortens s to at most n runes and makes control characters visible.
func Truncate(s string, n int) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 && r != '\n' && r != '\t' || r == 0x7f {
			return '·'
		}
		return r
	}, s)
	if r := []rune(s); len(r) > n {
		return string(r[:n]) + fmt.Sprintf("… (%d chars)", len(r))
	}
	return s
}

// OneLine is Truncate for titles: newlines are replaced by "⏎".
func OneLine(s string, n int) string {
	return strings.ReplaceAll(Truncate(s, n), "\n", "⏎")
}
