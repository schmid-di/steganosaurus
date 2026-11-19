package decode

import (
	"bytes"
	"strings"

	"github.com/schmid-di/steganosaurus/internal/detect"
)

// MaxChain is the maximum number of decoding steps followed.
const MaxChain = 5

// Step is one decoding step of a chain.
type Step struct {
	Decoder string
	Output  []byte
}

// Result is a successful decoding chain.
type Result struct {
	Input    string
	Steps    []Step
	Final    []byte
	FileType detect.FileType // non-Unknown if Final is a recognised file
}

// Decoders returns the decoder names of the chain, e.g. "base64 → hex".
func (r Result) Decoders() string {
	names := make([]string, len(r.Steps))
	for i, s := range r.Steps {
		names[i] = s.Decoder
	}
	return strings.Join(names, " → ")
}

// FlagChecker reports whether data contains a flag. It lets rotations be
// accepted when they reveal a flag.
type FlagChecker func([]byte) bool

// Chain decodes s repeatedly while the result stays plausible. It reports
// ok only if at least one step succeeded and the final output is a known
// file type, readable text or contains a flag.
func Chain(s string, hasFlag FlagChecker) (Result, bool) {
	res := Result{Input: s, FileType: detect.Unknown}
	cur := []byte(strings.TrimSpace(s))
	if hasFlag == nil {
		hasFlag = func([]byte) bool { return false }
	}

	for len(res.Steps) < MaxChain {
		step, ok := bestStep(cur)
		if !ok {
			// A rotation might hide a structural encoding, e.g. ROT13(Base64).
			for _, rot := range Rotations {
				if last(res.Steps) == rot.Name {
					continue
				}
				rotated, _ := rot.Decode(string(cur))
				if next, ok2 := bestStep(rotated); ok2 {
					res.Steps = append(res.Steps, Step{rot.Name, rotated})
					step, ok = next, true
					break
				}
			}
		}
		if !ok {
			break
		}
		res.Steps = append(res.Steps, step)
		cur = step.Output
		if ft := detect.Detect(cur); ft != detect.Unknown {
			res.FileType = ft
			break
		}
	}

	// Finally, a rotation of readable text may reveal the plaintext.
	if res.FileType == detect.Unknown && Printable(cur) >= 0.95 {
		if rot, ok := bestRotation(cur, hasFlag); ok {
			res.Steps = append(res.Steps, rot)
			cur = rot.Output
		}
	}

	res.Final = cur
	if len(res.Steps) == 0 {
		return res, false
	}
	return res, res.FileType != detect.Unknown || hasFlag(cur) || IsReadable(cur)
}

// bestStep applies all structural decoders and returns the most plausible
// output: recognised files first, then the most readable text.
func bestStep(cur []byte) (Step, bool) {
	s := string(bytes.TrimSpace(cur))
	var best Step
	bestScore := -1.0
	for _, d := range Structural {
		out, ok := d.Decode(s)
		if !ok || len(out) < 3 {
			continue
		}
		var score float64
		switch {
		case detect.Detect(out) != detect.Unknown:
			score = 2
		case Printable(out) >= 0.95:
			score = Readability(out)
		default:
			continue
		}
		if score > bestScore {
			best, bestScore = Step{d.Name, out}, score
		}
	}
	return best, bestScore >= 0
}

// bestRotation returns a rotation of cur that is clearly better than cur:
// it reveals a flag, adds CTF hint words or is notably more English.
func bestRotation(cur []byte, hasFlag FlagChecker) (Step, bool) {
	if hasFlag(cur) {
		return Step{}, false
	}
	baseHints := HintScore(cur)
	baseDist := EnglishDistance(cur)
	for _, rot := range Rotations {
		out, _ := rot.Decode(string(cur))
		if bytes.Equal(out, cur) {
			continue
		}
		if hasFlag(out) {
			return Step{rot.Name, out}, true
		}
		if HintScore(out) > baseHints && EnglishDistance(out) < baseDist {
			return Step{rot.Name, out}, true
		}
	}
	return Step{}, false
}

func last(steps []Step) string {
	if len(steps) == 0 {
		return ""
	}
	return steps[len(steps)-1].Decoder
}
