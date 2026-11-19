// Package decode recognises and decodes common CTF encodings (Base64,
// Base32, Base58, Ascii85, hex, binary, decimal, ROT13, ROT47, Morse) and
// follows chains of them, e.g. Base64 → hex → text.
package decode

import (
	"bytes"
	"math"
	"strings"
)

// Printable returns the fraction of bytes that are printable ASCII or
// common whitespace.
func Printable(b []byte) float64 {
	if len(b) == 0 {
		return 0
	}
	n := 0
	for _, c := range b {
		if isPrintable(c) {
			n++
		}
	}
	return float64(n) / float64(len(b))
}

func isPrintable(c byte) bool {
	return (c >= 0x20 && c < 0x7f) || c == '\n' || c == '\r' || c == '\t'
}

// Readability estimates how much b looks like human-readable text, from 0
// (binary noise) to 1 (plain prose). It combines the share of printable and
// "friendly" characters, the vowel ratio of letters and how often the
// character class (lower/upper/digit) flips inside words, which is high for
// random strings and encodings and low for natural language.
func Readability(b []byte) float64 {
	if len(b) == 0 {
		return 0
	}
	p := Printable(b)
	if p < 0.9 {
		return p * 0.4
	}
	var letters, vowels, digits, spaces, punct, alnum, flips int
	prev := byte(0) // class of previous char inside a word: 'l', 'u', 'd' or 0
	for _, c := range b {
		var class byte
		switch {
		case c >= 'a' && c <= 'z':
			class = 'l'
		case c >= 'A' && c <= 'Z':
			class = 'u'
		case c >= '0' && c <= '9':
			class = 'd'
		}
		switch class {
		case 'l', 'u':
			letters++
			if strings.IndexByte("aeiouyAEIOUY", c) >= 0 {
				vowels++
			}
		case 'd':
			digits++
		default:
			switch {
			case c == ' ' || c == '\n' || c == '\t' || c == '\r':
				spaces++
			case strings.IndexByte("_{}.,:;!?-'\"()", c) >= 0:
				punct++
			}
		}
		if class != 0 {
			alnum++
			// Upper→lower is normal capitalisation ("Hello"); others are flips.
			if prev != 0 && class != prev && !(prev == 'u' && class == 'l') {
				flips++
			}
		}
		prev = class
	}
	n := float64(len(b))
	friendly := float64(letters+digits+spaces+punct) / n

	vowelMult := 1.0
	if letters >= 6 {
		r := float64(vowels) / float64(letters)
		switch {
		case r < 0.12 || r > 0.75:
			vowelMult = 0.6
		case r < 0.2 || r > 0.6:
			vowelMult = 0.85
		}
	} else if letters == 0 {
		vowelMult = 0.7
	}

	flipMult := 1.0
	if alnum > 0 {
		flipMult = 1 - min(0.5, float64(flips)/float64(alnum))
	}
	return p * (0.45 + 0.55*friendly) * vowelMult * flipMult
}

// ReadableThreshold is the Readability above which data is treated as text.
const ReadableThreshold = 0.8

// IsReadable reports whether b is likely meaningful text.
func IsReadable(b []byte) bool {
	return len(b) >= 4 && Readability(b) >= ReadableThreshold
}

// Entropy returns the Shannon entropy of b in bits per byte (0–8).
func Entropy(b []byte) float64 {
	if len(b) == 0 {
		return 0
	}
	var freq [256]int
	for _, c := range b {
		freq[c]++
	}
	var h float64
	n := float64(len(b))
	for _, f := range freq {
		if f > 0 {
			p := float64(f) / n
			h -= p * math.Log2(p)
		}
	}
	return h
}

// englishFreq is the relative letter frequency in English text (a–z).
var englishFreq = [26]float64{
	8.2, 1.5, 2.8, 4.3, 12.7, 2.2, 2.0, 6.1, 7.0, 0.15, 0.77, 4.0, 2.4,
	6.7, 7.5, 1.9, 0.095, 6.0, 6.3, 9.1, 2.8, 0.98, 2.4, 0.15, 2.0, 0.074,
}

// EnglishDistance is a chi-squared distance between the letter
// distribution of b and English. Lower is more English. Returns +Inf when b
// has fewer than 4 letters.
func EnglishDistance(b []byte) float64 {
	var counts [26]int
	total := 0
	for _, c := range bytes.ToLower(b) {
		if c >= 'a' && c <= 'z' {
			counts[c-'a']++
			total++
		}
	}
	if total < 4 {
		return math.Inf(1)
	}
	var chi float64
	for i, c := range counts {
		expected := englishFreq[i] / 100 * float64(total)
		d := float64(c) - expected
		chi += d * d / expected
	}
	return chi / float64(total)
}

// hintWords are words that make a decoded candidate interesting in a CTF.
var hintWords = []string{
	"flag", "password", "passwd", "pass", "secret", "key", "hint", "hidden",
	"steg", "the ", "and ", "you", "thm", "htb", "ctf", "admin", "user",
}

// HintScore counts CTF-relevant words in b (case-insensitive).
func HintScore(b []byte) int {
	lower := strings.ToLower(string(b))
	n := 0
	for _, w := range hintWords {
		if strings.Contains(lower, w) {
			n++
		}
	}
	return n
}
