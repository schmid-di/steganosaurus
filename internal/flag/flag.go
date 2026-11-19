// Package flag finds CTF flags such as THM{...} or HTB{...} in arbitrary data.
package flag

import (
	"fmt"
	"regexp"
	"slices"
)

// DefaultPattern matches the common CTF flag formats. The flag body may
// contain any printable ASCII character except braces.
const DefaultPattern = `(?:picoCTF|THM|HTB|flag|FLAG|CTF)\{[\x20-\x7a\x7c\x7e]{1,256}\}`

// Matcher finds flags using the default pattern plus user-defined patterns.
type Matcher struct {
	patterns []*regexp.Regexp
}

// NewMatcher returns a matcher with the default pattern and the given
// additional regular expressions.
func NewMatcher(extra ...string) (*Matcher, error) {
	m := &Matcher{patterns: []*regexp.Regexp{regexp.MustCompile(DefaultPattern)}}
	for _, p := range extra {
		re, err := regexp.Compile(p)
		if err != nil {
			return nil, fmt.Errorf("invalid flag format %q: %w", p, err)
		}
		m.patterns = append(m.patterns, re)
	}
	return m, nil
}

// Find returns all distinct flags in data, ordered by first occurrence.
func (m *Matcher) Find(data []byte) []string {
	matches := m.Locate(data)
	out := make([]string, 0, len(matches))
	for _, mt := range matches {
		out = append(out, mt.Value)
	}
	return out
}

// FindString is like Find for strings.
func (m *Matcher) FindString(s string) []string {
	return m.Find([]byte(s))
}

// Match is a flag together with the byte offset of its first occurrence.
type Match struct {
	Value  string
	Offset int
}

// Locate is like Find but also returns the offset of each flag's first
// occurrence. Matches lying entirely inside another match (e.g. the default
// "CTF{x}" inside a custom "DUCTF{x}") are dropped.
func (m *Matcher) Locate(data []byte) []Match {
	type span struct{ start, end int }
	var spans []span
	for _, re := range m.patterns {
		for _, loc := range re.FindAllIndex(data, -1) {
			spans = append(spans, span{loc[0], loc[1]})
		}
	}
	// By start; for equal starts the longest match first.
	slices.SortFunc(spans, func(a, b span) int {
		if a.start != b.start {
			return a.start - b.start
		}
		return b.end - a.end
	})

	var out []Match
	seen := map[string]bool{}
	coveredUntil := -1
	for _, sp := range spans {
		if sp.end <= coveredUntil {
			continue // contained in an earlier, longer match
		}
		coveredUntil = sp.end
		v := string(data[sp.start:sp.end])
		if !seen[v] {
			seen[v] = true
			out = append(out, Match{Value: v, Offset: sp.start})
		}
	}
	return out
}
