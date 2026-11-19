// Package riff parses RIFF containers such as WAV files.
package riff

import (
	"encoding/binary"
	"errors"
)

// Chunk is a RIFF chunk. For LIST chunks, List holds the list type (e.g.
// "INFO") and Children the sub-chunks.
type Chunk struct {
	ID       string
	Offset   int
	Data     []byte
	List     string
	Children []Chunk
}

// ErrNotRIFF is returned for data without a RIFF header.
var ErrNotRIFF = errors.New("riff: missing RIFF header")

// ErrTruncated is returned when a chunk exceeds the data.
var ErrTruncated = errors.New("riff: truncated chunk")

// Parse returns the form type (e.g. "WAVE"), the top-level chunks and the
// end offset declared by the RIFF header (clamped to len(data)).
func Parse(data []byte) (form string, chunks []Chunk, end int, err error) {
	if len(data) < 12 || string(data[:4]) != "RIFF" {
		return "", nil, -1, ErrNotRIFF
	}
	declared := 8 + int(binary.LittleEndian.Uint32(data[4:8]))
	end = min(declared, len(data))
	form = string(data[8:12])
	chunks, err = parseChunks(data[:end], 12, 0)
	if declared > len(data) && err == nil {
		err = ErrTruncated
	}
	return form, chunks, end, err
}

func parseChunks(data []byte, off, depth int) ([]Chunk, error) {
	var out []Chunk
	for off+8 <= len(data) {
		id := string(data[off : off+4])
		n := int(binary.LittleEndian.Uint32(data[off+4 : off+8]))
		if n < 0 || off+8+n > len(data) {
			return out, ErrTruncated
		}
		c := Chunk{ID: id, Offset: off, Data: data[off+8 : off+8+n]}
		if id == "LIST" && n >= 4 && depth < 4 {
			c.List = string(c.Data[:4])
			children, err := parseChunks(data[:off+8+n], off+12, depth+1)
			c.Children = children
			if err != nil {
				out = append(out, c)
				return out, err
			}
		}
		out = append(out, c)
		off += 8 + n + n%2 // chunks are word-aligned
	}
	return out, nil
}
