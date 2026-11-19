// Package jpeg parses the marker segment structure of JPEG files without
// decoding image data.
package jpeg

import (
	"encoding/binary"
	"errors"
)

// Marker codes used by callers.
const (
	SOI  = 0xD8
	EOI  = 0xD9
	SOS  = 0xDA
	APP0 = 0xE0
	APP1 = 0xE1
	APP2 = 0xE2
	APPD = 0xED // APP13: Photoshop / IPTC
	COM  = 0xFE
)

// Segment is a marker segment. Data excludes the marker and length bytes.
// For SOS, Data contains only the header, not the entropy-coded scan.
type Segment struct {
	Marker byte
	Offset int // offset of the 0xFF marker byte
	Data   []byte
}

// Errors returned by Parse.
var (
	ErrSOI       = errors.New("jpeg: missing SOI marker")
	ErrTruncated = errors.New("jpeg: truncated segment")
	ErrMarker    = errors.New("jpeg: invalid marker")
)

// Parse walks the segments of a JPEG starting at data[0] until EOI. end is
// the offset after EOI, or -1 if EOI was not reached.
func Parse(data []byte) (segs []Segment, end int, err error) {
	if len(data) < 4 || data[0] != 0xFF || data[1] != SOI {
		return nil, -1, ErrSOI
	}
	off := 2
	for off < len(data) {
		if data[off] != 0xFF {
			return segs, -1, ErrMarker
		}
		// Skip fill bytes.
		for off+1 < len(data) && data[off+1] == 0xFF {
			off++
		}
		if off+1 >= len(data) {
			break
		}
		m := data[off+1]
		switch {
		case m == EOI:
			return segs, off + 2, nil
		case m == 0x00 || m == 0x01 || (m >= 0xD0 && m <= 0xD7):
			// Stand-alone markers without length.
			off += 2
			continue
		}
		if off+4 > len(data) {
			return segs, -1, ErrTruncated
		}
		n := int(binary.BigEndian.Uint16(data[off+2:]))
		if n < 2 || off+2+n > len(data) {
			return segs, -1, ErrTruncated
		}
		segs = append(segs, Segment{Marker: m, Offset: off, Data: data[off+4 : off+2+n]})
		off += 2 + n
		if m == SOS {
			off = skipScan(data, off)
		}
	}
	return segs, -1, ErrTruncated
}

// skipScan advances over entropy-coded data to the next real marker.
func skipScan(data []byte, off int) int {
	for off+1 < len(data) {
		if data[off] != 0xFF {
			off++
			continue
		}
		next := data[off+1]
		// Byte stuffing, restart markers and fill bytes belong to the scan.
		if next == 0x00 || (next >= 0xD0 && next <= 0xD7) || next == 0xFF {
			off++
			continue
		}
		return off
	}
	return len(data)
}

// End returns the offset after EOI, or -1 if data is not a complete JPEG.
func End(data []byte) int {
	_, end, _ := Parse(data)
	return end
}
