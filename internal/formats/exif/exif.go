// Package exif parses EXIF metadata (TIFF structure) as found in JPEG APP1
// segments and PNG eXIf chunks.
package exif

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"unicode/utf16"
)

// Entry is one decoded EXIF tag.
type Entry struct {
	IFD   string // "IFD0", "Exif", "GPS", "IFD1", "Interop"
	ID    uint16
	Name  string
	Value string // human-readable value
	Raw   []byte // raw value bytes
}

// Result is the parsed EXIF data.
type Result struct {
	Entries   []Entry
	Thumbnail []byte // embedded JPEG thumbnail from IFD1, if any
	Latitude  *float64
	Longitude *float64
}

// ErrHeader is returned when the TIFF header is invalid.
var ErrHeader = errors.New("exif: invalid TIFF header")

const (
	maxEntriesPerIFD = 512
	maxIFDs          = 16
	maxValues        = 32
)

type parser struct {
	data    []byte
	bo      binary.ByteOrder
	visited map[uint32]bool
	res     Result
}

// Parse decodes a TIFF structure. For JPEG APP1 segments, strip the
// "Exif\x00\x00" prefix first (see StripPrefix).
func Parse(data []byte) (Result, error) {
	if len(data) < 8 {
		return Result{}, ErrHeader
	}
	p := &parser{data: data, visited: map[uint32]bool{}}
	switch string(data[:4]) {
	case "II*\x00":
		p.bo = binary.LittleEndian
	case "MM\x00*":
		p.bo = binary.BigEndian
	default:
		return Result{}, ErrHeader
	}
	ifd0 := p.bo.Uint32(data[4:8])
	next := p.walk("IFD0", ifd0)
	if next != 0 {
		p.walk("IFD1", next)
	}
	p.gps()
	return p.res, nil
}

// StripPrefix removes the "Exif\0\0" header used in JPEG APP1 segments.
func StripPrefix(app1 []byte) ([]byte, bool) {
	return bytes.CutPrefix(app1, []byte("Exif\x00\x00"))
}

// walk parses one IFD and returns the offset of the next IFD.
func (p *parser) walk(name string, off uint32) uint32 {
	if off == 0 || p.visited[off] || len(p.visited) >= maxIFDs || int(off)+2 > len(p.data) {
		return 0
	}
	p.visited[off] = true
	n := int(p.bo.Uint16(p.data[off:]))
	if n > maxEntriesPerIFD {
		return 0
	}
	base := int(off) + 2
	var thumbOff, thumbLen uint32
	for i := range n {
		e := base + i*12
		if e+12 > len(p.data) {
			return 0
		}
		id := p.bo.Uint16(p.data[e:])
		typ := p.bo.Uint16(p.data[e+2:])
		count := p.bo.Uint32(p.data[e+4:])
		raw, ok := p.value(typ, count, e+8)
		if !ok {
			continue
		}
		switch id {
		case 0x8769:
			p.walk("Exif", p.uint(typ, raw))
			continue
		case 0x8825:
			p.walk("GPS", p.uint(typ, raw))
			continue
		case 0xA005:
			p.walk("Interop", p.uint(typ, raw))
			continue
		case 0x0201:
			thumbOff = p.uint(typ, raw)
		case 0x0202:
			thumbLen = p.uint(typ, raw)
		}
		p.res.Entries = append(p.res.Entries, Entry{
			IFD:   name,
			ID:    id,
			Name:  tagName(name, id),
			Value: p.format(id, typ, raw),
			Raw:   raw,
		})
	}
	if thumbLen > 0 && uint64(thumbOff)+uint64(thumbLen) <= uint64(len(p.data)) {
		p.res.Thumbnail = p.data[thumbOff : thumbOff+thumbLen]
	}
	if e := base + n*12; e+4 <= len(p.data) {
		return p.bo.Uint32(p.data[e:])
	}
	return 0
}

var typeSize = map[uint16]int{1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 6: 1, 7: 1, 8: 2, 9: 4, 10: 8, 11: 4, 12: 8}

// value returns the raw bytes of an entry's value.
func (p *parser) value(typ uint16, count uint32, field int) ([]byte, bool) {
	size, ok := typeSize[typ]
	if !ok {
		return nil, false
	}
	total := uint64(size) * uint64(count)
	if total <= 4 {
		return p.data[field : field+int(total)], true
	}
	off := uint64(p.bo.Uint32(p.data[field:]))
	if off+total > uint64(len(p.data)) {
		return nil, false
	}
	return p.data[off : off+total], true
}

func (p *parser) uint(typ uint16, raw []byte) uint32 {
	switch {
	case typ == 3 && len(raw) >= 2:
		return uint32(p.bo.Uint16(raw))
	case (typ == 4 || typ == 9) && len(raw) >= 4:
		return p.bo.Uint32(raw)
	}
	return 0
}

func (p *parser) format(id, typ uint16, raw []byte) string {
	switch {
	case id >= 0x9C9B && id <= 0x9C9F: // XPTitle, XPComment, XPAuthor, XPKeywords, XPSubject
		return utf16le(raw)
	case id == 0x9286: // UserComment
		return userComment(raw)
	}
	switch typ {
	case 2:
		return strings.TrimRight(string(raw), "\x00 ")
	case 1, 6, 7:
		trimmed := bytes.TrimRight(raw, "\x00")
		if len(trimmed) > 0 && printable(trimmed) {
			return string(trimmed)
		}
		if len(raw) > 64 {
			return hex.EncodeToString(raw[:64]) + fmt.Sprintf("… (%d bytes)", len(raw))
		}
		return hex.EncodeToString(raw)
	case 3, 8:
		return p.ints(raw, 2, typ == 8)
	case 4, 9:
		return p.ints(raw, 4, typ == 9)
	case 5, 10:
		var parts []string
		for i := 0; i+8 <= len(raw) && len(parts) < maxValues; i += 8 {
			num, den := p.bo.Uint32(raw[i:]), p.bo.Uint32(raw[i+4:])
			if typ == 10 {
				parts = append(parts, rational(float64(int32(num)), float64(int32(den))))
			} else {
				parts = append(parts, rational(float64(num), float64(den)))
			}
		}
		return strings.Join(parts, " ")
	}
	return hex.EncodeToString(raw)
}

func (p *parser) ints(raw []byte, size int, signed bool) string {
	var parts []string
	for i := 0; i+size <= len(raw) && len(parts) < maxValues; i += size {
		var v int64
		switch {
		case size == 2 && signed:
			v = int64(int16(p.bo.Uint16(raw[i:])))
		case size == 2:
			v = int64(p.bo.Uint16(raw[i:]))
		case signed:
			v = int64(int32(p.bo.Uint32(raw[i:])))
		default:
			v = int64(p.bo.Uint32(raw[i:]))
		}
		parts = append(parts, fmt.Sprint(v))
	}
	if len(raw)/size > maxValues {
		parts = append(parts, "…")
	}
	return strings.Join(parts, " ")
}

func rational(num, den float64) string {
	if den == 0 {
		return "0"
	}
	if den == 1 {
		return fmt.Sprintf("%g", num)
	}
	return fmt.Sprintf("%g", num/den)
}

func utf16le(raw []byte) string {
	u := make([]uint16, 0, len(raw)/2)
	for i := 0; i+1 < len(raw); i += 2 {
		c := binary.LittleEndian.Uint16(raw[i:])
		if c == 0 {
			break
		}
		u = append(u, c)
	}
	return string(utf16.Decode(u))
}

func userComment(raw []byte) string {
	if len(raw) < 8 {
		return strings.TrimRight(string(raw), "\x00 ")
	}
	body := raw[8:]
	switch string(bytes.TrimRight(raw[:8], "\x00")) {
	case "UNICODE":
		if len(body) >= 2 && body[0] == 0 {
			u := make([]uint16, 0, len(body)/2)
			for i := 0; i+1 < len(body); i += 2 {
				u = append(u, binary.BigEndian.Uint16(body[i:]))
			}
			return strings.TrimRight(string(utf16.Decode(u)), "\x00 ")
		}
		return strings.TrimRight(utf16le(body), "\x00 ")
	default:
		return strings.TrimRight(string(body), "\x00 ")
	}
}

func printable(b []byte) bool {
	for _, c := range b {
		if (c < 0x20 || c >= 0x7f) && c != '\n' && c != '\r' && c != '\t' {
			return false
		}
	}
	return true
}

// gps converts GPS latitude/longitude entries to decimal degrees.
func (p *parser) gps() {
	var lat, lon []byte
	latRef, lonRef := "N", "E"
	for _, e := range p.res.Entries {
		if e.IFD != "GPS" {
			continue
		}
		switch e.ID {
		case 1:
			latRef = e.Value
		case 2:
			lat = e.Raw
		case 3:
			lonRef = e.Value
		case 4:
			lon = e.Raw
		}
	}
	if v, ok := p.degrees(lat); ok {
		if latRef == "S" {
			v = -v
		}
		p.res.Latitude = &v
	}
	if v, ok := p.degrees(lon); ok {
		if lonRef == "W" {
			v = -v
		}
		p.res.Longitude = &v
	}
}

func (p *parser) degrees(raw []byte) (float64, bool) {
	if len(raw) != 24 {
		return 0, false
	}
	var parts [3]float64
	for i := range parts {
		num, den := p.bo.Uint32(raw[i*8:]), p.bo.Uint32(raw[i*8+4:])
		if den == 0 {
			return 0, false
		}
		parts[i] = float64(num) / float64(den)
	}
	return parts[0] + parts[1]/60 + parts[2]/3600, true
}
