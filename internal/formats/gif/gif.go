// Package gif parses the block structure of GIF files without decoding
// image data.
package gif

import (
	"errors"
)

// Comment is a GIF comment extension.
type Comment struct {
	Offset int
	Text   []byte
}

// Info is the result of Parse.
type Info struct {
	Comments    []Comment
	Frames      int
	Application []string // application extension identifiers, e.g. "NETSCAPE2.0"
	End         int      // offset after the trailer, -1 if not reached
}

// ErrFormat is returned for data that is not a GIF.
var ErrFormat = errors.New("gif: invalid header")

// ErrTruncated is returned when a block exceeds the data.
var ErrTruncated = errors.New("gif: truncated block")

// Parse walks the blocks of a GIF starting at data[0].
func Parse(data []byte) (Info, error) {
	info := Info{End: -1}
	if len(data) < 13 || (string(data[:6]) != "GIF87a" && string(data[:6]) != "GIF89a") {
		return info, ErrFormat
	}
	off := 13
	if flags := data[10]; flags&0x80 != 0 {
		off += 3 << (flags&0x07 + 1)
	}
	for off < len(data) {
		switch data[off] {
		case 0x3B: // trailer
			info.End = off + 1
			return info, nil
		case 0x21: // extension
			if off+2 > len(data) {
				return info, ErrTruncated
			}
			label := data[off+1]
			body, next, err := subBlocks(data, off+2)
			if err != nil {
				return info, err
			}
			switch label {
			case 0xFE:
				info.Comments = append(info.Comments, Comment{Offset: off, Text: body})
			case 0xFF:
				if len(body) >= 11 {
					info.Application = append(info.Application, string(body[:11]))
				}
			}
			off = next
		case 0x2C: // image descriptor
			if off+10 > len(data) {
				return info, ErrTruncated
			}
			flags := data[off+9]
			off += 10
			if flags&0x80 != 0 {
				off += 3 << (flags&0x07 + 1)
			}
			off++ // LZW minimum code size
			_, next, err := subBlocks(data, off)
			if err != nil {
				return info, err
			}
			info.Frames++
			off = next
		default:
			return info, ErrTruncated
		}
	}
	return info, ErrTruncated
}

// subBlocks reads a chain of data sub-blocks terminated by a zero-length
// block and returns their concatenated content and the offset after it.
func subBlocks(data []byte, off int) ([]byte, int, error) {
	var out []byte
	for {
		if off >= len(data) {
			return out, off, ErrTruncated
		}
		n := int(data[off])
		off++
		if n == 0 {
			return out, off, nil
		}
		if off+n > len(data) {
			return out, off, ErrTruncated
		}
		out = append(out, data[off:off+n]...)
		off += n
	}
}
