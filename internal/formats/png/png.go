// Package png parses the chunk structure of PNG files without decoding
// pixels. It is tolerant: it returns everything parsed up to an error.
package png

import (
	"encoding/binary"
	"errors"
	"hash/crc32"
)

// Signature is the 8-byte PNG file signature.
const Signature = "\x89PNG\r\n\x1a\n"

// Chunk is one PNG chunk.
type Chunk struct {
	Offset   int    // offset of the length field
	Type     string // e.g. "IHDR"
	Data     []byte
	CRC      uint32 // stored CRC
	CRCValid bool
}

// End returns the offset directly after the chunk's CRC.
func (c Chunk) End() int { return c.Offset + 12 + len(c.Data) }

// Errors returned by Parse.
var (
	ErrSignature = errors.New("png: invalid signature")
	ErrTruncated = errors.New("png: truncated chunk")
)

// maxChunkLen is the maximum chunk length allowed by the PNG specification.
const maxChunkLen = 1<<31 - 1

// Parse walks the chunks of a PNG starting at data[0]. It stops after IEND
// or at the first structural error. end is the offset after IEND's CRC, or
// -1 if no IEND was reached.
func Parse(data []byte) (chunks []Chunk, end int, err error) {
	if len(data) < len(Signature) || string(data[:len(Signature)]) != Signature {
		return nil, -1, ErrSignature
	}
	off := len(Signature)
	for {
		if off+8 > len(data) {
			return chunks, -1, ErrTruncated
		}
		n := binary.BigEndian.Uint32(data[off:])
		if n > maxChunkLen || off+12+int(n) > len(data) {
			return chunks, -1, ErrTruncated
		}
		typ := data[off+4 : off+8]
		body := data[off+8 : off+8+int(n)]
		stored := binary.BigEndian.Uint32(data[off+8+int(n):])
		c := Chunk{
			Offset:   off,
			Type:     string(typ),
			Data:     body,
			CRC:      stored,
			CRCValid: crc32.Update(crc32.ChecksumIEEE(typ), crc32.IEEETable, body) == stored,
		}
		chunks = append(chunks, c)
		off = c.End()
		if c.Type == "IEND" {
			return chunks, off, nil
		}
	}
}

// IsCritical reports whether a chunk type is critical (upper-case first letter).
func IsCritical(typ string) bool { return len(typ) == 4 && typ[0] >= 'A' && typ[0] <= 'Z' }

// IsPrivate reports whether a chunk type is private (lower-case second letter).
func IsPrivate(typ string) bool { return len(typ) == 4 && typ[1] >= 'a' && typ[1] <= 'z' }

// Standard lists the chunk types defined by the PNG specification and
// common registered extensions.
var Standard = map[string]bool{
	"IHDR": true, "PLTE": true, "IDAT": true, "IEND": true,
	"cHRM": true, "gAMA": true, "iCCP": true, "sBIT": true, "sRGB": true, "cICP": true, "mDCV": true, "cLLI": true,
	"bKGD": true, "hIST": true, "tRNS": true, "pHYs": true, "sPLT": true, "eXIf": true,
	"tIME": true, "iTXt": true, "tEXt": true, "zTXt": true,
	"acTL": true, "fcTL": true, "fdAT": true, // APNG
	"oFFs": true, "pCAL": true, "sCAL": true, "sTER": true, "gIFg": true, "gIFx": true, "dSIG": true,
}
