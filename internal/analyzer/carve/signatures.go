package carve

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"io"

	"github.com/schmid-di/steganosaurus/internal/detect"
	"github.com/schmid-di/steganosaurus/internal/formats/gif"
	"github.com/schmid-di/steganosaurus/internal/formats/jpeg"
	"github.com/schmid-di/steganosaurus/internal/formats/png"
	"github.com/schmid-di/steganosaurus/internal/formats/riff"
)

// signature describes how to find and delimit an embedded file.
type signature struct {
	typ   detect.FileType
	magic []byte
	// back is subtracted from the magic position to get the file start
	// (tar's magic is at offset 257).
	back int
	// end returns the length of the file starting at b[0], or -1 if the
	// end cannot be determined.
	end func(b []byte) int
	// strict signatures are dropped when end returns -1: their magic is
	// short enough to occur by chance in compressed data.
	strict bool
	ext    string
}

var signatures = []signature{
	{typ: detect.PNG, magic: []byte(png.Signature), end: pngEnd, ext: "png"},
	{typ: detect.JPEG, magic: []byte{0xFF, 0xD8, 0xFF}, end: jpeg.End, strict: true, ext: "jpg"},
	{typ: detect.GIF, magic: []byte("GIF89a"), end: gifEnd, ext: "gif"},
	{typ: detect.GIF, magic: []byte("GIF87a"), end: gifEnd, ext: "gif"},
	{typ: detect.BMP, magic: []byte("BM"), end: bmpEnd, strict: true, ext: "bmp"},
	{typ: detect.WAV, magic: []byte("RIFF"), end: wavEnd, strict: true, ext: "wav"},
	{typ: detect.ZIP, magic: []byte("PK\x03\x04"), end: zipEnd, ext: "zip"},
	{typ: detect.RAR, magic: []byte("Rar!\x1a\x07"), end: unknownEnd, ext: "rar"},
	{typ: detect.SevenZip, magic: []byte("7z\xbc\xaf\x27\x1c"), end: sevenZipEnd, ext: "7z"},
	{typ: detect.Gzip, magic: []byte{0x1f, 0x8b, 0x08}, end: gzipEnd, strict: true, ext: "gz"},
	{typ: detect.Bzip2, magic: []byte("BZh"), end: bzip2End, strict: true, ext: "bz2"},
	{typ: detect.XZ, magic: []byte("\xfd7zXZ\x00"), end: unknownEnd, ext: "xz"},
	{typ: detect.Tar, magic: []byte("ustar"), back: 257, end: tarEnd, strict: true, ext: "tar"},
	{typ: detect.PDF, magic: []byte("%PDF-"), end: pdfEnd, ext: "pdf"},
	{typ: detect.ELF, magic: []byte("\x7fELF"), end: elfEnd, strict: true, ext: "elf"},
	{typ: detect.PE, magic: []byte("MZ"), end: peEnd, strict: true, ext: "exe"},
}

// signatureFor returns the signature for a detected root type.
func signatureFor(t detect.FileType) (signature, bool) {
	for _, s := range signatures {
		if s.typ == t {
			return s, true
		}
	}
	return signature{}, false
}

func unknownEnd([]byte) int { return -1 }

func pngEnd(b []byte) int {
	_, end, _ := png.Parse(b)
	return end
}

func gifEnd(b []byte) int {
	info, _ := gif.Parse(b)
	return info.End
}

func bmpEnd(b []byte) int {
	if detect.Detect(b) != detect.BMP || len(b) < 6 {
		return -1
	}
	n := int(binary.LittleEndian.Uint32(b[2:6]))
	if n < 26 || n > len(b) {
		return -1
	}
	return n
}

func wavEnd(b []byte) int {
	if detect.Detect(b) != detect.WAV {
		return -1
	}
	_, _, end, err := riff.Parse(b)
	if err != nil {
		return -1
	}
	return end
}

// zipEnd finds the end-of-central-directory record that belongs to the
// archive starting at b[0] and returns the offset after its comment.
func zipEnd(b []byte) int {
	for search := 0; ; {
		i := bytes.Index(b[search:], []byte("PK\x05\x06"))
		if i < 0 {
			return -1
		}
		eocd := search + i
		search = eocd + 4
		if eocd+22 > len(b) {
			return -1
		}
		cdSize := int(binary.LittleEndian.Uint32(b[eocd+12:]))
		cdOff := int(binary.LittleEndian.Uint32(b[eocd+16:]))
		comment := int(binary.LittleEndian.Uint16(b[eocd+20:]))
		end := eocd + 22 + comment
		// The central directory must end right at the EOCD record.
		if cdOff+cdSize == eocd && end <= len(b) {
			return end
		}
	}
}

func sevenZipEnd(b []byte) int {
	if len(b) < 32 {
		return -1
	}
	next := binary.LittleEndian.Uint64(b[12:])
	size := binary.LittleEndian.Uint64(b[20:])
	end := 32 + next + size
	if next > uint64(len(b)) || size > uint64(len(b)) || end > uint64(len(b)) {
		return -1
	}
	return int(end)
}

// gzipEnd decompresses the first gzip member to find where it ends.
// bytes.Reader implements io.ByteReader, so gzip does not over-read.
func gzipEnd(b []byte) int {
	r := bytes.NewReader(b)
	zr, err := gzip.NewReader(r)
	if err != nil {
		return -1
	}
	zr.Multistream(false)
	if _, err := io.Copy(io.Discard, io.LimitReader(zr, maxEntrySize)); err != nil {
		return -1
	}
	return len(b) - r.Len()
}

// bzip2End only validates the stream header; the end of a bzip2 stream is
// not byte-aligned, so the carved data extends to the end of the input.
func bzip2End(b []byte) int {
	if len(b) < 10 || b[3] < '1' || b[3] > '9' || string(b[4:10]) != "1AY&SY" {
		return 0
	}
	return len(b)
}

func tarEnd(b []byte) int {
	if len(b) < 512 || !tarChecksumOK(b[:512]) {
		return -1
	}
	return len(b) // refined during extraction
}

func tarChecksumOK(h []byte) bool {
	var sum int64
	for i, c := range h {
		if i >= 148 && i < 156 {
			c = ' '
		}
		sum += int64(c)
	}
	field := bytes.TrimRight(bytes.TrimLeft(h[148:156], " \x00"), " \x00")
	var stored int64
	for _, c := range field {
		if c < '0' || c > '7' {
			return false
		}
		stored = stored*8 + int64(c-'0')
	}
	return len(field) > 0 && stored == sum
}

func pdfEnd(b []byte) int {
	i := bytes.LastIndex(b, []byte("%%EOF"))
	if i < 0 {
		return -1
	}
	end := i + 5
	for end < len(b) && (b[end] == '\r' || b[end] == '\n') && end < i+7 {
		end++
	}
	return end
}

func elfEnd(b []byte) int {
	if len(b) < 52 || (b[4] != 1 && b[4] != 2) || (b[5] != 1 && b[5] != 2) || b[6] != 1 {
		return -1
	}
	var bo binary.ByteOrder = binary.LittleEndian
	if b[5] == 2 {
		bo = binary.BigEndian
	}
	var phoff, shoff uint64
	var phentsize, phnum, shentsize, shnum uint64
	if b[4] == 1 {
		phoff, shoff = uint64(bo.Uint32(b[28:])), uint64(bo.Uint32(b[32:]))
		phentsize, phnum = uint64(bo.Uint16(b[42:])), uint64(bo.Uint16(b[44:]))
		shentsize, shnum = uint64(bo.Uint16(b[46:])), uint64(bo.Uint16(b[48:]))
	} else {
		if len(b) < 64 {
			return -1
		}
		phoff, shoff = bo.Uint64(b[32:]), bo.Uint64(b[40:])
		phentsize, phnum = uint64(bo.Uint16(b[54:])), uint64(bo.Uint16(b[56:]))
		shentsize, shnum = uint64(bo.Uint16(b[58:])), uint64(bo.Uint16(b[60:]))
	}
	end := shoff + shentsize*shnum
	// Segments may extend beyond the section header table.
	for i := uint64(0); i < phnum && phoff+(i+1)*phentsize <= uint64(len(b)); i++ {
		p := b[phoff+i*phentsize:]
		var off, size uint64
		if b[4] == 1 {
			off, size = uint64(bo.Uint32(p[4:])), uint64(bo.Uint32(p[16:]))
		} else {
			off, size = bo.Uint64(p[8:]), bo.Uint64(p[32:])
		}
		end = max(end, off+size)
	}
	if end == 0 || end > uint64(len(b)) {
		return -1
	}
	return int(end)
}

func peEnd(b []byte) int {
	if detect.Detect(b) != detect.PE || len(b) < 0x40 {
		return -1
	}
	pe := int(binary.LittleEndian.Uint32(b[0x3c:]))
	if pe+24 > len(b) {
		return -1
	}
	nsec := int(binary.LittleEndian.Uint16(b[pe+6:]))
	optSize := int(binary.LittleEndian.Uint16(b[pe+20:]))
	sec := pe + 24 + optSize
	end := 0
	for i := range nsec {
		s := sec + i*40
		if s+40 > len(b) {
			return -1
		}
		raw := int(binary.LittleEndian.Uint32(b[s+16:]))
		ptr := int(binary.LittleEndian.Uint32(b[s+20:]))
		end = max(end, ptr+raw)
	}
	if end == 0 || end > len(b) {
		return -1
	}
	return end
}
