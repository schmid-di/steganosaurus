// Package testutil builds small media files with embedded data for tests.
// Everything is generated in-process so the test suite needs no external
// tools or binary fixtures.
package testutil

import (
	"archive/zip"
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"hash/crc32"
	"image"
	"image/color"
	"image/jpeg"
	"testing"
)

// PNGChunk is a raw PNG chunk used by PNGWithChunks.
type PNGChunk struct {
	Type string
	Data []byte
}

// PNG returns a minimal valid w×h RGBA PNG (opaque mid-gray).
func PNG(w, h int) []byte {
	return PNGWithChunks(w, h, nil)
}

// PNGWithChunks returns a valid PNG with extra chunks inserted after IHDR.
func PNGWithChunks(w, h int, extra []PNGChunk) []byte {
	var buf bytes.Buffer
	buf.WriteString("\x89PNG\r\n\x1a\n")

	ihdr := make([]byte, 13)
	binary.BigEndian.PutUint32(ihdr[0:], uint32(w))
	binary.BigEndian.PutUint32(ihdr[4:], uint32(h))
	ihdr[8], ihdr[9] = 8, 6 // 8-bit, RGBA
	writeChunk(&buf, "IHDR", ihdr)

	for _, c := range extra {
		writeChunk(&buf, c.Type, c.Data)
	}

	// One IDAT with zlib-compressed scanlines (filter byte 0 per row).
	raw := make([]byte, 0, h*(1+w*4))
	for y := 0; y < h; y++ {
		raw = append(raw, 0)
		for x := 0; x < w*4; x++ {
			raw = append(raw, 0x80)
		}
	}
	var zb bytes.Buffer
	zw := zlib.NewWriter(&zb)
	zw.Write(raw)
	zw.Close()
	writeChunk(&buf, "IDAT", zb.Bytes())
	writeChunk(&buf, "IEND", nil)
	return buf.Bytes()
}

// TextChunk builds a PNG tEXt chunk.
func TextChunk(keyword, text string) PNGChunk {
	return PNGChunk{Type: "tEXt", Data: []byte(keyword + "\x00" + text)}
}

// ZTextChunk builds a compressed PNG zTXt chunk.
func ZTextChunk(keyword, text string) PNGChunk {
	var zb bytes.Buffer
	zw := zlib.NewWriter(&zb)
	zw.Write([]byte(text))
	zw.Close()
	data := append([]byte(keyword+"\x00\x00"), zb.Bytes()...)
	return PNGChunk{Type: "zTXt", Data: data}
}

func writeChunk(buf *bytes.Buffer, typ string, data []byte) {
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(data)))
	buf.Write(length[:])
	start := buf.Len()
	buf.WriteString(typ)
	buf.Write(data)
	crc := crc32.ChecksumIEEE(buf.Bytes()[start:])
	var c [4]byte
	binary.BigEndian.PutUint32(c[:], crc)
	buf.Write(c[:])
}

// JPEG returns a small valid JPEG, optionally carrying a COM comment.
func JPEG(t *testing.T, comment string) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, 8, 8))
	for i := range img.Pix {
		img.Pix[i] = 0x80
	}
	var buf bytes.Buffer
	if err := jpeg.Encode(&buf, img, &jpeg.Options{Quality: 80}); err != nil {
		t.Fatalf("encode jpeg: %v", err)
	}
	if comment == "" {
		return buf.Bytes()
	}
	return insertComment(buf.Bytes(), comment)
}

// insertComment adds a COM segment right after the SOI marker.
func insertComment(j []byte, comment string) []byte {
	seg := make([]byte, 0, len(comment)+4)
	seg = append(seg, 0xFF, 0xFE)
	seg = binary.BigEndian.AppendUint16(seg, uint16(len(comment)+2))
	seg = append(seg, comment...)
	out := make([]byte, 0, len(j)+len(seg))
	out = append(out, j[:2]...)
	out = append(out, seg...)
	out = append(out, j[2:]...)
	return out
}

// Gray8 returns an 8-bit grayscale image.Image of the given size.
func Gray8(w, h int) *image.Gray {
	img := image.NewGray(image.Rect(0, 0, w, h))
	for i := range img.Pix {
		img.Pix[i] = uint8((i * 7) % 256)
	}
	return img
}

var _ = color.Gray{}

// Zip builds a ZIP archive from name→content pairs.
func Zip(files map[string]string) []byte {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, content := range files {
		w, _ := zw.Create(name)
		w.Write([]byte(content))
	}
	zw.Close()
	return buf.Bytes()
}

// WAV builds a minimal PCM WAV file with the given sample bytes and an
// optional LIST/INFO chunk of id→value pairs.
func WAV(samples []byte, info map[string]string) []byte {
	var body bytes.Buffer
	// fmt chunk: PCM, mono, 8000 Hz, 8-bit.
	body.WriteString("fmt ")
	binary.Write(&body, binary.LittleEndian, uint32(16))
	binary.Write(&body, binary.LittleEndian, uint16(1))
	binary.Write(&body, binary.LittleEndian, uint16(1))
	binary.Write(&body, binary.LittleEndian, uint32(8000))
	binary.Write(&body, binary.LittleEndian, uint32(8000))
	binary.Write(&body, binary.LittleEndian, uint16(1))
	binary.Write(&body, binary.LittleEndian, uint16(8))

	body.WriteString("data")
	binary.Write(&body, binary.LittleEndian, uint32(len(samples)))
	body.Write(samples)
	if len(samples)%2 == 1 {
		body.WriteByte(0)
	}

	if len(info) > 0 {
		var list bytes.Buffer
		list.WriteString("INFO")
		for id, v := range info {
			list.WriteString(id)
			val := append([]byte(v), 0)
			if len(val)%2 == 1 {
				val = append(val, 0)
			}
			binary.Write(&list, binary.LittleEndian, uint32(len(val)))
			list.Write(val)
		}
		body.WriteString("LIST")
		binary.Write(&body, binary.LittleEndian, uint32(list.Len()))
		body.Write(list.Bytes())
	}

	var buf bytes.Buffer
	buf.WriteString("RIFF")
	binary.Write(&buf, binary.LittleEndian, uint32(4+body.Len()))
	buf.WriteString("WAVE")
	buf.Write(body.Bytes())
	return buf.Bytes()
}
