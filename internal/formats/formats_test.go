package formats_test

import (
	"testing"

	"github.com/schmid-di/steganosaurus/internal/formats/gif"
	"github.com/schmid-di/steganosaurus/internal/formats/jpeg"
	"github.com/schmid-di/steganosaurus/internal/formats/png"
	"github.com/schmid-di/steganosaurus/internal/formats/riff"
	"github.com/schmid-di/steganosaurus/internal/testutil"
)

func TestPNGParse(t *testing.T) {
	data := testutil.PNGWithChunks(4, 4, []testutil.PNGChunk{testutil.TextChunk("k", "v")})
	chunks, end, err := png.Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	if end != len(data) {
		t.Errorf("end = %d, want %d", end, len(data))
	}
	var types []string
	for _, c := range chunks {
		types = append(types, c.Type)
		if !c.CRCValid {
			t.Errorf("chunk %s has invalid CRC", c.Type)
		}
	}
	want := []string{"IHDR", "tEXt", "IDAT", "IEND"}
	if len(types) != len(want) {
		t.Fatalf("chunk types = %v, want %v", types, want)
	}
}

func TestPNGTrailingData(t *testing.T) {
	data := append(testutil.PNG(4, 4), []byte("EXTRA")...)
	_, end, err := png.Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	if end != len(data)-5 {
		t.Errorf("end = %d, want %d (before trailing)", end, len(data)-5)
	}
}

func TestPNGBadCRC(t *testing.T) {
	data := testutil.PNG(4, 4)
	data[20] ^= 0xFF // corrupt IHDR body
	chunks, _, _ := png.Parse(data)
	if len(chunks) == 0 || chunks[0].CRCValid {
		t.Error("corrupted IHDR should have invalid CRC")
	}
}

func TestPNGTruncated(t *testing.T) {
	data := testutil.PNG(4, 4)
	if _, _, err := png.Parse(data[:20]); err == nil {
		t.Error("expected error for truncated PNG")
	}
}

func TestJPEGParse(t *testing.T) {
	data := testutil.JPEG(t, "hello")
	segs, end, err := jpeg.Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	if end != len(data) {
		t.Errorf("end = %d, want %d", end, len(data))
	}
	var hasCOM bool
	for _, s := range segs {
		if s.Marker == jpeg.COM && string(s.Data) == "hello" {
			hasCOM = true
		}
	}
	if !hasCOM {
		t.Error("COM segment not found")
	}
}

func TestJPEGTrailing(t *testing.T) {
	data := append(testutil.JPEG(t, ""), []byte("appended")...)
	if end := jpeg.End(data); end != len(data)-8 {
		t.Errorf("end = %d, want %d", end, len(data)-8)
	}
}

func TestRIFFParse(t *testing.T) {
	data := testutil.WAV([]byte{1, 2, 3, 4}, map[string]string{"ICMT": "hi"})
	form, chunks, end, err := riff.Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	if form != "WAVE" || end != len(data) {
		t.Errorf("form=%q end=%d (len %d)", form, end, len(data))
	}
	var hasInfo bool
	for _, c := range chunks {
		if c.ID == "LIST" && c.List == "INFO" {
			for _, sub := range c.Children {
				if sub.ID == "ICMT" {
					hasInfo = true
				}
			}
		}
	}
	if !hasInfo {
		t.Error("LIST/INFO/ICMT not parsed")
	}
}

func TestGIFParse(t *testing.T) {
	// Build a tiny GIF with a comment extension via raw bytes.
	data := []byte("GIF89a\x01\x00\x01\x00\x00\x00\x00") // header, no GCT
	data = append(data, 0x21, 0xFE, 0x05)                // comment extension, 5 bytes
	data = append(data, []byte("hello")...)
	data = append(data, 0x00) // block terminator
	data = append(data, 0x3B) // trailer
	info, err := gif.Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(info.Comments) != 1 || string(info.Comments[0].Text) != "hello" {
		t.Errorf("comments = %+v", info.Comments)
	}
	if info.End != len(data) {
		t.Errorf("end = %d, want %d", info.End, len(data))
	}
}

func FuzzPNG(f *testing.F) {
	f.Add(testutil.PNG(2, 2))
	f.Fuzz(func(t *testing.T, data []byte) { _, _, _ = png.Parse(data) })
}

func FuzzJPEG(f *testing.F) {
	f.Add([]byte{0xFF, 0xD8, 0xFF, 0xD9})
	f.Fuzz(func(t *testing.T, data []byte) { _, _, _ = jpeg.Parse(data) })
}

func FuzzRIFF(f *testing.F) {
	f.Add(testutil.WAV([]byte{1, 2}, nil))
	f.Fuzz(func(t *testing.T, data []byte) { _, _, _, _ = riff.Parse(data) })
}

func FuzzGIF(f *testing.F) {
	f.Add([]byte("GIF89a\x01\x00\x01\x00\x00\x00\x00\x3B"))
	f.Fuzz(func(t *testing.T, data []byte) { _, _ = gif.Parse(data) })
}
