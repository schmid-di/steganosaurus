package exif

import (
	"encoding/binary"
	"testing"
)

// buildTIFF builds a little-endian TIFF with one IFD0 of ASCII entries
// (id→value). Values longer than 4 bytes are stored out-of-line.
func buildTIFF(entries []struct {
	id  uint16
	val string
}) []byte {
	hdr := []byte("II*\x00")
	hdr = binary.LittleEndian.AppendUint32(hdr, 8) // IFD0 at offset 8

	n := len(entries)
	ifd := make([]byte, 0, 2+n*12+4)
	ifd = binary.LittleEndian.AppendUint16(ifd, uint16(n))

	dataOff := 8 + 2 + n*12 + 4
	var extra []byte
	for _, e := range entries {
		v := append([]byte(e.val), 0)
		ifd = binary.LittleEndian.AppendUint16(ifd, e.id)
		ifd = binary.LittleEndian.AppendUint16(ifd, 2) // ASCII
		ifd = binary.LittleEndian.AppendUint32(ifd, uint32(len(v)))
		if len(v) <= 4 {
			field := make([]byte, 4)
			copy(field, v)
			ifd = append(ifd, field...)
		} else {
			ifd = binary.LittleEndian.AppendUint32(ifd, uint32(dataOff+len(extra)))
			extra = append(extra, v...)
		}
	}
	ifd = binary.LittleEndian.AppendUint32(ifd, 0) // no next IFD
	return append(append(hdr, ifd...), extra...)
}

func TestParseEntries(t *testing.T) {
	data := buildTIFF([]struct {
		id  uint16
		val string
	}{
		{0x010E, "THM{exif_description}"}, // ImageDescription
		{0x013B, "dino"},                  // Artist
		{0x0131, "Adobe Photoshop"},       // Software
	})
	res, err := Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"ImageDescription": "THM{exif_description}",
		"Artist":           "dino",
		"Software":         "Adobe Photoshop",
	}
	got := map[string]string{}
	for _, e := range res.Entries {
		got[e.Name] = e.Value
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %q, want %q", k, got[k], v)
		}
	}
}

func TestParseBadHeader(t *testing.T) {
	if _, err := Parse([]byte("not tiff")); err == nil {
		t.Error("expected header error")
	}
}

func TestStripPrefix(t *testing.T) {
	body, ok := StripPrefix([]byte("Exif\x00\x00II*\x00"))
	if !ok || string(body) != "II*\x00" {
		t.Errorf("StripPrefix = %q, %v", body, ok)
	}
}

func TestIFDLoopGuard(t *testing.T) {
	// IFD0 pointing at itself (offset 8) must not loop forever.
	data := []byte("II*\x00")
	data = binary.LittleEndian.AppendUint32(data, 8)
	data = binary.LittleEndian.AppendUint16(data, 0) // zero entries
	data = binary.LittleEndian.AppendUint32(data, 8) // next IFD = self
	if _, err := Parse(data); err != nil {
		t.Fatal(err)
	}
}

func FuzzParse(f *testing.F) {
	f.Add(buildTIFF([]struct {
		id  uint16
		val string
	}{{0x010E, "hi"}}))
	f.Add([]byte("MM\x00*\x00\x00\x00\x08"))
	f.Fuzz(func(t *testing.T, data []byte) { _, _ = Parse(data) })
}
