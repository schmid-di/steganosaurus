package detect

import (
	"encoding/binary"
	"testing"
)

func bmpHeader() []byte {
	b := make([]byte, 54)
	copy(b, "BM")
	binary.LittleEndian.PutUint32(b[14:18], 40)
	return b
}

func peHeader() []byte {
	b := make([]byte, 0x80)
	copy(b, "MZ")
	binary.LittleEndian.PutUint32(b[0x3c:0x40], 0x40)
	copy(b[0x40:], "PE\x00\x00")
	return b
}

func tarHeader() []byte {
	b := make([]byte, 512)
	copy(b[257:], "ustar")
	return b
}

func TestDetect(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want FileType
	}{
		{"png", []byte("\x89PNG\r\n\x1a\n\x00\x00\x00\x0dIHDR"), PNG},
		{"jpeg", []byte("\xff\xd8\xff\xe0\x00\x10JFIF"), JPEG},
		{"gif87", []byte("GIF87a...."), GIF},
		{"gif89", []byte("GIF89a...."), GIF},
		{"bmp", bmpHeader(), BMP},
		{"bm text is not bmp", []byte("BMW is a car brand, not a bitmap"), Unknown},
		{"wav", []byte("RIFF\x24\x00\x00\x00WAVEfmt "), WAV},
		{"riff avi is not wav", []byte("RIFF\x24\x00\x00\x00AVI LIST"), Unknown},
		{"zip", []byte("PK\x03\x04\x14\x00"), ZIP},
		{"empty zip", []byte("PK\x05\x06" + string(make([]byte, 18))), ZIP},
		{"rar", []byte("Rar!\x1a\x07\x01\x00"), RAR},
		{"7z", []byte("7z\xbc\xaf\x27\x1c\x00\x04"), SevenZip},
		{"gzip", []byte("\x1f\x8b\x08\x00"), Gzip},
		{"bzip2", []byte("BZh91AY&SY"), Bzip2},
		{"xz", []byte("\xfd7zXZ\x00\x00"), XZ},
		{"pdf", []byte("%PDF-1.7\n"), PDF},
		{"elf", []byte("\x7fELF\x02\x01\x01"), ELF},
		{"pe", peHeader(), PE},
		{"tar", tarHeader(), Tar},
		{"text", []byte("hello world"), Unknown},
		{"empty", nil, Unknown},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Detect(tt.data); got != tt.want {
				t.Errorf("Detect() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestExtensionMismatch(t *testing.T) {
	tests := []struct {
		typ  FileType
		name string
		want bool
	}{
		{PNG, "image.png", false},
		{PNG, "IMAGE.PNG", false},
		{PNG, "image.jpg", true},
		{JPEG, "photo.jpeg", false},
		{ZIP, "secret.png", true},
		{PNG, "noext", false},
		{Unknown, "file.png", false},
	}
	for _, tt := range tests {
		if got := ExtensionMismatch(tt.typ, tt.name); got != tt.want {
			t.Errorf("ExtensionMismatch(%q, %q) = %v, want %v", tt.typ, tt.name, got, tt.want)
		}
	}
}

func FuzzDetect(f *testing.F) {
	f.Add([]byte("\x89PNG\r\n\x1a\n"))
	f.Add(bmpHeader())
	f.Add(peHeader())
	f.Fuzz(func(t *testing.T, data []byte) {
		_ = Detect(data)
	})
}
