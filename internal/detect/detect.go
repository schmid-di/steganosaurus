// Package detect identifies file types by their magic bytes.
//
// The file extension is never used to determine the type; it is only
// compared against the detected type to report mismatches.
package detect

import (
	"bytes"
	"encoding/binary"
	"path/filepath"
	"slices"
	"strings"
)

// FileType is a detected file format.
type FileType string

// Known file types.
const (
	Unknown  FileType = "unknown"
	PNG      FileType = "png"
	JPEG     FileType = "jpeg"
	BMP      FileType = "bmp"
	GIF      FileType = "gif"
	WAV      FileType = "wav"
	ZIP      FileType = "zip"
	RAR      FileType = "rar"
	SevenZip FileType = "7z"
	Gzip     FileType = "gzip"
	Bzip2    FileType = "bzip2"
	XZ       FileType = "xz"
	Tar      FileType = "tar"
	PDF      FileType = "pdf"
	ELF      FileType = "elf"
	PE       FileType = "pe"
)

type signature struct {
	typ   FileType
	match func([]byte) bool
	exts  []string
}

func prefix(p string) func([]byte) bool {
	return func(b []byte) bool { return bytes.HasPrefix(b, []byte(p)) }
}

// signatures is ordered: more specific checks come first.
var signatures = []signature{
	{PNG, prefix("\x89PNG\r\n\x1a\n"), []string{".png"}},
	{JPEG, prefix("\xff\xd8\xff"), []string{".jpg", ".jpeg", ".jfif", ".jpe"}},
	{GIF, func(b []byte) bool {
		return bytes.HasPrefix(b, []byte("GIF87a")) || bytes.HasPrefix(b, []byte("GIF89a"))
	}, []string{".gif"}},
	{BMP, isBMP, []string{".bmp", ".dib"}},
	{WAV, func(b []byte) bool { return len(b) >= 12 && string(b[0:4]) == "RIFF" && string(b[8:12]) == "WAVE" }, []string{".wav", ".wave"}},
	{ZIP, func(b []byte) bool {
		return bytes.HasPrefix(b, []byte("PK\x03\x04")) || bytes.HasPrefix(b, []byte("PK\x05\x06"))
	}, []string{".zip", ".jar", ".apk", ".docx", ".xlsx", ".pptx", ".odt"}},
	{RAR, func(b []byte) bool { return bytes.HasPrefix(b, []byte("Rar!\x1a\x07")) }, []string{".rar"}},
	{SevenZip, prefix("7z\xbc\xaf\x27\x1c"), []string{".7z"}},
	{Gzip, prefix("\x1f\x8b"), []string{".gz", ".tgz"}},
	{Bzip2, prefix("BZh"), []string{".bz2", ".tbz2"}},
	{XZ, prefix("\xfd7zXZ\x00"), []string{".xz", ".txz"}},
	{PDF, prefix("%PDF-"), []string{".pdf"}},
	{ELF, prefix("\x7fELF"), []string{"", ".elf", ".so", ".o", ".bin"}},
	{PE, isPE, []string{".exe", ".dll", ".sys"}},
	{Tar, func(b []byte) bool { return len(b) >= 262 && string(b[257:262]) == "ustar" }, []string{".tar"}},
}

// isBMP checks the "BM" magic plus a plausible DIB header size, since two
// ASCII bytes alone produce too many false positives.
func isBMP(b []byte) bool {
	if len(b) < 18 || b[0] != 'B' || b[1] != 'M' {
		return false
	}
	switch binary.LittleEndian.Uint32(b[14:18]) {
	case 12, 16, 40, 52, 56, 64, 108, 124:
		return true
	}
	return false
}

// isPE checks the "MZ" magic and, if available, the "PE\0\0" header it points to.
func isPE(b []byte) bool {
	if len(b) < 2 || b[0] != 'M' || b[1] != 'Z' {
		return false
	}
	if len(b) < 0x40 {
		return true
	}
	off := int(binary.LittleEndian.Uint32(b[0x3c:0x40]))
	return off+4 <= len(b) && string(b[off:off+4]) == "PE\x00\x00"
}

// Detect returns the file type of data based on its magic bytes.
func Detect(data []byte) FileType {
	for _, s := range signatures {
		if s.match(data) {
			return s.typ
		}
	}
	return Unknown
}

// Extensions returns the common file extensions (lower case, with dot) for t.
func (t FileType) Extensions() []string {
	for _, s := range signatures {
		if s.typ == t {
			return s.exts
		}
	}
	return nil
}

// IsImage reports whether t is a raster image format.
func (t FileType) IsImage() bool {
	return t == PNG || t == JPEG || t == BMP || t == GIF
}

// ExtensionMismatch reports whether the extension of name contradicts the
// detected type t. Unknown types and names without extension never mismatch.
func ExtensionMismatch(t FileType, name string) bool {
	ext := strings.ToLower(filepath.Ext(name))
	if t == Unknown || ext == "" {
		return false
	}
	return !slices.Contains(t.Extensions(), ext)
}
