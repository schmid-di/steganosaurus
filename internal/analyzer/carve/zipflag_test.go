package carve

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/schmid-di/steganosaurus/internal/testutil"
)

// encryptedZip returns a ZIP in which every entry's "encrypted" general
// purpose bit flag is set, so the reader treats it as password-protected.
// The bytes stay a structurally valid archive (we only flip a flag bit).
func encryptedZip(t *testing.T) []byte {
	t.Helper()
	data := testutil.Zip(map[string]string{"flag.txt": "unreadable"})
	// Local file header: signature PK\x03\x04, flags at offset 6.
	setBit := func(sig []byte, flagOffset int) {
		for off := 0; ; {
			i := bytes.Index(data[off:], sig)
			if i < 0 {
				return
			}
			p := off + i + flagOffset
			if p+2 <= len(data) {
				v := binary.LittleEndian.Uint16(data[p:])
				binary.LittleEndian.PutUint16(data[p:], v|zipEncrypted)
			}
			off = off + i + len(sig)
		}
	}
	setBit([]byte("PK\x03\x04"), 6) // local header flags
	setBit([]byte("PK\x01\x02"), 8) // central directory flags
	return data
}
