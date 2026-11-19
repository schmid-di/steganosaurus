package decode

import (
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/schmid-di/steganosaurus/internal/detect"
	"github.com/schmid-di/steganosaurus/internal/flag"
)

func flagCheck(t *testing.T) FlagChecker {
	m, err := flag.NewMatcher()
	if err != nil {
		t.Fatal(err)
	}
	return func(b []byte) bool { return len(m.Find(b)) > 0 }
}

func TestDecoders(t *testing.T) {
	tests := []struct {
		dec, in, want string
	}{
		{"binary", "01100110 01101100 01100001 01100111", "flag"},
		{"binary", "01100110011011000110000101100111", "flag"},
		{"decimal", "102 108 97 103", "flag"},
		{"decimal", "72,105,33,33", "Hi!!"},
		{"morse", ".... . .-.. .-.. --- / .-- --- .-. .-.. -..", "HELLO WORLD"},
		{"morse", "..-. .-.. .- --.", "FLAG"},
		{"hex", "666c6167", "flag"},
		{"hex", "0x66 0x6c 0x61 0x67", "flag"},
		{"hex", `\x66\x6c\x61\x67`, "flag"},
		{"base32", "MZWGCZ33NBSWY3DPPU======", "flag{hello}"},
		{"base32", "MZWGCZ33NBSWY3DPPU", "flag{hello}"},
		{"base64", "ZmxhZ3toZWxsb30=", "flag{hello}"},
		{"base64", "ZmxhZ3toZWxsb30", "flag{hello}"},
		{"base64url", "Pz8_Pz8-Pj4-", "?????>>>>"},
		{"base58", "StV1DL6CwTryKyV", "hello world"},
		{"ascii85", "<~BOu!rD]j7BEbo7~>", "hello world"},
		{"ascii85", "BOu!rD]j7BEbo7", "hello world"},
	}
	all := append(append([]Decoder{}, Structural...), Rotations...)
	for _, tt := range tests {
		t.Run(tt.dec+"/"+tt.in, func(t *testing.T) {
			for _, d := range all {
				if d.Name != tt.dec {
					continue
				}
				out, ok := d.Decode(tt.in)
				if !ok || string(out) != tt.want {
					t.Errorf("%s(%q) = %q, %v; want %q", d.Name, tt.in, out, ok, tt.want)
				}
				return
			}
			t.Fatalf("decoder %q not found", tt.dec)
		})
	}
}

func TestDecodersReject(t *testing.T) {
	rejects := map[string][]string{
		"binary":  {"0110", "01100110 2"},
		"decimal": {"102 108", "2023 11 19 20", "300 301 302 303"},
		"morse":   {"-", "....", "a-b-c"},
		"hex":     {"abc", "xyz12345", "abcdef1"},
		"base32":  {"short", "lowercase=="},
		"base64":  {"short", "has spaces in it", "abcde"},
		"base58":  {"0OIl00", "abc"},
		"ascii85": {"short", "<~vvvvv~>"},
	}
	for _, d := range Structural {
		for _, in := range rejects[d.Name] {
			if out, ok := d.Decode(in); ok {
				t.Errorf("%s(%q) accepted: %q", d.Name, in, out)
			}
		}
	}
}

func TestRotations(t *testing.T) {
	if got := rot13("GUZ{ebg_guvegrra}"); got != "THM{rot_thirteen}" {
		t.Errorf("rot13 = %q", got)
	}
	if got := rot47(rot47("flag{x}")); got != "flag{x}" {
		t.Errorf("rot47 is not an involution: %q", got)
	}
}

func TestChains(t *testing.T) {
	check := flagCheck(t)
	b64 := func(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

	tests := []struct {
		name     string
		in       string
		decoders string
		final    string
	}{
		{"base64", b64("THM{simple}"), "base64", "THM{simple}"},
		{"base64 of hex", b64(hex.EncodeToString([]byte("HTB{two_steps}"))), "base64 → hex", "HTB{two_steps}"},
		{"triple base64", b64(b64(b64("flag{three}"))), "base64 → base64 → base64", "flag{three}"},
		{"rot13 of base64", rot13(b64("flag{rotated_b64}")), "rot13 → base64", "flag{rotated_b64}"},
		{"base64 of rot13", b64(rot13("THM{inner_rot}")), "base64 → rot13", "THM{inner_rot}"},
		{"plain rot13 flag", "GUZ{ebg_guvegrra}", "rot13", "THM{rot_thirteen}"},
		{"rot47", rot47("picoCTF{r0t47_w0rks}"), "rot47", "picoCTF{r0t47_w0rks}"},
		{"binary text", "01110000 01100001 01110011 01110011 01110111 01101111 01110010 01100100", "binary", "password"},
		{"readable sentence", b64("the password is dinosaur"), "base64", "the password is dinosaur"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res, ok := Chain(tt.in, check)
			if !ok {
				t.Fatalf("Chain(%q) not ok: %+v", tt.in, res)
			}
			if res.Decoders() != tt.decoders || string(res.Final) != tt.final {
				t.Errorf("Chain(%q) = %s → %q, want %s → %q", tt.in, res.Decoders(), res.Final, tt.decoders, tt.final)
			}
		})
	}
}

func TestChainFindsFile(t *testing.T) {
	png := "\x89PNG\r\n\x1a\n\x00\x00\x00\x0dIHDR"
	res, ok := Chain(base64.StdEncoding.EncodeToString([]byte(png)), nil)
	if !ok || res.FileType != detect.PNG {
		t.Errorf("expected PNG, got %+v", res)
	}
}

func TestChainRejectsNoise(t *testing.T) {
	check := flagCheck(t)
	noise := []string{
		"Software", "Photoshop", "Adobe ImageReady", "deadbeefcafebabe", "20231119",
		"IHDR", "JFIF", "sRGB", "hello world", "This is a normal sentence.",
		"xmp.did:A1B2C3D4E5F6", "ICC_PROFILE", "Exif", "http://ns.adobe.com/xap/1.0/",
		"abcdefghijklmnop", "ABCDEFGHIJKLMNOP", "1234567890",
	}
	for _, s := range noise {
		if res, ok := Chain(s, check); ok {
			t.Errorf("Chain(%q) false positive: %s → %q", s, res.Decoders(), res.Final)
		}
	}
}

func TestReadability(t *testing.T) {
	readable := []string{"the password is dinosaur", "password: stegosaurus", "Hello World", "HELLO WORLD"}
	for _, s := range readable {
		if !IsReadable([]byte(s)) {
			t.Errorf("IsReadable(%q) = false (%.2f)", s, Readability([]byte(s)))
		}
	}
	unreadable := []string{"\x00\x01\x02\x03\x04", "\xff\xfe\x89\x12abc", "x8Q#z!", "qxzkvbnmwrtp", "V%6gBv26", "ZmxhZ3toZWxsb30="}
	for _, s := range unreadable {
		if IsReadable([]byte(s)) {
			t.Errorf("IsReadable(%q) = true (%.2f)", s, Readability([]byte(s)))
		}
	}
}

func TestEntropy(t *testing.T) {
	if e := Entropy([]byte(strings.Repeat("a", 100))); e != 0 {
		t.Errorf("entropy of constant = %v", e)
	}
	all := make([]byte, 256)
	for i := range all {
		all[i] = byte(i)
	}
	if e := Entropy(all); e != 8 {
		t.Errorf("entropy of all bytes = %v", e)
	}
}

func FuzzChain(f *testing.F) {
	f.Add("ZmxhZ3toZWxsb30=")
	f.Add(".... . .-.. .-.. ---")
	f.Add("<~BOu!rD]j7BEbo7~>")
	f.Fuzz(func(t *testing.T, s string) {
		_, _ = Chain(s, nil)
	})
}
