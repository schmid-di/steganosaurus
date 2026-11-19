package decode

import (
	"bytes"
	"encoding/ascii85"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"math/big"
	"regexp"
	"strconv"
	"strings"
)

// Decoder converts an encoded string to bytes. ok is false when s is not a
// plausible instance of the encoding.
type Decoder struct {
	Name   string
	Decode func(s string) (out []byte, ok bool)
}

// Structural are decoders with a strict alphabet or syntax. Their validity
// check alone filters most false positives. Order sets priority on ties.
var Structural = []Decoder{
	{"binary", decodeBinary},
	{"decimal", decodeDecimal},
	{"morse", decodeMorse},
	{"hex", decodeHex},
	{"base32", decodeBase32},
	{"base64", decodeBase64},
	{"base64url", decodeBase64URL},
	{"base58", decodeBase58},
	{"ascii85", decodeASCII85},
}

// Rotations are letter substitutions; they apply to almost any text and are
// therefore only accepted when they demonstrably improve the result.
var Rotations = []Decoder{
	{"rot13", func(s string) ([]byte, bool) { return []byte(rot13(s)), true }},
	{"rot47", func(s string) ([]byte, bool) { return []byte(rot47(s)), true }},
}

var (
	reBinary  = regexp.MustCompile(`^[01]{8}(?:[ ,]?[01]{8})+$`)
	reDecimal = regexp.MustCompile(`^\d{2,3}(?:[ ,;]+\d{2,3}){3,}$`)
	reMorse   = regexp.MustCompile(`^[.\-_]{1,7}(?:(?: +| */ *|\|)[.\-_]{1,7}){2,}$`)
	reHex     = regexp.MustCompile(`^(?:[0-9a-fA-F]{2})+$`)
	reHexSep  = regexp.MustCompile(`^(?:(?:0x|\\x)?[0-9a-fA-F]{2}[ ,:]*){4,}$`)
	reB32     = regexp.MustCompile(`^[A-Z2-7]+=*$`)
	reB64     = regexp.MustCompile(`^[A-Za-z0-9+/]+={0,2}$`)
	reB64URL  = regexp.MustCompile(`^[A-Za-z0-9_-]+={0,2}$`)
	reB58     = regexp.MustCompile(`^[1-9A-HJ-NP-Za-km-z]+$`)
)

func decodeBinary(s string) ([]byte, bool) {
	if !reBinary.MatchString(s) {
		return nil, false
	}
	bits := strings.Map(func(r rune) rune {
		if r == '0' || r == '1' {
			return r
		}
		return -1
	}, s)
	out := make([]byte, len(bits)/8)
	for i := range out {
		v, err := strconv.ParseUint(bits[i*8:i*8+8], 2, 8)
		if err != nil {
			return nil, false
		}
		out[i] = byte(v)
	}
	return out, true
}

func decodeDecimal(s string) ([]byte, bool) {
	if !reDecimal.MatchString(s) {
		return nil, false
	}
	var out []byte
	for _, f := range strings.FieldsFunc(s, func(r rune) bool { return r == ' ' || r == ',' || r == ';' }) {
		v, err := strconv.Atoi(f)
		if err != nil || v < 9 || v > 126 {
			return nil, false
		}
		out = append(out, byte(v))
	}
	return out, true
}

var morseTable = map[string]byte{
	".-": 'A', "-...": 'B', "-.-.": 'C', "-..": 'D', ".": 'E', "..-.": 'F', "--.": 'G',
	"....": 'H', "..": 'I', ".---": 'J', "-.-": 'K', ".-..": 'L', "--": 'M', "-.": 'N',
	"---": 'O', ".--.": 'P', "--.-": 'Q', ".-.": 'R', "...": 'S', "-": 'T', "..-": 'U',
	"...-": 'V', ".--": 'W', "-..-": 'X', "-.--": 'Y', "--..": 'Z',
	"-----": '0', ".----": '1', "..---": '2', "...--": '3', "....-": '4', ".....": '5',
	"-....": '6', "--...": '7', "---..": '8', "----.": '9',
	".-.-.-": '.', "--..--": ',', "..--..": '?', "-.-.--": '!', "-..-.": '/',
	"-.--.": '(', "-.--.-": ')', "---...": ':', "-...-": '=', ".-.-.": '+',
	"-....-": '-', "..--.-": '_', ".--.-.": '@', ".----.": '\'',
}

func decodeMorse(s string) ([]byte, bool) {
	s = strings.TrimSpace(s)
	if !reMorse.MatchString(s) {
		return nil, false
	}
	s = strings.ReplaceAll(s, "_", "-")
	s = strings.ReplaceAll(s, "|", " / ")
	var out []byte
	for i, word := range strings.Split(s, "/") {
		if i > 0 {
			out = append(out, ' ')
		}
		for _, sym := range strings.Fields(word) {
			c, ok := morseTable[sym]
			if !ok {
				return nil, false
			}
			out = append(out, c)
		}
	}
	return bytes.TrimSpace(out), len(out) > 0
}

func decodeHex(s string) ([]byte, bool) {
	if len(s) < 8 {
		return nil, false
	}
	if !reHex.MatchString(s) {
		if !reHexSep.MatchString(s) {
			return nil, false
		}
		s = strings.NewReplacer("0x", "", "\\x", "", " ", "", ",", "", ":", "").Replace(s)
	}
	out, err := hex.DecodeString(s)
	return out, err == nil
}

func decodeBase32(s string) ([]byte, bool) {
	if len(s) < 8 || !reB32.MatchString(s) {
		return nil, false
	}
	enc := base32.StdEncoding
	if !strings.HasSuffix(s, "=") && len(s)%8 != 0 {
		enc = enc.WithPadding(base32.NoPadding)
	}
	out, err := enc.DecodeString(s)
	return out, err == nil && len(out) > 0
}

func decodeBase64(s string) ([]byte, bool) {
	return decodeB64(s, reB64, base64.StdEncoding, base64.RawStdEncoding)
}

func decodeBase64URL(s string) ([]byte, bool) {
	// Only relevant if URL-specific characters are present; otherwise it is
	// identical to standard Base64.
	if !strings.ContainsAny(s, "-_") {
		return nil, false
	}
	return decodeB64(s, reB64URL, base64.URLEncoding, base64.RawURLEncoding)
}

func decodeB64(s string, re *regexp.Regexp, padded, raw *base64.Encoding) ([]byte, bool) {
	if len(s) < 8 || !re.MatchString(s) {
		return nil, false
	}
	enc := padded
	if !strings.HasSuffix(s, "=") {
		if len(s)%4 == 1 {
			return nil, false
		}
		if len(s)%4 != 0 {
			enc = raw
		}
	}
	out, err := enc.DecodeString(s)
	return out, err == nil && len(out) > 0
}

const base58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

func decodeBase58(s string) ([]byte, bool) {
	if len(s) < 6 || len(s) > 4096 || !reB58.MatchString(s) {
		return nil, false
	}
	n := new(big.Int)
	radix := big.NewInt(58)
	for _, c := range []byte(s) {
		n.Mul(n, radix)
		n.Add(n, big.NewInt(int64(strings.IndexByte(base58Alphabet, c))))
	}
	out := n.Bytes()
	// Leading '1's encode leading zero bytes.
	for i := 0; i < len(s) && s[i] == '1'; i++ {
		out = append([]byte{0}, out...)
	}
	return out, len(out) > 0
}

func decodeASCII85(s string) ([]byte, bool) {
	inner, delimited := strings.CutPrefix(s, "<~")
	if delimited {
		inner = strings.TrimSuffix(inner, "~>")
	} else if len(s) < 10 {
		// Undelimited Ascii85 accepts almost any text; require some length.
		return nil, false
	}
	for _, c := range []byte(inner) {
		if (c < '!' || c > 'u') && c != 'z' {
			return nil, false
		}
	}
	out := make([]byte, len(inner)*4/5+4)
	n, _, err := ascii85.Decode(out, []byte(inner), true)
	return out[:n], err == nil && n > 0
}

func rot13(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z':
			return 'a' + (r-'a'+13)%26
		case r >= 'A' && r <= 'Z':
			return 'A' + (r-'A'+13)%26
		}
		return r
	}, s)
}

func rot47(s string) string {
	return strings.Map(func(r rune) rune {
		if r >= '!' && r <= '~' {
			return '!' + (r-'!'+47)%94
		}
		return r
	}, s)
}
