package strings

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/schmid-di/steganosaurus/internal/detect"
	"github.com/schmid-di/steganosaurus/internal/engine"
	"github.com/schmid-di/steganosaurus/internal/flag"
)

func run(t *testing.T, data []byte) []engine.Finding {
	t.Helper()
	m, err := flag.NewMatcher()
	if err != nil {
		t.Fatal(err)
	}
	in := &engine.Input{Name: "t", Data: data, Type: detect.Detect(data), Matcher: m}
	fs, err := New().Analyze(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	return fs
}

func dump(fs []engine.Finding) string {
	var b strings.Builder
	for _, f := range fs {
		b.WriteString(f.Title + " || " + f.Detail + "\n")
	}
	return b.String()
}

func TestExtractASCII(t *testing.T) {
	data := []byte("\x00\x01hello world\xff\xfeshort\x00abcdefgh")
	got := Extract(data, 6)
	var values []string
	for _, s := range got {
		values = append(values, s.Value)
	}
	want := map[string]bool{"hello world": true, "abcdefgh": true}
	for _, v := range values {
		delete(want, v)
	}
	if len(want) != 0 {
		t.Errorf("missing strings %v in %v", want, values)
	}
	for _, v := range values {
		if v == "short" {
			t.Error("string below min length extracted")
		}
	}
}

func TestExtractUTF16(t *testing.T) {
	// "flag42" as UTF-16LE.
	var le []byte
	for _, c := range "flag42" {
		le = append(le, byte(c), 0)
	}
	got := Extract(append([]byte{0xff}, le...), 6)
	var found bool
	for _, s := range got {
		if s.Value == "flag42" && s.Encoding == "utf16le" {
			found = true
		}
	}
	if !found {
		t.Errorf("UTF-16LE string not found: %+v", got)
	}
}

func TestEncodedStringDecoded(t *testing.T) {
	enc := base64.StdEncoding.EncodeToString([]byte("THM{strings_decode}"))
	data := []byte("prefix junk \x00 key=" + enc + " \x00 suffix")
	fs := run(t, data)
	if !strings.Contains(dump(fs), "THM{strings_decode}") {
		t.Errorf("encoded flag in string not decoded:\n%s", dump(fs))
	}
}

func TestInterestingString(t *testing.T) {
	data := []byte("\x00\x00random data here\x00password: hunter2\x00\x00more padding bytes")
	fs := run(t, data)
	var found bool
	for _, f := range fs {
		if strings.Contains(f.Title, "Interesting string") && strings.Contains(f.Title, "password") {
			found = true
		}
	}
	if !found {
		t.Errorf("password hint not flagged:\n%s", dump(fs))
	}
}

func TestPlainTextInput(t *testing.T) {
	// A text artifact (unknown type, printable) is shown and decoded whole.
	enc := base64.StdEncoding.EncodeToString([]byte("flag{multiline}"))
	// Wrap at a column to force whole-input decoding.
	wrapped := enc[:4] + "\n" + enc[4:]
	fs := run(t, []byte(wrapped))
	if !strings.Contains(dump(fs), "flag{multiline}") {
		t.Errorf("whitespace-wrapped base64 not decoded:\n%s", dump(fs))
	}
}

func TestNoStringsNoSummary(t *testing.T) {
	fs := run(t, []byte{0x00, 0x01, 0x02, 0x03})
	for _, f := range fs {
		if strings.Contains(f.Title, "strings") {
			t.Errorf("summary emitted for binary with no strings: %+v", f)
		}
	}
}

func FuzzAnalyze(f *testing.F) {
	f.Add([]byte("key=ZmxhZ3t4fQ=="))
	f.Add([]byte("\x00\x01hello world\x00"))
	m, _ := flag.NewMatcher()
	a := New()
	f.Fuzz(func(t *testing.T, data []byte) {
		in := &engine.Input{Name: "f", Data: data, Type: detect.Detect(data), Matcher: m}
		_, _ = a.Analyze(context.Background(), in)
	})
}
