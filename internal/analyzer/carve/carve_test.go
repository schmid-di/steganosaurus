package carve

import (
	"bytes"
	"compress/gzip"
	"context"
	"strings"
	"testing"

	"github.com/schmid-di/steganosaurus/internal/detect"
	"github.com/schmid-di/steganosaurus/internal/engine"
	"github.com/schmid-di/steganosaurus/internal/testutil"
)

func run(t *testing.T, data []byte) []engine.Finding {
	t.Helper()
	in := &engine.Input{Name: "t", Data: data, Type: detect.Detect(data)}
	fs, err := New().Analyze(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	return fs
}

// artifactNamed returns the first artifact whose data matches pred.
func findArtifact(fs []engine.Finding, pred func([]byte) bool) *engine.Artifact {
	for _, f := range fs {
		if f.Artifact != nil && pred(f.Artifact.Data) {
			return f.Artifact
		}
	}
	return nil
}

func TestAppendedZipAfterPNG(t *testing.T) {
	zipData := testutil.Zip(map[string]string{"secret.txt": "THM{appended_zip}"})
	data := append(testutil.PNG(8, 8), zipData...)
	fs := run(t, data)

	art := findArtifact(fs, func(b []byte) bool { return detect.Detect(b) == detect.ZIP })
	if art == nil {
		t.Fatalf("appended ZIP not carved:\n%s", summarize(fs))
	}
	if !bytes.Equal(art.Data, zipData) {
		t.Error("carved ZIP bytes differ from original")
	}
	// Trailing finding should be high-value.
	var hi bool
	for _, f := range fs {
		if strings.Contains(f.Title, "Appended data") && f.Score >= 70 {
			hi = true
		}
	}
	if !hi {
		t.Errorf("appended data not scored highly:\n%s", summarize(fs))
	}
}

func TestZipEntriesExtracted(t *testing.T) {
	zipData := testutil.Zip(map[string]string{
		"note.txt":     "look deeper",
		"dir/flag.txt": "HTB{inside_zip}",
	})
	fs := run(t, zipData)
	if findArtifact(fs, func(b []byte) bool { return string(b) == "HTB{inside_zip}" }) == nil {
		t.Errorf("zip entry not extracted:\n%s", summarize(fs))
	}
}

func TestEmbeddedPNGInData(t *testing.T) {
	inner := testutil.PNGWithChunks(4, 4, []testutil.PNGChunk{testutil.TextChunk("c", "flag{inner}")})
	data := append([]byte("RANDOM PADDING DATA ___________ "), inner...)
	data = append(data, []byte(" ___ trailing junk")...)
	fs := run(t, data)
	art := findArtifact(fs, func(b []byte) bool { return detect.Detect(b) == detect.PNG })
	if art == nil {
		t.Fatalf("embedded PNG not found:\n%s", summarize(fs))
	}
	if !bytes.Equal(art.Data, inner) {
		t.Errorf("embedded PNG not delimited correctly: got %d bytes, want %d", len(art.Data), len(inner))
	}
}

func TestGzipExtracted(t *testing.T) {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	zw.Write([]byte("picoCTF{gzip}"))
	zw.Close()
	fs := run(t, buf.Bytes())
	if findArtifact(fs, func(b []byte) bool { return string(b) == "picoCTF{gzip}" }) == nil {
		t.Errorf("gzip not extracted:\n%s", summarize(fs))
	}
}

func TestEncryptedZipReported(t *testing.T) {
	// Build a ZIP whose entry has the encrypted flag bit set. We cannot use
	// archive/zip to encrypt, so flip the general-purpose bit in a stored
	// entry's local and central headers.
	data := encryptedZip(t)
	fs := run(t, data)
	var reported bool
	for _, f := range fs {
		if strings.Contains(f.Title, "Password-protected ZIP") {
			reported = true
		}
	}
	if !reported {
		t.Errorf("encrypted ZIP not reported:\n%s", summarize(fs))
	}
}

func TestCleanPNGNoCarve(t *testing.T) {
	for _, f := range run(t, testutil.PNG(16, 16)) {
		if f.Artifact != nil {
			t.Errorf("clean PNG produced artifact: %+v", f.Title)
		}
	}
}

func TestTrailingZerosIgnored(t *testing.T) {
	data := append(testutil.PNG(8, 8), make([]byte, 100)...)
	for _, f := range run(t, data) {
		if strings.Contains(f.Title, "Appended") {
			t.Errorf("padding zeros reported as appended data")
		}
	}
}

func summarize(fs []engine.Finding) string {
	var b strings.Builder
	for _, f := range fs {
		b.WriteString(f.Title)
		if f.Artifact != nil {
			b.WriteString(" [artifact " + f.Artifact.Name + "]")
		}
		b.WriteByte('\n')
	}
	return b.String()
}

func FuzzCarve(f *testing.F) {
	f.Add(append(testutil.PNG(4, 4), testutil.Zip(map[string]string{"a": "b"})...))
	f.Add(testutil.Zip(map[string]string{"x.txt": "data"}))
	f.Add([]byte("PK\x03\x04 garbage \xff\xd8\xff more"))
	a := New()
	f.Fuzz(func(t *testing.T, data []byte) {
		in := &engine.Input{Name: "f", Data: data, Type: detect.Detect(data)}
		_, _ = a.Analyze(context.Background(), in)
	})
}
