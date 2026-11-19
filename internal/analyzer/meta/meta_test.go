package meta

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/schmid-di/steganosaurus/internal/detect"
	"github.com/schmid-di/steganosaurus/internal/engine"
	"github.com/schmid-di/steganosaurus/internal/flag"
	"github.com/schmid-di/steganosaurus/internal/testutil"
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

// titles joins finding titles for substring assertions.
func titles(fs []engine.Finding) string {
	var b strings.Builder
	for _, f := range fs {
		b.WriteString(f.Title)
		b.WriteString(" || ")
		b.WriteString(f.Detail)
		b.WriteString("\n")
	}
	return b.String()
}

func has(t *testing.T, fs []engine.Finding, want string) {
	t.Helper()
	if !strings.Contains(titles(fs), want) {
		t.Errorf("missing %q in:\n%s", want, titles(fs))
	}
}

func TestPNGTextChunks(t *testing.T) {
	png := testutil.PNGWithChunks(4, 4, []testutil.PNGChunk{
		testutil.TextChunk("Comment", "THM{png_text}"),
		testutil.ZTextChunk("Secret", "the password is dino"),
		testutil.TextChunk("Software", "GIMP 2.10"),
	})
	fs := run(t, png)
	has(t, fs, "THM{png_text}")
	has(t, fs, "the password is dino")
	// The flag is found; a Software value is not promoted to a top finding.
	for _, f := range fs {
		if strings.Contains(f.Title, "Software") && f.Score >= engine.ScoreLow {
			t.Errorf("Software should be low-scored, got %+v", f)
		}
	}
}

func TestPNGEncodedChunk(t *testing.T) {
	enc := base64.StdEncoding.EncodeToString([]byte("HTB{base64_in_png}"))
	png := testutil.PNGWithChunks(4, 4, []testutil.PNGChunk{testutil.TextChunk("note", enc)})
	fs := run(t, png)
	has(t, fs, "decodes via base64")
	var found bool
	for _, f := range fs {
		for _, fl := range f.Flags {
			if fl == "HTB{base64_in_png}" {
				found = true
			}
		}
		if strings.Contains(f.Detail, "HTB{base64_in_png}") {
			found = true
		}
	}
	if !found {
		t.Errorf("decoded flag not surfaced:\n%s", titles(fs))
	}
}

func TestJPEGComment(t *testing.T) {
	fs := run(t, testutil.JPEG(t, "flag{jpeg_comment}"))
	has(t, fs, "flag{jpeg_comment}")
}

func TestJPEGBoringComment(t *testing.T) {
	fs := run(t, testutil.JPEG(t, "Created with GIMP"))
	for _, f := range fs {
		if strings.Contains(f.Title, "Comment:") && f.Score >= engine.ScoreLow {
			t.Errorf("boring comment promoted: %+v", f)
		}
	}
}

func TestWAVInfo(t *testing.T) {
	wav := testutil.WAV([]byte{1, 2, 3, 4}, map[string]string{"ICMT": "CTF{wav_info}", "ISFT": "Lavf"})
	has(t, run(t, wav), "CTF{wav_info}")
}

func TestNoMetadata(t *testing.T) {
	fs := run(t, testutil.PNG(4, 4))
	for _, f := range fs {
		if f.Score >= engine.ScoreLow {
			t.Errorf("clean PNG produced a notable finding: %+v", f)
		}
	}
}
