package engine_test

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/schmid-di/steganosaurus/internal/analyzer"
	"github.com/schmid-di/steganosaurus/internal/engine"
	"github.com/schmid-di/steganosaurus/internal/flag"
	"github.com/schmid-di/steganosaurus/internal/testutil"
)

func scan(t *testing.T, name string, data []byte) *engine.Result {
	t.Helper()
	m, err := flag.NewMatcher()
	if err != nil {
		t.Fatal(err)
	}
	eng := engine.New(engine.Options{MaxDepth: 5, Matcher: m}, analyzer.All()...)
	res, err := eng.Run(context.Background(), name, data)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func flagValues(res *engine.Result) []string {
	var out []string
	for _, f := range res.Flags {
		out = append(out, f.Value)
	}
	return out
}

// TestLayeredChallenge is the M2 acceptance test: a cover PNG (named .jpg)
// with an appended ZIP that contains a PNG whose tEXt chunk holds a
// base64-encoded flag. A single `scan` must solve all layers.
func TestLayeredChallenge(t *testing.T) {
	inner := testutil.PNGWithChunks(4, 4, []testutil.PNGChunk{
		testutil.TextChunk("note", "VEhNe2wzdmVsXzNfZDFub3NhdXJ9"), // base64 THM{l3vel_3_d1nosaur}
	})
	zipBytes := testutil.Zip(map[string]string{"stage3.png": string(inner)})
	data := append(testutil.PNG(32, 32), zipBytes...)

	res := scan(t, "challenge.jpg", data)

	if !slices.Contains(flagValues(res), "THM{l3vel_3_d1nosaur}") {
		t.Fatalf("flag not recovered; flags = %v", flagValues(res))
	}
	// The flag's provenance must record every layer it passed through.
	var prov []string
	for _, f := range res.Flags {
		if f.Value == "THM{l3vel_3_d1nosaur}" {
			prov = f.Provenance
		}
	}
	chain := strings.Join(prov, " > ")
	for _, want := range []string{"challenge.jpg", "trailing.zip", "stage3.png"} {
		if !strings.Contains(chain, want) {
			t.Errorf("provenance %q missing %q", chain, want)
		}
	}
}

func TestExifFlag(t *testing.T) {
	// EXIF ImageDescription via a PNG eXIf chunk is out of M2 scope for the
	// builder; this guards the simpler JPEG comment path end to end.
	res := scan(t, "pic.jpg", testutil.JPEG(t, "HTB{comment_flag}"))
	if !slices.Contains(flagValues(res), "HTB{comment_flag}") {
		t.Errorf("flags = %v", flagValues(res))
	}
}

func TestCleanFileNoFlags(t *testing.T) {
	res := scan(t, "clean.png", testutil.PNG(24, 24))
	if len(res.Flags) != 0 {
		t.Errorf("clean file produced flags: %v", flagValues(res))
	}
	if len(res.Errors) != 0 {
		t.Errorf("clean file produced analyzer errors: %+v", res.Errors)
	}
}
