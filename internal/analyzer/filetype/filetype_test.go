package filetype

import (
	"context"
	"testing"

	"github.com/schmid-di/steganosaurus/internal/detect"
	"github.com/schmid-di/steganosaurus/internal/engine"
)

func analyze(t *testing.T, name string, data []byte) []engine.Finding {
	t.Helper()
	in := &engine.Input{Name: name, Data: data, Type: detect.Detect(data)}
	fs, err := New().Analyze(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	return fs
}

func TestMatchingExtension(t *testing.T) {
	fs := analyze(t, "a.png", []byte("\x89PNG\r\n\x1a\n"))
	if len(fs) != 1 || fs[0].Score != engine.ScoreInfo {
		t.Errorf("findings = %+v", fs)
	}
}

func TestMismatch(t *testing.T) {
	fs := analyze(t, "secret.jpg", []byte("PK\x03\x04"))
	if len(fs) != 2 || fs[1].Score != engine.ScoreMedium {
		t.Fatalf("findings = %+v", fs)
	}
}

func TestUnknown(t *testing.T) {
	fs := analyze(t, "x.png", []byte("garbage"))
	if len(fs) != 1 || fs[0].Title != "Unknown file type" {
		t.Errorf("findings = %+v", fs)
	}
}
