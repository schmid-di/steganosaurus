package carve

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/bzip2"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"path"
	"strings"

	"github.com/schmid-di/steganosaurus/internal/detect"
	"github.com/schmid-di/steganosaurus/internal/engine"
)

// archiveEntries extracts the members of an archive input as artifacts.
func archiveEntries(ctx context.Context, in *engine.Input) []engine.Finding {
	switch in.Type {
	case detect.ZIP:
		return unzip(ctx, in.Data)
	case detect.Tar:
		return untar(ctx, in.Data)
	case detect.Gzip:
		return gunzip(in.Data)
	case detect.Bzip2:
		return unbzip2(in.Data)
	}
	return nil
}

// encrypted ZIP general-purpose bit flag.
const zipEncrypted = 0x1

func unzip(ctx context.Context, data []byte) []engine.Finding {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil
	}
	var out []engine.Finding
	var encrypted []string
	files := 0
	for _, f := range zr.File {
		if ctx.Err() != nil || files >= maxArchiveFiles {
			break
		}
		if f.FileInfo().IsDir() {
			continue
		}
		files++
		name := cleanName(f.Name)
		if f.Flags&zipEncrypted != 0 {
			encrypted = append(encrypted, f.Name)
			continue
		}
		rc, err := f.Open()
		if err != nil {
			out = append(out, readError("ZIP", f.Name, err))
			continue
		}
		content, err := io.ReadAll(io.LimitReader(rc, maxEntrySize))
		rc.Close()
		if err != nil {
			out = append(out, readError("ZIP", f.Name, err))
			continue
		}
		out = append(out, entryFinding("ZIP", f.Name, name, content))
	}
	if len(encrypted) > 0 {
		out = append(out, engine.Finding{
			Title: fmt.Sprintf("Password-protected ZIP (%d encrypted %s)", len(encrypted), plural(len(encrypted), "entry", "entries")),
			Detail: "Encrypted entries: " + strings.Join(encrypted, ", ") +
				"\nThe password is often hidden elsewhere in the challenge (metadata, a note, the file name).",
			Score: 55,
		})
	}
	return out
}

func untar(ctx context.Context, data []byte) []engine.Finding {
	tr := tar.NewReader(bytes.NewReader(data))
	var out []engine.Finding
	files := 0
	for files < maxArchiveFiles {
		if ctx.Err() != nil {
			break
		}
		h, err := tr.Next()
		if err != nil {
			break
		}
		if h.Typeflag != tar.TypeReg {
			continue
		}
		files++
		content, err := io.ReadAll(io.LimitReader(tr, maxEntrySize))
		if err != nil {
			out = append(out, readError("tar", h.Name, err))
			continue
		}
		out = append(out, entryFinding("tar", h.Name, cleanName(h.Name), content))
	}
	return out
}

func gunzip(data []byte) []engine.Finding {
	zr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil
	}
	defer zr.Close()
	content, err := io.ReadAll(io.LimitReader(zr, maxEntrySize))
	if err != nil && len(content) == 0 {
		return []engine.Finding{readError("gzip", "", err)}
	}
	name := cleanName(zr.Name)
	if name == "" {
		name = "gunzipped.bin"
	}
	return []engine.Finding{entryFinding("gzip", zr.Name, name, content)}
}

func unbzip2(data []byte) []engine.Finding {
	content, err := io.ReadAll(io.LimitReader(bzip2.NewReader(bytes.NewReader(data)), maxEntrySize))
	if err != nil && len(content) == 0 {
		return []engine.Finding{readError("bzip2", "", err)}
	}
	return []engine.Finding{entryFinding("bzip2", "", "bunzipped.bin", content)}
}

func entryFinding(format, origName, safeName string, content []byte) engine.Finding {
	ft := detect.Detect(content)
	label := origName
	if label == "" {
		label = safeName
	}
	detail := fmt.Sprintf("Extracted from %s archive.", format)
	if ft != detect.Unknown {
		detail += " Detected type: " + string(ft) + "."
	}
	return engine.Finding{
		Title:    fmt.Sprintf("%s entry: %s (%d bytes)", format, label, len(content)),
		Detail:   detail,
		Score:    55,
		Artifact: &engine.Artifact{Name: safeName, Data: content},
	}
}

func readError(format, name string, err error) engine.Finding {
	return engine.Finding{
		Title:  fmt.Sprintf("%s entry %q could not be read", format, name),
		Detail: err.Error(),
		Score:  engine.ScoreLow,
	}
}

// cleanName reduces an archive path to a safe base name. Artifact names are
// sanitized again by the engine; this keeps the readable part.
func cleanName(name string) string {
	name = strings.ReplaceAll(name, "\\", "/")
	base := path.Base(path.Clean("/" + name))
	base = strings.TrimLeft(base, "/.")
	if base == "" || base == "." {
		return ""
	}
	return base
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
