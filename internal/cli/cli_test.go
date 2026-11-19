package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func run(t *testing.T, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errOut bytes.Buffer
	code = Execute(args, &out, &errOut)
	return code, out.String(), errOut.String()
}

func writeFile(t *testing.T, name string, data string) (path, outDir string) {
	t.Helper()
	dir := t.TempDir()
	path = filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}
	return path, filepath.Join(dir, "out")
}

func TestScanFindsFlag(t *testing.T) {
	path, out := writeFile(t, "chall.jpg", "\x89PNG\r\n\x1a\n...THM{hello_dino}...")
	code, stdout, stderr := run(t, "scan", "-o", out, path)
	if code != ExitFlagFound {
		t.Fatalf("exit = %d, stderr = %s", code, stderr)
	}
	for _, want := range []string{"THM{hello_dino}", "does not match content"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("stdout missing %q:\n%s", want, stdout)
		}
	}
	if _, err := os.Stat(filepath.Join(out, "report.json")); err != nil {
		t.Errorf("report.json not written: %v", err)
	}
}

func TestScanNoFlag(t *testing.T) {
	path, out := writeFile(t, "plain.txt", "nothing to see")
	if code, _, stderr := run(t, "scan", "-o", out, path); code != ExitOK {
		t.Errorf("exit = %d, stderr = %s", code, stderr)
	}
}

func TestScanJSONAndQuiet(t *testing.T) {
	path, out := writeFile(t, "x.bin", "HTB{json}")
	_, stdout, _ := run(t, "scan", "--json", "-o", out, path)
	var doc struct {
		SchemaVersion int `json:"schema_version"`
		Flags         []struct{ Value string }
	}
	if err := json.Unmarshal([]byte(stdout), &doc); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, stdout)
	}
	if doc.SchemaVersion != 1 || len(doc.Flags) != 1 || doc.Flags[0].Value != "HTB{json}" {
		t.Errorf("doc = %+v", doc)
	}

	_, stdout, _ = run(t, "scan", "-q", "-o", out, path)
	if stdout != "HTB{json}\n" {
		t.Errorf("quiet stdout = %q", stdout)
	}
}

func TestCustomFlagFormat(t *testing.T) {
	path, out := writeFile(t, "x.bin", "DUCTF{custom}")
	_, stdout, _ := run(t, "scan", "-q", "--flag-format", `DUCTF\{[^}]+\}`, "-o", out, path)
	if stdout != "DUCTF{custom}\n" {
		t.Errorf("stdout = %q", stdout)
	}
}

func TestErrors(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{"missing file", []string{"scan", "/does/not/exist"}, "no such file"},
		{"no args", []string{"scan"}, "exactly one file"},
		{"bad regex", []string{"scan", "--flag-format", "(", "x"}, "invalid flag format"},
		{"verbose and quiet", []string{"scan", "-v", "-q", "x"}, "none of the others"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, _, stderr := run(t, tt.args...)
			if code != ExitError || !strings.Contains(stderr, tt.want) {
				t.Errorf("exit = %d, stderr = %q, want %q", code, stderr, tt.want)
			}
		})
	}
}

func TestVersion(t *testing.T) {
	code, stdout, _ := run(t, "version")
	if code != ExitOK || !strings.HasPrefix(stdout, "steganosaurus ") {
		t.Errorf("exit = %d, stdout = %q", code, stdout)
	}
}
