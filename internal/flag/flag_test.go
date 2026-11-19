package flag

import (
	"slices"
	"testing"
)

func TestFindDefaults(t *testing.T) {
	m, err := NewMatcher()
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		in   string
		want []string
	}{
		{"thm", "xx THM{st3g0_is_fun} yy", []string{"THM{st3g0_is_fun}"}},
		{"htb", "HTB{b1ts_n_byt3s}", []string{"HTB{b1ts_n_byt3s}"}},
		{"pico not cut to CTF", "picoCTF{r3d_1s_th3_ult1m4t3}", []string{"picoCTF{r3d_1s_th3_ult1m4t3}"}},
		{"lower and upper flag", "flag{a} FLAG{b}", []string{"flag{a}", "FLAG{b}"}},
		{"duplicates once", "CTF{x}CTF{x}", []string{"CTF{x}"}},
		{"embedded in binary", "\x00\x89THM{bin}\xff", []string{"THM{bin}"}},
		{"spaces allowed", "flag{hello world}", []string{"flag{hello world}"}},
		{"empty body rejected", "flag{}", nil},
		{"nested brace rejected", "flag{a{b}", nil},
		{"newline rejected", "flag{a\nb}", nil},
		{"no flag", "nothing here", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := m.FindString(tt.in)
			if len(got) == 0 && len(tt.want) == 0 {
				return
			}
			if !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestCustomPattern(t *testing.T) {
	m, err := NewMatcher(`DUCTF\{[^}]+\}`)
	if err != nil {
		t.Fatal(err)
	}
	got := m.FindString("DUCTF{custom} and THM{default}")
	want := []string{"DUCTF{custom}", "THM{default}"}
	if !slices.Equal(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestLocateOffsets(t *testing.T) {
	m, _ := NewMatcher()
	got := m.Locate([]byte("..HTB{b}..THM{a}..HTB{b}"))
	want := []Match{{"HTB{b}", 2}, {"THM{a}", 10}}
	if !slices.Equal(got, want) {
		t.Errorf("got %+v, want %+v", got, want)
	}
}

func FuzzFind(f *testing.F) {
	m, _ := NewMatcher(`DUCTF\{[^}]+\}`)
	f.Add([]byte("DUCTF{x} picoCTF{y} THM{z}"))
	f.Fuzz(func(t *testing.T, data []byte) {
		for _, mt := range m.Locate(data) {
			if string(data[mt.Offset:mt.Offset+len(mt.Value)]) != mt.Value {
				t.Fatalf("offset mismatch for %q", mt.Value)
			}
		}
	})
}

func TestInvalidPattern(t *testing.T) {
	if _, err := NewMatcher(`(`); err == nil {
		t.Error("expected error for invalid regex")
	}
}
