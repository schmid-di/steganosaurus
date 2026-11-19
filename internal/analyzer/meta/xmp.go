package meta

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"html"
	"regexp"
	"strings"
)

var (
	xmpElement   = regexp.MustCompile(`<([A-Za-z][\w.-]*:[\w.-]+)(?:\s[^>]*)?>([^<]+)</([A-Za-z][\w.-]*:[\w.-]+)>`)
	xmpAttribute = regexp.MustCompile(`\s([A-Za-z][\w.-]*:[\w.-]+)="([^"]*)"`)
)

// xmp extracts key/value pairs from an XMP packet. It is a deliberately
// simple scanner instead of a full RDF parser: CTF metadata is usually
// flat, and a scanner is robust against broken XML.
func (c *collector) xmp(data []byte, loc string) {
	s := string(data)
	seen := map[string]bool{}
	add := func(key, value string) {
		value = strings.TrimSpace(html.UnescapeString(value))
		lk := strings.ToLower(key)
		if value == "" || strings.HasPrefix(lk, "xmlns:") || strings.HasPrefix(lk, "rdf:") || strings.HasPrefix(lk, "x:") {
			return
		}
		if seen[key+"\x00"+value] {
			return
		}
		seen[key+"\x00"+value] = true
		c.add(field{"XMP", key, value, loc, keyBase(key)})
	}
	for _, m := range xmpAttribute.FindAllStringSubmatch(s, -1) {
		add(m[1], m[2])
	}
	for _, m := range xmpElement.FindAllStringSubmatch(s, -1) {
		if m[1] == m[3] {
			add(m[1], m[2])
			continue
		}
		// Values inside rdf:Alt/rdf:Seq/rdf:Bag (<rdf:li>) belong to the
		// enclosing property; find it by looking backwards.
		if m[1] == "rdf:li" {
			idx := strings.Index(s, m[0])
			if prop := enclosingProperty(s[:max(idx, 0)]); prop != "" {
				add(prop, m[2])
			}
		}
	}
}

var openTag = regexp.MustCompile(`<([A-Za-z][\w.-]*:[\w.-]+)[\s>]`)

func enclosingProperty(before string) string {
	tags := openTag.FindAllStringSubmatch(before, -1)
	for i := len(tags) - 1; i >= 0; i-- {
		t := tags[i][1]
		if !strings.HasPrefix(t, "rdf:") {
			return t
		}
	}
	return ""
}

var iptcNames = map[byte]string{
	5: "ObjectName", 25: "Keywords", 40: "SpecialInstructions", 55: "DateCreated",
	80: "By-line", 85: "By-lineTitle", 90: "City", 95: "Province-State", 101: "Country",
	105: "Headline", 110: "Credit", 115: "Source", 116: "CopyrightNotice", 120: "Caption",
	122: "Writer-Editor",
}

// iptc parses IPTC records from a Photoshop APP13 segment.
func (c *collector) iptc(data []byte, loc string) {
	body, ok := bytes.CutPrefix(data, []byte("Photoshop 3.0\x00"))
	if !ok {
		return
	}
	for off := 0; off+12 <= len(body); {
		if string(body[off:off+4]) != "8BIM" {
			return
		}
		id := binary.BigEndian.Uint16(body[off+4:])
		nameLen := int(body[off+6])
		p := off + 6 + 1 + nameLen
		if (1+nameLen)%2 == 1 {
			p++ // Pascal string padded to even length
		}
		if p+4 > len(body) {
			return
		}
		size := int(binary.BigEndian.Uint32(body[p:]))
		p += 4
		if size < 0 || p+size > len(body) {
			return
		}
		if id == 0x0404 {
			c.iptcRecords(body[p:p+size], loc)
		}
		off = p + size + size%2
	}
}

func (c *collector) iptcRecords(d []byte, loc string) {
	for off := 0; off+5 <= len(d) && d[off] == 0x1C; {
		rec, ds := d[off+1], d[off+2]
		n := int(binary.BigEndian.Uint16(d[off+3:]))
		off += 5
		if n&0x8000 != 0 || off+n > len(d) {
			return
		}
		if rec == 2 && ds != 0 {
			name, ok := iptcNames[ds]
			if !ok {
				name = fmt.Sprintf("IPTC2:%d", ds)
			}
			c.add(field{"IPTC", name, string(d[off : off+n]), loc, keyBase(name)})
		}
		off += n
	}
}
