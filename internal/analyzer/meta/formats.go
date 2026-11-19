package meta

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"fmt"
	"io"
	"strings"

	"github.com/schmid-di/steganosaurus/internal/engine"
	"github.com/schmid-di/steganosaurus/internal/formats/exif"
	"github.com/schmid-di/steganosaurus/internal/formats/gif"
	"github.com/schmid-di/steganosaurus/internal/formats/jpeg"
	"github.com/schmid-di/steganosaurus/internal/formats/png"
	"github.com/schmid-di/steganosaurus/internal/formats/riff"
)

// maxInflate limits decompressed zTXt/iTXt text.
const maxInflate = 1 << 20

func (c *collector) png(data []byte) error {
	chunks, _, err := png.Parse(data)
	for _, ch := range chunks {
		loc := fmt.Sprintf("chunk %s @ 0x%X", ch.Type, ch.Offset)
		switch ch.Type {
		case "tEXt":
			k, v, _ := bytes.Cut(ch.Data, []byte{0})
			c.addText("PNG tEXt", string(k), latin1(v), loc)
		case "zTXt":
			k, rest, _ := bytes.Cut(ch.Data, []byte{0})
			if len(rest) > 1 {
				c.addText("PNG zTXt", string(k), string(inflate(rest[1:])), loc)
			}
		case "iTXt":
			c.itxt(ch.Data, loc)
		case "eXIf":
			c.exif(ch.Data, "chunk eXIf")
		case "tIME":
			if len(ch.Data) == 7 {
				d := ch.Data
				c.add(field{"PNG", "tIME", fmt.Sprintf("%04d-%02d-%02d %02d:%02d:%02d",
					binary.BigEndian.Uint16(d), d[2], d[3], d[4], d[5], d[6]), loc, keyCommon})
			}
		}
	}
	return err
}

func (c *collector) addText(source, key, value, loc string) {
	if key == "XML:com.adobe.xmp" {
		c.xmp([]byte(value), loc)
		return
	}
	// ImageMagick stores raw profiles as hex text chunks.
	if strings.HasPrefix(key, "Raw profile type") {
		c.add(field{source, key, value, loc, keyBoring})
		return
	}
	c.add(field{source, key, value, loc, keyBase(key)})
}

func (c *collector) itxt(d []byte, loc string) {
	key, rest, ok := bytes.Cut(d, []byte{0})
	if !ok || len(rest) < 2 {
		return
	}
	compressed := rest[0] == 1
	rest = rest[2:]
	_, rest, _ = bytes.Cut(rest, []byte{0})  // language tag
	_, text, _ := bytes.Cut(rest, []byte{0}) // translated keyword
	if compressed {
		text = inflate(text)
	}
	c.addText("PNG iTXt", string(key), string(text), loc)
}

func inflate(b []byte) []byte {
	r, err := zlib.NewReader(bytes.NewReader(b))
	if err != nil {
		return nil
	}
	defer r.Close()
	out, _ := io.ReadAll(io.LimitReader(r, maxInflate))
	return out
}

func latin1(b []byte) string {
	r := make([]rune, len(b))
	for i, c := range b {
		r[i] = rune(c)
	}
	return string(r)
}

func (c *collector) jpeg(data []byte) error {
	segs, _, err := jpeg.Parse(data)
	for _, s := range segs {
		loc := fmt.Sprintf("APP%d @ 0x%X", int(s.Marker)-jpeg.APP0, s.Offset)
		switch {
		case s.Marker == jpeg.COM:
			loc = fmt.Sprintf("COM @ 0x%X", s.Offset)
			base := keyText
			if boringComment(string(s.Data)) {
				base = keyCommon
			}
			c.add(field{"JPEG", "Comment", latin1(bytes.TrimRight(s.Data, "\x00")), loc, base})
		case s.Marker == jpeg.APP1:
			if body, ok := exif.StripPrefix(s.Data); ok {
				c.exif(body, loc)
			} else if body, ok := bytes.CutPrefix(s.Data, []byte("http://ns.adobe.com/xap/1.0/\x00")); ok {
				c.xmp(body, loc)
			}
		case s.Marker == jpeg.APPD:
			c.iptc(s.Data, loc)
		}
	}
	return err
}

// boringComment recognises comments written by common encoders.
func boringComment(s string) bool {
	for _, p := range []string{"CREATOR: gd-jpeg", "Created with GIMP", "Optimized by JPEGmini", "File written by Adobe Photoshop", "LEAD Technologies", "Intel(R) JPEG Library", "AppleMark"} {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}

func (c *collector) exif(data []byte, loc string) {
	res, err := exif.Parse(data)
	if err != nil {
		return
	}
	for _, e := range res.Entries {
		if e.ID == 0x02BC { // XMP inside TIFF
			c.xmp(e.Raw, loc)
			continue
		}
		c.add(field{"EXIF " + e.IFD, e.Name, e.Value, loc, keyBase(e.Name)})
	}
	if res.Latitude != nil && res.Longitude != nil {
		pos := fmt.Sprintf("%.6f, %.6f", *res.Latitude, *res.Longitude)
		c.extra = append(c.extra, engine.Finding{
			Title:    "GPS position: " + pos,
			Detail:   fmt.Sprintf("https://www.openstreetmap.org/?mlat=%.6f&mlon=%.6f&zoom=16", *res.Latitude, *res.Longitude),
			Score:    keyGPS,
			Location: loc,
		})
	}
	if len(res.Thumbnail) > 0 {
		c.extra = append(c.extra, engine.Finding{
			Title:    fmt.Sprintf("EXIF thumbnail (%d bytes)", len(res.Thumbnail)),
			Detail:   "Some editors do not update the thumbnail; it may show the original, unedited image.",
			Score:    30,
			Location: loc,
			Artifact: &engine.Artifact{Name: "exif_thumbnail.jpg", Data: res.Thumbnail},
		})
	}
}

func (c *collector) gif(data []byte) error {
	info, err := gif.Parse(data)
	for _, cm := range info.Comments {
		c.add(field{"GIF", "Comment", latin1(cm.Text), fmt.Sprintf("comment extension @ 0x%X", cm.Offset), keyText})
	}
	if info.Frames > 1 {
		c.add(field{"GIF", "Frames", fmt.Sprint(info.Frames), "", keyOther})
	}
	return err
}

func (c *collector) wav(data []byte) error {
	_, chunks, _, err := riff.Parse(data)
	for _, ch := range chunks {
		if ch.ID == "LIST" && ch.List == "INFO" {
			for _, sub := range ch.Children {
				c.add(field{"WAV INFO", sub.ID, latin1(bytes.TrimRight(sub.Data, "\x00")),
					fmt.Sprintf("LIST/INFO/%s @ 0x%X", sub.ID, sub.Offset), keyBase(sub.ID)})
			}
		}
	}
	return err
}
