// Package meta extracts metadata: EXIF, XMP, IPTC, JPEG comments, PNG text
// chunks, GIF comments and WAV INFO chunks. Interesting fields are reported
// individually and every value is run through the decoder.
package meta

import (
	"context"
	"fmt"
	"strings"

	"github.com/schmid-di/steganosaurus/internal/analyzer/textutil"
	"github.com/schmid-di/steganosaurus/internal/decode"
	"github.com/schmid-di/steganosaurus/internal/detect"
	"github.com/schmid-di/steganosaurus/internal/engine"
)

// Analyzer implements engine.Analyzer.
type Analyzer struct{}

// New returns the metadata analyzer.
func New() *Analyzer { return &Analyzer{} }

// Name implements engine.Analyzer.
func (*Analyzer) Name() string { return "meta" }

// Supports implements engine.Analyzer.
func (*Analyzer) Supports(ft detect.FileType) bool {
	switch ft {
	case detect.PNG, detect.JPEG, detect.GIF, detect.WAV:
		return true
	}
	return false
}

// field is one metadata value.
type field struct {
	Source   string // "EXIF IFD0", "PNG tEXt", "XMP", …
	Key      string
	Value    string
	Location string
	Base     int // base relevance from the key
}

// collector gathers fields and extra findings (e.g. thumbnails).
type collector struct {
	fields []field
	extra  []engine.Finding
}

func (c *collector) add(f field) {
	f.Value = strings.TrimSpace(f.Value)
	if f.Value == "" {
		return
	}
	c.fields = append(c.fields, f)
}

// Analyze implements engine.Analyzer.
func (*Analyzer) Analyze(_ context.Context, in *engine.Input) ([]engine.Finding, error) {
	c := &collector{}
	var err error
	switch in.Type {
	case detect.PNG:
		err = c.png(in.Data)
	case detect.JPEG:
		err = c.jpeg(in.Data)
	case detect.GIF:
		err = c.gif(in.Data)
	case detect.WAV:
		err = c.wav(in.Data)
	}
	// Structural errors are reported by the structure analyzer (M3); we
	// still report whatever metadata was parsed.
	_ = err
	return c.findings(in), nil
}

func (c *collector) findings(in *engine.Input) []engine.Finding {
	out := c.extra
	if len(c.fields) == 0 {
		return out
	}

	var all []string
	dec := textutil.NewDecoder(in)
	for _, f := range c.fields {
		all = append(all, fmt.Sprintf("%s %s: %s", f.Source, f.Key, textutil.OneLine(f.Value, 200)))
		label := f.Source + " " + f.Key
		score := relevance(f)
		if score >= engine.ScoreLow {
			out = append(out, engine.Finding{
				Title:    fmt.Sprintf("%s: %s", label, textutil.OneLine(f.Value, 60)),
				Detail:   detailFor(f),
				Score:    score,
				Location: f.Location,
			})
		}
		out = append(out, dec.Decode(label, f.Location, f.Value)...)
	}
	out = append(out, engine.Finding{
		Title:  fmt.Sprintf("Metadata: %d fields", len(c.fields)),
		Detail: strings.Join(all, "\n"),
		Score:  engine.ScoreInfo,
	})
	return out
}

func detailFor(f field) string {
	if len([]rune(f.Value)) <= 60 && !strings.Contains(f.Value, "\n") {
		return ""
	}
	return textutil.Truncate(f.Value, 2000)
}

// relevance scores a field from its key and content.
func relevance(f field) int {
	s := f.Base
	if len(f.Value) > 64 {
		s += 10
	}
	if decode.HintScore([]byte(f.Value)) > 0 && f.Base < 40 {
		s += 30
	}
	if len(f.Value) >= 16 && decode.Entropy([]byte(f.Value)) > 4.5 && !strings.Contains(f.Value, " ") {
		s += 10 // long random-looking token: maybe a key or encoded data
	}
	return min(s, 95)
}

// Relevance levels for keys.
const (
	keyBoring = 5  // technical values: dimensions, resolution, versions
	keyCommon = 10 // usually set by software: Make, Model, Software, dates
	keyOther  = 25 // unknown or uncommon keys
	keyText   = 40 // free-text fields where challenge authors hide things
	keyGPS    = 50
)

var textKeys = map[string]bool{
	// EXIF
	"imagedescription": true, "artist": true, "copyright": true, "usercomment": true,
	"xptitle": true, "xpcomment": true, "xpauthor": true, "xpkeywords": true, "xpsubject": true,
	"documentname": true, "cameraownername": true,
	// PNG text keywords
	"title": true, "author": true, "description": true, "comment": true, "disclaimer": true,
	"warning": true, "source": true,
	// XMP
	"dc:description": true, "dc:title": true, "dc:creator": true, "dc:rights": true, "dc:subject": true,
	"xmp:label": true, "photoshop:instructions": true, "photoshop:headline": true,
	"photoshop:captionwriter": true, "xmprights:usageterms": true,
	// IPTC
	"objectname": true, "keywords": true, "by-line": true, "headline": true,
	"caption": true, "copyrightnotice": true, "specialinstructions": true,
	// WAV INFO
	"icmt": true, "inam": true, "iart": true, "isbj": true, "ikey": true, "icop": true,
}

var commonKeys = map[string]bool{
	"make": true, "model": true, "software": true, "datetime": true, "datetimeoriginal": true,
	"datetimedigitized": true, "hostcomputer": true, "lensmake": true, "lensmodel": true,
	"creation time": true, "date:create": true, "date:modify": true, "date:timestamp": true,
	"xmp:creatortool": true, "xmp:createdate": true, "xmp:modifydate": true, "xmp:metadatadate": true,
	"isft": true, "icrd": true, "ieng": true, "imageuniqueid": true,
	"bodyserialnumber": true, "lensserialnumber": true, "offsettime": true, "offsettimeoriginal": true,
}

var boringPrefixes = []string{"xmpmm:", "stevt:", "stref:", "tiff:", "exif:", "crs:", "aux:", "photoshop:colormode", "photoshop:iccprofile", "xmp:rating"}

func keyBase(key string) int {
	k := strings.ToLower(key)
	switch {
	case textKeys[k]:
		return keyText
	case commonKeys[k]:
		return keyCommon
	case strings.HasPrefix(k, "gps"):
		return keyCommon
	case strings.HasPrefix(k, "tag0x"):
		return keyOther
	}
	for _, p := range boringPrefixes {
		if strings.HasPrefix(k, p) {
			return keyBoring
		}
	}
	if knownTechnical[k] {
		return keyBoring
	}
	return keyOther
}

var knownTechnical = map[string]bool{
	"imagewidth": true, "imageheight": true, "bitspersample": true, "compression": true,
	"photometricinterpretation": true, "orientation": true, "samplesperpixel": true,
	"xresolution": true, "yresolution": true, "resolutionunit": true, "ycbcrpositioning": true,
	"exifversion": true, "flashpixversion": true, "colorspace": true, "pixelxdimension": true,
	"pixelydimension": true, "componentsconfiguration": true, "thumbnailoffset": true,
	"thumbnaillength": true, "exposuretime": true, "fnumber": true, "exposureprogram": true,
	"iso": true, "shutterspeedvalue": true, "aperturevalue": true, "exposurebiasvalue": true,
	"meteringmode": true, "flash": true, "focallength": true, "subsectime": true,
	"subsectimeoriginal": true, "exposuremode": true, "whitebalance": true, "scenecapturetype": true,
	"stripoffsets": true, "makernote": true, "xmp": true,
	"xml:com.adobe.xmp": true, "jfif": true, "ihdr": true, "phys": true,
}
