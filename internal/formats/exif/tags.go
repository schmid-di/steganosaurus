package exif

import "fmt"

var tiffTags = map[uint16]string{
	0x0100: "ImageWidth", 0x0101: "ImageHeight", 0x0102: "BitsPerSample", 0x0103: "Compression",
	0x0106: "PhotometricInterpretation", 0x010D: "DocumentName", 0x010E: "ImageDescription",
	0x010F: "Make", 0x0110: "Model", 0x0111: "StripOffsets", 0x0112: "Orientation",
	0x0115: "SamplesPerPixel", 0x011A: "XResolution", 0x011B: "YResolution", 0x0128: "ResolutionUnit",
	0x0131: "Software", 0x0132: "DateTime", 0x013B: "Artist", 0x013C: "HostComputer",
	0x0201: "ThumbnailOffset", 0x0202: "ThumbnailLength", 0x0213: "YCbCrPositioning",
	0x8298: "Copyright", 0x02BC: "XMP",
	0x9C9B: "XPTitle", 0x9C9C: "XPComment", 0x9C9D: "XPAuthor", 0x9C9E: "XPKeywords", 0x9C9F: "XPSubject",
	// Exif IFD
	0x829A: "ExposureTime", 0x829D: "FNumber", 0x8822: "ExposureProgram", 0x8827: "ISO",
	0x9000: "ExifVersion", 0x9003: "DateTimeOriginal", 0x9004: "DateTimeDigitized",
	0x9010: "OffsetTime", 0x9011: "OffsetTimeOriginal", 0x9101: "ComponentsConfiguration",
	0x9201: "ShutterSpeedValue", 0x9202: "ApertureValue", 0x9204: "ExposureBiasValue",
	0x9207: "MeteringMode", 0x9209: "Flash", 0x920A: "FocalLength", 0x927C: "MakerNote",
	0x9286: "UserComment", 0x9290: "SubSecTime", 0x9291: "SubSecTimeOriginal",
	0xA000: "FlashpixVersion", 0xA001: "ColorSpace", 0xA002: "PixelXDimension", 0xA003: "PixelYDimension",
	0xA402: "ExposureMode", 0xA403: "WhiteBalance", 0xA406: "SceneCaptureType",
	0xA420: "ImageUniqueID", 0xA430: "CameraOwnerName", 0xA431: "BodySerialNumber",
	0xA433: "LensMake", 0xA434: "LensModel", 0xA435: "LensSerialNumber",
}

var gpsTags = map[uint16]string{
	0x00: "GPSVersionID", 0x01: "GPSLatitudeRef", 0x02: "GPSLatitude", 0x03: "GPSLongitudeRef",
	0x04: "GPSLongitude", 0x05: "GPSAltitudeRef", 0x06: "GPSAltitude", 0x07: "GPSTimeStamp",
	0x12: "GPSMapDatum", 0x1D: "GPSDateStamp",
}

func tagName(ifd string, id uint16) string {
	table := tiffTags
	if ifd == "GPS" {
		table = gpsTags
	}
	if n, ok := table[id]; ok {
		return n
	}
	return fmt.Sprintf("Tag0x%04X", id)
}
