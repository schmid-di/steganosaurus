# steganosaurus

Steganografie-Analyse-Tool in Go – gebaut für CTF-Spieler (TryHackMe, HackTheBox, picoCTF …).
Eine statische Binary statt zehn Einzeltools: `steganosaurus scan` erkennt den Dateityp, führt alle passenden
Analysen aus, steigt rekursiv in extrahierte Daten ein und hebt Flags wie `THM{…}` oder `HTB{…}` hervor.

> Status: früh in Entwicklung. Fertig: M1 (Grundgerüst), M2 (Metadaten, Strings + Encoding-Erkennung, Carving + Rekursion). Als Nächstes: M3 (LSB, Strukturprüfung). Siehe [Spezifikation](docs/SPEC.md) und [Backlog](docs/BACKLOG.md).

## Was es findet

- **Metadaten:** EXIF (inkl. GPS, Thumbnail), XMP, IPTC, JPEG-Kommentare, PNG tEXt/zTXt/iTXt/eXIf, GIF-Kommentare, WAV INFO. Auffällige Felder werden hervorgehoben.
- **Encoding-Ketten:** Base64/32/58, Ascii85, Hex, Binär, Dezimal, ROT13/47, Morse – auch verschachtelt (z. B. Base64 → Hex → Text) und in Metadaten-Werten und Strings.
- **Strings:** ASCII und UTF-16 (LE/BE), mit Erkennung interessanter Treffer (`password:`, `secret` …).
- **Carving:** eingebettete und angehängte Dateien (Daten nach IEND/EOI), Archive (ZIP/tar/gzip/bzip2) werden entpackt und rekursiv gescannt. Passwortgeschützte ZIPs werden gemeldet.

## Installation

```sh
go install github.com/schmid-di/steganosaurus/cmd/steganosaurus@latest
# oder aus dem Repo
make build   # → bin/steganosaurus
```

## Nutzung

```sh
steganosaurus scan challenge.png                 # Auto-Triage
steganosaurus scan -v challenge.png              # alle Funde, volle Details
steganosaurus scan -q --stop-on-flag image.jpg   # nur Flags ausgeben
steganosaurus scan --json file.wav               # JSON für Skripte
steganosaurus scan --flag-format 'DUCTF\{[^}]+\}' file.bmp
```

Artefakte und `report.json` landen in `./<datei>_steg/` (änderbar mit `-o`).

Exit-Codes: `0` kein Flag · `1` Fehler · `2` Flag gefunden

## Entwicklung

```sh
make test    # Tests mit Race-Detector
make lint    # go vet + staticcheck
make cross   # Release-Binaries für linux/darwin/windows × amd64/arm64
```

Neue Analyzer implementieren `engine.Analyzer` in einem eigenen Paket unter `internal/analyzer/`
und werden in `internal/analyzer/analyzer.go` registriert.
