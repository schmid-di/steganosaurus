<p align="center">
  <img src="SteganoSaurus.jpeg" alt="SteganoSaurus-Logo – ein Stegosaurus im Hoodie" width="520">
</p>

<h1 align="center">steganosaurus</h1>

<p align="center">
  <strong>Steganografie-Analyse für CTF-Spieler – eine statische Binary statt zehn Einzeltools.</strong>
</p>

`steganosaurus scan` erkennt den Dateityp, führt alle passenden Analysen aus, steigt rekursiv in
extrahierte Daten ein und hebt Flags wie `THM{…}` oder `HTB{…}` hervor. Gebaut für TryHackMe,
HackTheBox und picoCTF.

> **Status:** früh in Entwicklung. Fertig: M1 (Grundgerüst), M2 (Metadaten, Strings + Encoding-Erkennung, Carving + Rekursion). Als Nächstes: M3 (LSB-Analyse, Strukturprüfung). Fahrplan in [docs/SPEC.md](docs/SPEC.md), Backlog in [docs/BACKLOG.md](docs/BACKLOG.md).

---

## 🤖 Für Coding-Agents – zuerst lesen

Wenn du ein KI-Agent bist, der an diesem Repo arbeitet, halte dich an Folgendes:

1. **Kontext und Zweck verstehen.** Lies **[docs/CONTEXT.md](docs/CONTEXT.md)** – es erklärt, worum es geht und warum das ein legitimes, defensiv-ausgerichtetes Sicherheits-/Forensik-Projekt ist. Danach [docs/SPEC.md](docs/SPEC.md) (Anforderungen F1–F10, Architektur, Meilensteine) und [docs/BACKLOG.md](docs/BACKLOG.md).
2. **Nach Meilensteinen arbeiten.** Umgesetzt wird entlang M1 → M5 (SPEC §10). Pro Meilenstein ein eigener Branch und ein eigener PR. Steht der PR des Vor-Meilensteins noch offen, wird der nächste PR darauf gestapelt (Basis = Branch des Vor-Meilensteins), damit der Diff klein bleibt.
3. **Qualität ist nicht optional.** Jede Änderung muss durch `make test` (inkl. `-race`), `make lint` (`go vet` + `staticcheck`) und `gofmt`. Parser bekommen Fuzz-Tests. Minimierte Fuzz-Crasher werden als Regression-Seeds unter `testdata/fuzz/` eingecheckt.
4. **Keine Laufzeit-Abhängigkeiten.** Reines Go, `CGO_ENABLED=0`, keine externen Programme (kein Aufruf von exiftool, binwalk, steghide …). Erlaubt sind nur die Bibliotheken in `go.mod` (aktuell Cobra). Format-Parser und Decoder werden selbst geschrieben.
5. **Konventionen.**
   - Programmausgabe auf **Englisch** (internationale CTF-Community), Projektdokumentation und Commit-Kontext auf **Deutsch**.
   - Analyzer sind seiteneffektfrei und arbeiten auf `[]byte`; Dateien schreibt nur das Paket `report`.
   - Die Originaldatei wird ausschließlich gelesen, nie überschrieben.
   - Robustheit vor Vollständigkeit: kein `panic` bei kaputten oder bösartigen Dateien.
   - Commit- und PR-Attribution gemäß der Session-Vorgabe (Co-Author-Zeile bzw. PR-Fußzeile).

### Einen neuen Analyzer hinzufügen

Das ist der häufigste Erweiterungsschritt. Ein Analyzer implementiert `engine.Analyzer`:

```go
type Analyzer interface {
    Name() string                                   // kurz, z. B. "lsb"
    Supports(ft detect.FileType) bool               // für welche Dateitypen?
    Analyze(ctx context.Context, in *engine.Input) ([]engine.Finding, error)
}
```

1. Neues Paket unter `internal/analyzer/<name>/` anlegen.
2. Funde als `engine.Finding` zurückgeben; extrahierte Daten in `Finding.Artifact` legen – die Engine scannt sie **rekursiv** weiter.
3. Zum Bewerten/Dekodieren die vorhandenen Helfer nutzen: `internal/decode` (Encoding-Ketten, Lesbarkeit, Entropie) und `internal/analyzer/textutil` (Wert → Fund).
4. Den Analyzer in `internal/analyzer/analyzer.go` in `All()` registrieren.
5. Unit-Tests dazu; Fixtures baut `internal/testutil` **in-process** (kein externes Tool nötig). Für neue Format-Parser einen Fuzzer ergänzen.

### Projektstruktur

```
cmd/steganosaurus/      main
internal/
  cli/                  Cobra-Kommandos, Flags, Exit-Codes
  engine/               Analyzer-Interface, Scheduler, Rekursion, Scoring, Provenienz
  detect/               Dateityp-Erkennung über Magic Bytes
  analyzer/             Registry + ein Paket je Analyzer
    filetype/ meta/ strings/ carve/ textutil/   (M3+: lsb/ structure/ steghide/)
  decode/               Base*, ROT, Morse, Ketten-Dekodierung, Text-Scoring
  flag/                 Flag-Muster und Matching
  formats/              eigene Parser: png, jpeg, bmp, riff, gif, exif
  report/               Terminal- und JSON-Ausgabe, Artefakt-Verzeichnis
  testutil/             In-Process-Generatoren für Testdateien
testdata/               Challenge-Korpus (teils generiert)
```

---

## Was es findet

- **Metadaten:** EXIF (inkl. GPS, Thumbnail), XMP, IPTC, JPEG-Kommentare, PNG tEXt/zTXt/iTXt/eXIf, GIF-Kommentare, WAV INFO. Auffällige Felder werden hervorgehoben.
- **Encoding-Ketten:** Base64/32/58, Ascii85, Hex, Binär, Dezimal, ROT13/47, Morse – auch verschachtelt (z. B. Base64 → Hex → Text), in Metadaten-Werten und Strings.
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

## Lizenz

Noch festzulegen (siehe SPEC §8).
