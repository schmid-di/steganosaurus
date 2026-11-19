# Steganosaurus – Spezifikation (Kern / MVP)

> Status: Entwurf · Stand: 2026-11-19
> Projektkontext und Zielsetzung: siehe [CONTEXT.md](CONTEXT.md)
> Weiterführende Features: siehe [BACKLOG.md](BACKLOG.md)

## 1. Ziel und Motivation

Steganosaurus ist ein Steganografie-Analyse-Tool in Go. Der Name ist eine Anspielung auf den Stegosaurus.

Wer heute eine Stego-Challenge auf TryHackMe oder HackTheBox löst, braucht dafür 6–10 Einzelwerkzeuge (exiftool, strings, binwalk, foremost, zsteg, steghide, stegseek, stegsolve, pngcheck …). Diese Tools haben mehrere Probleme:

- Sie sind in verschiedenen Sprachen geschrieben (Ruby, Java, Python 2, C) und lassen sich teils nur mühsam installieren.
- Teilweise sind sie veraltet oder werden nicht mehr gepflegt (z. B. stegsolve, steghide).
- Sie arbeiten isoliert, sodass die Triage-Reihenfolge jedes Mal von Hand abläuft.

Steganosaurus ersetzt diese Kette durch **eine statische Binary**, die eine Datei selbstständig triagiert, Funde nach Relevanz sortiert und Flags automatisch erkennt.

## 2. Zielgruppe

**Primär:** CTF-Spieler, also Einsteiger bis Fortgeschrittene auf TryHackMe, HackTheBox, picoCTF und bei CTFtime-Events.

Daraus folgen diese Anforderungen:
- Ein einziger Befehl liefert sinnvolle Ergebnisse, ohne dass man Vorwissen über die richtige Tool-Reihenfolge braucht.
- Die Ausgabe erklärt, *was* gefunden wurde und *warum* es relevant ist. Das hat auch einen Lerneffekt.
- Fortgeschrittene können jede Analyse einzeln und fein parametrisiert aufrufen.

## 3. Nicht-Ziele (MVP)

- Kein Einbetten bzw. Encodieren von Daten (→ Backlog)
- Keine GUI und kein Web-Viewer (→ Backlog)
- Keine Audio-, GIF- oder Text-Stego-Analyse (→ Backlog)
- Keine JPEG-DCT-Verfahren wie OutGuess oder F5 (→ Backlog)
- Keine Abhängigkeit von externen Programmen zur Laufzeit

## 4. Unterstützte Formate (MVP)

| Format | Erkennung | Analysen |
|---|---|---|
| PNG | Magic Bytes | Metadaten, Struktur/CRC, LSB, Anhang, Strings, Carving |
| BMP | Magic Bytes | Metadaten, Struktur, LSB, steghide, Anhang, Strings, Carving |
| JPEG | Magic Bytes | Metadaten, Struktur, steghide, Anhang, Strings, Carving |
| WAV | Magic Bytes | steghide, Metadaten, Strings, Carving |
| Beliebige Datei | Fallback | Strings, Carving, Encoding-Erkennung |

Der Dateityp wird immer anhand der **Magic Bytes** bestimmt, nie anhand der Dateiendung. Eine Abweichung zwischen Endung und Inhalt wird als Fund gemeldet.

## 5. Kommandozeile

Name der Binary: `steganosaurus`

```
steganosaurus scan    <datei>   [flags]   # Auto-Triage: alle passenden Analysen
steganosaurus meta    <datei>             # Metadaten
steganosaurus strings <datei>             # Strings + Encoding-Erkennung
steganosaurus carve   <datei>             # eingebettete/angehängte Dateien extrahieren
steganosaurus lsb     <datei>             # LSB-Analyse (PNG/BMP)
steganosaurus steghide extract <datei> [-p pass]
steganosaurus steghide crack   <datei> [-w wordlist]
steganosaurus fix     <datei>             # Strukturprüfung + Reparatur
steganosaurus version
```

Globale Flags:

| Flag | Default | Bedeutung |
|---|---|---|
| `-o, --out <dir>` | `./<datei>_steg/` | Ausgabeordner für Artefakte |
| `--json` | aus | Maschinenlesbare Ausgabe auf stdout |
| `--flag-format <regex>` | – | Zusätzliches Flag-Muster (mehrfach angebbar) |
| `--stop-on-flag` | aus | Abbruch beim ersten Flag-Treffer |
| `--depth <n>` | 3 | Maximale Rekursionstiefe beim Carving |
| `-w, --wordlist <file>` | – | Wortliste für Passwort-Angriffe |
| `-j, --jobs <n>` | Anzahl CPUs | Parallelität |
| `-v / -q` | – | Ausführliche bzw. stille Ausgabe |
| `--no-color` | auto | Farben deaktivieren (automatisch bei Nicht-TTY) |

Exit-Codes: `0` = Analyse ok, kein Flag · `1` = Fehler · `2` = Flag gefunden

## 6. Funktionale Anforderungen

### F1 – Auto-Triage (`scan`)
- Erkennt den Dateityp und führt **alle passenden Analyzer parallel** aus.
- Jeder Fund (*Finding*) bekommt eine **Relevanzbewertung** (0–100), die aus folgenden Signalen entsteht:
  - Flag-Treffer
  - Klartext-Anteil
  - Entropie
  - bekannte Dateisignatur
  - Abweichung vom Erwartbaren
- Die Ausgabe ist nach Relevanz sortiert. Funde unter einem Schwellwert erscheinen nur mit `-v`.
- Neue Artefakte, also extrahierte Dateien und dekodierte Daten, durchlaufen **selbst wieder** den Scan, bis `--depth` erreicht ist.
- Am Ende steht eine Zusammenfassung mit Anzahl der Funde, gefundenen Flags und dem Pfad zum Ausgabeordner.

**Akzeptanz:** Eine Testdatei mit dem Aufbau „PNG mit angehängtem ZIP, darin ein JPG mit steghide-Payload (leeres Passwort) und Flag“ wird mit `steganosaurus scan` ohne weitere Parameter vollständig gelöst.

### F2 – Flag-Erkennung
- Diese Muster sind vorkonfiguriert: `THM{…}`, `HTB{…}`, `flag{…}`, `FLAG{…}`, `CTF{…}`, `picoCTF{…}`.
- Eigene Muster sind über `--flag-format` und die Konfigurationsdatei möglich.
- Die Erkennung läuft über **alle** Ausgaben: Rohdaten, Strings, Metadaten, dekodierte Daten und LSB-Streams.
- Treffer werden farblich hervorgehoben und als eigener Abschnitt ganz oben ausgegeben, jeweils mit Herkunftskette (z. B. `image.png → carve:zip → secret.jpg → steghide`).

### F3 – Carving und rekursive Extraktion
- Signatur-Scan über die gesamte Datei für mindestens diese Formate: ZIP, RAR, 7z, gzip, bzip2, xz, tar, PNG, JPEG, GIF, BMP, PDF, ELF, PE und WAV.
- Das Ende einer Datei wird über die jeweilige Formatstruktur bestimmt (z. B. ZIP-EOCD, PNG-IEND, JPEG-EOI) und nicht pauschal bis zum Dateiende angenommen.
- **Daten nach dem regulären Dateiende** (nach IEND bzw. EOI) werden immer als eigener Fund gemeldet.
- Archive werden automatisch entpackt. Ist ein ZIP passwortgeschützt, wird es als Fund gemeldet und Passwort-Kandidaten werden probiert (siehe F7).
- Schutz vor Zip-Bombs: Größenlimit und Kompressionsratio-Limit, beide konfigurierbar.

### F4 – Metadaten
- Ausgelesen werden: EXIF (inkl. GPS, Kommentar, Artist, Copyright), XMP, IPTC, JPEG-COM, die PNG-Textchunks `tEXt`/`zTXt`/`iTXt` sowie WAV-`LIST/INFO`.
- **Auffällige Felder** werden markiert, z. B. ungewöhnlich lange Werte, hohe Entropie, Base64-ähnlicher Inhalt oder unbekannte Chunks.
- Jeder Metadatenwert läuft durch die Encoding-Erkennung (F5) und die Flag-Erkennung (F2).

### F5 – Strings und Encoding-Erkennung
- Extrahiert werden ASCII- und UTF-16LE/BE-Strings mit konfigurierbarer Mindestlänge (Default 6).
- Für jeden Kandidaten erkennt und dekodiert das Tool automatisch: Base64 (Standard + URL), Base32, Base58, Base85/Ascii85, Hex, Binär (`01001…`), Dezimal-ASCII, ROT13, ROT47 und Morse.
- **Ketten-Dekodierung:** Dekodiert wird wiederholt, solange das Ergebnis „besser lesbar“ wird. Maximal 5 Stufen, Bewertung über Klartext-Score und Entropie.
- Ausgegeben werden nur Strings mit Relevanz. Ohne `-v` erscheint also kein Rauschen.

### F6 – LSB-Analyse (PNG, BMP)
- Die Extraktion läuft über alle sinnvollen Kombinationen aus:
  - Bit-Ebenen 0–7 (einzeln und Bereiche wie `0-1`)
  - Kanälen R, G, B, A und deren Reihenfolgen (`rgb`, `bgr`, `rgba` …)
  - Bit-Reihenfolge MSB/LSB-first
  - Scanrichtung zeilen- oder spaltenweise
- Jeder Stream wird bewertet: Steht am Anfang eine Dateisignatur, ein Längenpräfix, Klartext oder ein Flag?
- Streams mit Treffer werden als Datei gespeichert und rekursiv gescannt (F1).
- Mit `steganosaurus lsb --bits 0 --channels rgb --order lsb` lässt sich eine Kombination gezielt extrahieren.
- Paletten-PNGs und 16-Bit-PNGs werden korrekt behandelt.

**Akzeptanz:** Alle von zsteg im Default-Modus gefundenen Payloads werden ebenfalls gefunden. Das wird mit Referenzdateien getestet.

### F7 – steghide: Extraktion und Cracking
- **Native Go-Implementierung** des steghide-Formats für JPEG, BMP und WAV. Steghide wird nicht extern aufgerufen.
- Unterstützt wird der Default-Algorithmus von steghide (Rijndael-128, CBC) sowie unverschlüsselte Payloads.
- Reihenfolge der Passwortversuche im `scan`:
  1. Leeres Passwort
  2. **Kontext-Kandidaten:** Dateiname, Strings und Metadaten-Werte aus derselben Analyse
  3. Eine eingebaute Mini-Wortliste mit typischen CTF-Passwörtern
  4. Optional die Wortliste aus `-w`
- Der Wörterbuch-Angriff ist parallelisiert. Zielwert ist eine Geschwindigkeit in der Größenordnung von stegseek: rockyou.txt in unter 1 Minute auf einem aktuellen 8-Kern-Rechner. Wie bei stegseek wird dazu der Header früh verworfen, statt jedes Mal komplett zu entschlüsseln.
- Ausgegeben werden das Passwort, der eingebettete Dateiname und der extrahierte Inhalt, der dann rekursiv gescannt wird.

**Akzeptanz:** Payloads, die mit dem Original-steghide 0.5.1 erzeugt wurden, werden korrekt extrahiert.

> Hinweis: F7 ist das aufwändigste Feature, weil das Einbettungsverfahren von steghide nachgebaut werden muss (Graph-Matching und PRNG). Es sollte daher als eigener Meilenstein eingeplant werden.

### F8 – Strukturprüfung und Reparatur (`fix`)
- **PNG:**
  - Signatur, Chunk-Reihenfolge und CRC jedes Chunks werden geprüft.
  - Bei falschem IHDR-CRC wird die passende Breite und Höhe per **CRC-Bruteforce** gesucht und das Bild repariert.
  - Unbekannte oder private Chunks sowie Daten nach IEND werden gemeldet.
- **JPEG:** SOI/EOI und Segmentstruktur werden geprüft, Daten nach EOI gemeldet.
- **BMP:** Header-Größenangaben werden gegen die tatsächliche Dateigröße geprüft. Bei manipulierter Höhe oder Breite wird ein Vorschlag gemacht.
- **Magic Bytes:** Beschädigte oder vertauschte Signaturen werden erkannt, z. B. eine PNG-Signatur mit verändertem Byte, und lassen sich reparieren.
- Reparierte Dateien werden **nie** in die Originaldatei geschrieben, sondern immer in den Ausgabeordner.

### F9 – Ausgabe und Artefakte
- **Terminal:** farbig und gruppiert in Flags, Funde nach Relevanz und Zusammenfassung. Jeder Fund zeigt Analyzer, Fundort (Offset, Chunk, LSB-Parameter), eine kurze Erklärung und gegebenenfalls den Artefakt-Pfad.
- **JSON (`--json`):** stabiles, versioniertes Schema (`schema_version`) mit allen Findings, Flags, Artefakten und der Herkunftskette.
- **Ausgabeordner:** Alle Artefakte sind nach Herkunft benannt (z. B. `003_lsb_b0_rgb_lsb.bin`, `004_carve_0x1A2F.zip`). Dazu kommt eine `report.json`.
- Die Originaldatei wird ausschließlich gelesen.

### F10 – Konfiguration
- Optionale Datei `~/.config/steganosaurus/config.yaml` für Flag-Muster, Default-Wortliste, Schwellwerte und Limits.
- Kommandozeilen-Flags überschreiben die Konfigurationsdatei.

## 7. Architektur

```
cmd/steganosaurus/      # main, Cobra-Kommandos
internal/
  engine/               # Scheduler, Rekursion, Scoring, Provenienz
  detect/               # Dateityp-Erkennung (Magic Bytes)
  analyzer/             # Analyzer-Interface + Registry
    meta/  strings/  carve/  lsb/  steghide/  structure/
  decode/               # Base*, ROT, Morse, Ketten-Dekodierung
  flag/                 # Flag-Muster und Matching
  report/               # Terminal- und JSON-Ausgabe
  formats/              # Parser: png, jpeg, bmp, wav, zip …
testdata/               # Challenge-Dateien + erwartete Ergebnisse
```

Das zentrale Interface sieht so aus:

```go
type Analyzer interface {
    Name() string
    Supports(ft detect.FileType) bool
    Analyze(ctx context.Context, in *engine.Input) ([]engine.Finding, error)
}

type Finding struct {
    Analyzer   string
    Title      string
    Detail     string
    Score      int            // 0–100
    Location   string         // Offset, Chunk, LSB-Parameter …
    Artifact   *engine.Artifact // extrahierte Daten (optional, wird rekursiv gescannt)
    Flags      []string
    Provenance []string
}
```

- Die Engine verteilt Inputs an alle unterstützenden Analyzer und führt sie über einen Worker-Pool aus, gesteuert mit `context` für Abbruch und Timeouts.
- Artefakte werden per Hash dedupliziert, damit keine Endlosschleifen entstehen.
- Analyzer sind reine Funktionen auf `[]byte` bzw. `io.ReaderAt`, Seiteneffekte gibt es nur in `report`.

## 8. Nicht-funktionale Anforderungen

| Bereich | Anforderung |
|---|---|
| Distribution | Reines Go, `CGO_ENABLED=0`, statische Binaries für linux/darwin/windows × amd64/arm64 |
| Abhängigkeiten | Möglichst Standardbibliothek; erlaubt sind Cobra, ein YAML-Parser und eine EXIF-Bibliothek. Keine externen Programme |
| Performance | `scan` einer typischen CTF-Datei (< 5 MB) ohne Wortliste in < 3 s |
| Robustheit | Kein Panic bei kaputten oder bösartigen Dateien, Fuzzing der Parser mit `go test -fuzz` |
| Sicherheit | Originaldatei wird nur gelesen, Pfade beim Entpacken werden bereinigt (kein Zip-Slip), Größenlimits greifen |
| Go-Version | Aktuelle stabile Go-Version |
| Lizenz | Offen (festzulegen) |

## 9. Teststrategie

- **Unit-Tests** pro Analyzer und Decoder.
- **Challenge-Korpus** in `testdata/`: kleine, selbst erzeugte Dateien nach dem Vorbild typischer THM/HTB-Aufgaben, jeweils mit einer `expected.json` (erwartete Flags und Funde). Nachgebildet werden:
  - Flag im EXIF-Kommentar
  - Base64-Kette in einem PNG-tEXt-Chunk
  - ZIP angehängt an JPG
  - LSB in Ebene 0 der RGB-Kanäle
  - steghide mit leerem Passwort und mit Passwort aus der Wortliste
  - PNG mit manipulierter Höhe
  - verschachtelte Kette über drei Stufen
- **Referenztests** gegen zsteg und steghide: Deren Ausgaben werden einmalig erzeugt und als Fixtures eingecheckt.
- **Fuzzing** für alle Format-Parser.
- CI führt Tests, `go vet`, `staticcheck` und Cross-Compile aus.

## 10. Meilensteine

1. **M1 – Grundgerüst:** CLI, Engine, Dateityp-Erkennung, Report (Terminal + JSON), Flag-Erkennung
2. **M2 – Schnelle Erfolge:** Metadaten, Strings + Encoding-Erkennung, Carving + Rekursion
3. **M3 – Bilder:** LSB-Analyse, Strukturprüfung und PNG-CRC-Reparatur
4. **M4 – steghide:** Extraktion, Kontext-Passwörter, paralleles Cracken
5. **M5 – Release 0.1:** Challenge-Korpus komplett grün, Fuzzing, Release-Binaries
