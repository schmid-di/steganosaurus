# Steganosaurus – Backlog

Features außerhalb des Kerns (siehe [SPEC.md](SPEC.md)). Sie werden erst nach Release 0.1 spezifiziert. Die Reihenfolge ist eine grobe Priorität.

## Version 1

### B1 – Bild-Ansichten (Ersatz für stegsolve)
- Export von Bitplanes pro Kanal, Einzelkanälen, Farbinversion, Zufallspalette und Graustufen als PNG
- Optional ein lokaler Web-Viewer `steganosaurus view <datei>` zum Durchblättern der Ansichten
- Herkunft in den Labs: THM c4ptur3-th3-fl4g, HTB-Stego-Challenges (Flags sind nur in einzelnen Bitplanes sichtbar)

### B2 – Bildvergleich
- `steganosaurus diff a.png b.png`: XOR, Differenz, Subtraktion, Hervorhebung abweichender Pixel
- Herkunft in den Labs: der Image Combiner von stegsolve, Aufgaben vom Typ „Original vs. Stego-Bild“

### B3 – Audio-Analyse
- LSB-Extraktion für WAV und FLAC
- Spektrogramm als PNG mit Skalierung und Frequenzbereich
- DTMF- und Morse-Erkennung im Signal, Hinweis auf SSTV
- Herkunft in den Labs: THM c4ptur3-th3-fl4g, HTB „Milkshake“ (Text oder QR-Code im Spektrogramm)

### B4 – QR- und Barcode-Erkennung
- Automatische Erkennung in allen erzeugten Bildern: Originale, Bitplanes, Spektrogramme, GIF-Frames
- Herkunft in den Labs: THM Biohazard / CTF Collection (Kette aus Spektrogramm, QR-Code und Morse)

### B5 – GIF und APNG
- Frames einzeln exportieren
- Frame-Delays und Disposal-Werte als mögliche Daten auswerten
- Paletten-Tricks erkennen (z. B. Farben mit fast gleichem Wert)

### B6 – Text-Stego
- Zero-Width-Unicode (ZWSP, ZWNJ, ZWJ …) dekodieren
- Whitespace-Stego im Stil von SNOW
- Homoglyphen und Trailing Whitespace

### B7 – Kontext-Passwörter für weitere Verfahren
- Kontext-Kandidaten aus F7 auch für passwortgeschützte ZIP-, RAR- und 7z-Archive nutzen, zusätzlich Wortlisten-Angriff
- Regeln für Varianten (Groß-/Kleinschreibung, angehängte Zahlen, Leetspeak)

## Später

### C1 – Einbetten (Encode)
- LSB-Einbettung, steghide-kompatibles Einbetten und Anhängen
- Zweck: eigene Challenges bauen und Test-Korpus erzeugen

### C2 – JPEG-DCT-Verfahren und Statistik
- Erkennung und Extraktion von OutGuess (0.13 und neu) sowie F5
- Statistische Tests: Chi-Quadrat, RS-Analyse, Sample Pair Analysis
- Ähnliche Funktionen wie stegdetect und stegbreak

### C3 – Plugin- und Rezept-System
- Eigene Analyse-Schritte als Konfiguration, ähnlich wie CyberChef-Rezepte
- Eventuell externe Plugins über ein stabiles JSON-Protokoll (stdin/stdout)

### C4 – Weitere Formate
- PDF: Streams, Objekte nach `%%EOF`, eingebettete Dateien
- Office-Dateien (OOXML/ODF): Makros, versteckte Teile
- PCAP: Dateien aus HTTP-, FTP- und SMB-Verbindungen extrahieren

## Ideen-Parkplatz
- TUI-Modus (z. B. mit Bubble Tea) für interaktive Triage
- Writeup-Export: Der Lösungsweg wird als Markdown aus der Herkunftskette erzeugt
- Docker-Image und Pakete (Homebrew, AUR, Kali)
