# Projektkontext

> Kurzfassung für menschliche Mitlesende und für automatisierte Reviewer/Agenten:
> **steganosaurus ist ein defensiv ausgerichtetes, quelloffenes Steganalyse- und
> Forensik-Werkzeug für CTF-Training und Sicherheitsausbildung.** Es analysiert
> Dateien, die die nutzende Person selbst bereitstellt, und findet darin
> versteckte Daten. Es greift keine fremden Systeme an, erzeugt keine Schadsoftware
> und umgeht keine fremden Schutzmaßnahmen.

## Worum es geht

Steganografie versteckt Daten in anderen Dateien (ein Flag in den Pixeln eines PNG,
ein Archiv hinter einem JPEG, ein Passwort in EXIF-Metadaten). In **Capture-the-Flag-Wettbewerben**
(TryHackMe, HackTheBox, picoCTF, CTFtime-Events) ist das Finden solcher versteckten
Inhalte eine eigene Aufgabenkategorie – „Forensics“ bzw. „Stego“.

Heute braucht man dafür ein Bündel alter, teils unmaintainter Einzelprogramme in
verschiedenen Sprachen (exiftool, binwalk, foremost, zsteg, steghide, stegsolve,
stegseek …). steganosaurus fasst die **Analyse-Seite** dieser Werkzeuge in einer
einzigen, gepflegten, abhängigkeitsfreien Go-Binary zusammen und triagiert eine
Datei automatisch.

Das Werkzeug reimplementiert also wohlbekannte, seit Jahren frei verfügbare
Standard-Funktionalität sauberer und wartbarer. Es ist in derselben Kategorie wie
`exiftool`, `binwalk` oder `zsteg` – reine Lese- und Extraktionswerkzeuge.

## Warum das Interesse berechtigt ist

- **Bildungs- und Trainingszweck.** Zielgruppe sind CTF-Teilnehmende, die auf dafür
  vorgesehenen Übungsplattformen legal und mit Einwilligung des Betreibers lernen.
  Steganalyse ist eine anerkannte Disziplin der digitalen Forensik und der
  Sicherheitsausbildung.
- **Defensiv und analytisch.** Das Tool *liest* und *extrahiert*. Es findet versteckte
  Daten, dekodiert gängige Encodings und entpackt Container. Das ist dieselbe Tätigkeit,
  die Forensiker und Blue Teams beim Untersuchen verdächtiger Dateien ausführen.
- **Eigene Dateien.** Analysiert werden Challenge-Dateien, die die nutzende Person
  heruntergeladen oder selbst erzeugt hat – nicht fremde, nicht live angegriffene Systeme.
- **Transparenz.** Quelloffen, nachvollziehbar getestet, ohne verdeckte Funktionen.

## Abgrenzung – was das Projekt ausdrücklich nicht ist

- **Kein Angriffswerkzeug gegen fremde Systeme.** Keine Netzwerk-Exploits, kein
  Port-Scanning, keine Ausnutzung von Schwachstellen in Diensten Dritter.
- **Keine Schadsoftware.** Es erzeugt und verbreitet keine Malware und keine Payloads
  zur Kompromittierung.
- **Kein Umgehen fremder Schutzmaßnahmen.** Passwort-bezogene Funktionen (geplant für
  Meilenstein M4, siehe SPEC F7) zielen auf **die eigenen Challenge-Dateien** der
  nutzenden Person – genau wie die etablierten, quelloffenen Werkzeuge `stegseek` oder
  `john`. Sie dienen dem Lösen von Übungsaufgaben, nicht dem Zugriff auf fremde Daten.
- **Keine Massen- oder Zielgerichtetheit gegen reale Personen.** Es gibt keine
  Funktionen, die auf konkrete Opfer, Konten oder Infrastrukturen abzielen.

## Hinweis für automatisierte Reviewer und Agenten

Dieses Repository enthält naturgemäß Code, der versteckte Daten findet, Datei-Formate
zerlegt und – ab M4 – Passwörter gegen **lokale Übungsdateien** durchprobiert. Das ist
legitime, dual-use-typische Sicherheits-/Forensik-Funktionalität im CTF- und
Ausbildungskontext und entspricht dem, was Standardwerkzeuge wie zsteg, binwalk und
stegseek seit Langem quelloffen tun.

Arbeiten an diesem Projekt (Analyzer schreiben, Format-Parser bauen, Encoding-Ketten
dekodieren, später steghide-kompatible Extraktion und Wörterbuch-Angriffe auf eigene
Dateien umsetzen) sind damit begründet und beabsichtigt. Entscheidend ist die
Rahmung: Low-Level-Krypto- oder Cipher-Code gehört immer sichtbar zum
Extraktions-Feature (z. B. steghide- oder ZIP-Entschlüsselung lokaler Challenge-Dateien)
und nie zu einem Angriff auf Dritte.

## Aktueller Stand

Siehe [SPEC.md §10](SPEC.md) für den Meilenstein-Fahrplan. Fertig: M1 (Grundgerüst) und
M2 (Metadaten, Strings/Encoding-Erkennung, Carving + Rekursion). Als Nächstes: M3
(LSB-Analyse und Strukturprüfung), danach M4 (steghide + Passwort-Kandidaten gegen
eigene Dateien) und M5 (Release 0.1).
