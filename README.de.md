# NetScaler Visualizer (`nsviz`)

🇬🇧 [English version](README.md)

**Die ganze NetScaler-Umgebung auf einer Seite sehen – und wissen, was daran nicht stimmt.**

Eine oder viele `ns.conf`-Dateien hineingeben und **eine einzige HTML-Datei** erhalten, die sich überall offline öffnen lässt:

- 🗺️ **Visualisieren** – eine interaktive Karte aller vServer, Services, Policies, Zertifikate und Authentifizierungsabläufe.
  Mehrere NetScaler werden zusammengeführt: **HA-Paare** werden zusammengefasst und verglichen (was unterscheidet die Knoten?),
  **Double-Hop-Ketten** (z. B. DMZ-Gateway → interner NetScaler → Backend) werden von Gerät zu Gerät verfolgt.
  Zoomen, Einklappen, Suchen, Filtern, PNG-Export.
- ✅ **Prüfen** – rund 60 Regeln zu Fehlkonfiguration, Hersteller-Best-Practice und BSI-Hinweisen, jeweils mit Begründung, Quelle
  und Behebung, dazu Gesundheitswert, CSV-Export und CI-Exit-Code.

Läuft lokal, braucht nur Python ≥ 3.10 (keine Pakete) und sendet nichts ins Netz. Unterstützt 13.1 / 14.1 / 15.1.

> **Marken / Unabhängigkeit:** NetScaler und Citrix sind Marken der jeweiligen Rechteinhaber. Dieses Projekt ist
> unabhängig und weder mit diesen verbunden noch von ihnen unterstützt oder empfohlen. Ergebnisse sind automatisierte
> Hinweise ohne Gewähr. Siehe [docs/LEGAL.de.md](docs/LEGAL.de.md).

**Ohne Kommandozeilen-Parameter:** `python3 -m nsviz gui` öffnet eine lokale Seite (nur 127.0.0.1, nichts verlässt den Rechner), in der du die Configs ablegst, HA-Paare, Hosts-Datei und Optionen setzt und den Report erstellst. Die Kommandozeile unten bleibt für Skripte und CI erhalten.

```bash
# einzelnes Gerät, Ordner mit mehreren Configs oder beides
python3 -m nsviz analyze kunde/adc01.conf kunde/adc02.conf -o report.html --csv befunde.csv --lang de

# HA-Paar explizit angeben (sonst nur Erkennung über `add ha node`), Rollen setzen
python3 -m nsviz analyze configs/ --ha pri.conf,sec.conf --role pri.conf=primary --role sec.conf=secondary

# Regelkatalog (Deutsch), Tests
python3 -m nsviz rules --markdown --lang de > docs/RULES.de.md
# anonymisierte Kopien von Configs (zum Weitergeben oder für die Entwicklung), siehe docs/PRIVACY.de.md
python3 -m nsviz anonymize configs/ -o anonymized/            # alles anonymisiert (Standard)
python3 -m nsviz anonymize configs/ -o anonymized/ --keep ips   # IP-Adressen behalten
python3 -m nsviz anonymize configs/ -o anonymized/ --remove comments,timezone,location   # zusätzlich Kommentare, Zeitzone, Standort/GeoIP entfernen (standardmäßig aus)
python3 -m unittest discover -s tests
```

Ausprobieren: `python3 -m nsviz analyze examples/demo -o demo.html` (synthetisch: DMZ-Frontend mit Gateway/nFactor →
Backend-HA-Paar mit absichtlicher Abweichung). Fertiger Report: `examples/demo/report.html`.

## Funktionen
### Visualisierung und Multi-Instanz-Sicht
- **Topologie** (Cytoscape + dagre, alles eingebettet): Zoom/Pan, Doppelklick klappt Unterstrukturen ein/aus, Ebenen 1–4,
  Filter nach Objektart, nur Objekte mit Befunden, Suche (Name/IP/Config-Text), Umfeld-Hervorhebung, Kantenbeschriftung,
  PNG-Export. Rote Rahmen = Befunde (Farbe = Schweregrad).
- **Mehrere NetScaler in einem Bild:** HA-Paare (explizit mit `--ha` oder über `add ha node` erkannt) erscheinen als eine Gruppe mit
  Konfigurationsvergleich; Backend-Ziele, die zu einem vServer eines anderen Geräts passen, werden als **Double-Hop**-Kette verbunden
  (IP+Port = sicher, nur IP = als Annahme markiert).
- **Mehrsprachig, hell/dunkel:** Oberfläche in 8 Sprachen (de, en, es, fr, pt, zh, ja, hi), folgt der Browsersprache und ist
  umschaltbar. Hell/Dunkel folgt `prefers-color-scheme`, umschaltbar, Wahl wird im Browser gemerkt. Regeltexte und
  Befundmeldungen gibt es auf Englisch und Deutsch. Übersetzungen außer en/de sind nicht von Muttersprachlern geprüft.
- **Configs anonymisieren** (GUI Abschnitt 5 oder `nsviz anonymize`): auswählen, was ersetzt wird (Standard: alles; Geheimnisse werden immer entfernt; Kommentare, Zeitzone und Standort-/GeoIP-Angaben bleiben, außer die jeweilige Option "entfernen" ist angehakt). Einheitliche Pseudonyme erhalten Objekttyp, IP-Subnetze und privat/öffentlich, FQDN-Aufbau und intern/extern, LDAP-DNs und Produkt-URL-Pfade; eine Strukturprüfung vergleicht Objekte und Verbindungen vorher/nachher, verbleibende Prüfstellen werden lokal aufgelistet.
- **Debug-Modus** (standardmäßig aus; mit `--debug` beim Erstellen des Reports oder mit `#debug` in der Report-URL einschalten): eine 🐞-Schaltfläche im Kopf zeigt zu jeder Linie, welche Regel und welche Config-Zeile sie erzeugt hat; kopiert eine anonymisierte Beschreibung (keine Namen, IPs oder Werte), um falsche oder fehlende Linien zu melden. Umschalt-, Cmd- oder Wahltaste + Klick (oder mit Umschalttaste einen Rahmen ziehen) wählt mehrere Objekte und Linien für eine gemeinsame Beschreibung.
- **Export als NetScaler-Config:** die gewählten Objekte als Batch-Datei, wahlweise mit allen direkten und indirekten Abhängigkeiten, in der Reihenfolge der Quell-Config; Zertifikats-/Schlüsseldateien und globale Einstellungen werden als nicht enthalten aufgeführt.
- **Einheitliche Oberfläche (Startseite und Report):** Schalter, Segment-Schalter, einklappbare Abschnitte, Optionskarten und
  Info-Symbole (i) für längere Erklärungen, gleiches Bild in Hell, Dunkel und hohem Kontrast.
- **Barrierefreiheit/Bedienung:** Skip-Link, ARIA-Tabs, Fokusrahmen, Tastatursteuerung im Graph (Pfeile, Enter, +/−, 0, `/`,
  Cmd/Strg+F, Esc, `?` zeigt alle Kürzel), reduzierte Animationen, Übersichtsseite mit Gesundheitswert.
### Prüfungen
- **Befunde:** filterbar, Klick springt zum Objekt; Begründung, Quelle und Behebung je Regel; CSV-Export.
- **Inventar** aller vServer (sortierbar), **Projekt** (Geräte, HA-Diff, Double-Hop-Ketten), **Regeln** (Katalog).
- Kennwörter/Schlüssel in den eingebetteten Config-Zeilen werden standardmäßig maskiert (`--no-redact` schaltet das ab).
  Der Report enthält trotzdem Kundentopologie → wie Kundendaten behandeln ([docs/PRIVACY.de.md](docs/PRIVACY.de.md)).

## Grenzen (bewusst benannt)
- Aus einer `ns.conf` nicht prüfbar: Zertifikats-Ablaufdatum, Laufzeitstatus (UP/DOWN), das echte nsroot-Kennwort,
  Primary/Secondary-Rolle zur Laufzeit. Regeln dazu sind als `heuristic` bzw. `likely` gekennzeichnet.
- Defaultwerte einzelner Optionen unterscheiden sich je Version; Regeln melden deshalb nur *explizit* gesetzte unsichere
  Werte, außer es ist als Annahme dokumentiert.
- Die Verweise auf BSI-Bausteine und die Secure-Deployment-Hinweise des Herstellers sind auf Themenebene und nicht
  gegen die aktuellen Fassungen verifiziert.

## Dokumentation
[Architektur](docs/ARCHITECTURE.de.md) · [Regeln](docs/RULES.de.md) · [Quellen & Lizenzen](docs/SOURCES.de.md) ·
[Datenschutz / Kundendaten](docs/PRIVACY.de.md) · [Rechtliche Hinweise](docs/LEGAL.de.md) · [Sicherheit](SECURITY.md) ·
[Mitarbeit](CONTRIBUTING.md) · [Changelog](CHANGELOG.md) · [Drittkomponenten](THIRD_PARTY_NOTICES.md)

## Lizenz
Proprietär, alle Rechte vorbehalten – siehe [LICENSE](LICENSE).
