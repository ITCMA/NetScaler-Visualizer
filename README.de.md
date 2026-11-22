# NetScaler Visualizer (`nsviz`)

🇬🇧 [English version](README.md)

**NetScaler-Konfigurationen visualisieren und prüfen: die gesamte Umgebung auf einer Seite.**

nsviz liest die `ns.conf` eines Geräts oder einer ganzen Umgebung und erzeugt **eine einzelne HTML-Datei**, die offline in
jedem Browser geöffnet werden kann. Es wird nichts hochgeladen und nichts auf der NetScaler installiert.

![Topologie einer Demo-Umgebung: DMZ-NetScaler und Backend-HA-Paar](docs/images/topology.png)

## Funktionen im Überblick
| | |
|---|---|
| 🗺️ **Topologie** | Interaktive Karte aus vServern, Services, Policies, Zertifikaten und Authentifizierung, mit Ebenen, Filtern und Suche. |
| 🔗 **Mehrere NetScaler** | HA-Paare werden zusammengeführt und verglichen; Double-Hop-Ketten (DMZ → intern → Backend) werden geräteübergreifend verfolgt. |
| 🚪 **Gateway-Ansicht** | Pro Gateway: Session-Policies mit wirksamen Werten einschließlich globaler Standardwerte, StoreFront und STA, EPA, Clientzertifikate, ACLs. |
| 🔐 **nFactor-Ablauf** | Der Anmeldeablauf je Einstiegspunkt als Faktorspalten: Schemas, Policies, Aktionen, Erfolgs- und Fehlerpfade. |
| ✅ **Prüfungen** | Mehr als 80 Regeln zu Fehlkonfiguration, Hersteller-Best-Practice und BSI-Hinweisen, jeweils mit Begründung, Quelle und Abhilfe; Health-Score. |
| ⚙️ **Regelkonfiguration** | Regeln deaktivieren, Schweregrade ändern und akzeptierte Risiken mit Begründung und Ablaufdatum erfassen. |
| 🧹 **Bereinigung** | Findet ungenutzte Konfiguration und erzeugt einen geordneten Bereinigungs-Batch mit Rollback-Batch. |
| 🔍 **Vergleich** | Vergleicht zwei Konfigurationsstände: hinzugefügte, entfernte und geänderte Objekte, neue und behobene Befunde. |
| 📤 **Export** | PNG, SVG, PDF, draw.io, CSV, JSON sowie ausgewählte Objekte als NetScaler-Konfiguration. |
| 🕶️ **Datenschutz** | Geheimnisse werden standardmäßig maskiert; Konfigurationen lassen sich zur Weitergabe anonymisieren; alles läuft auf Ihrem Rechner. |
| 🌍 **Sprachen** | Oberfläche in 8 Sprachen, heller und dunkler Modus, Tastaturbedienung. |

<table><tr>
<td><img src="docs/images/gateway.png" alt="Gateway-Ansicht mit Session-Policies" width="100%"></td>
<td><img src="docs/images/nfactor.png" alt="nFactor-Anmeldeablauf" width="100%"></td>
</tr><tr>
<td><img src="docs/images/overview.png" alt="Übersicht mit Health-Score" width="100%"></td>
<td><img src="docs/images/findings.png" alt="Befunde mit Begründung und Abhilfe" width="100%"></td>
</tr></table>

Alle Screenshots zeigen die synthetische Demo-Umgebung in [`examples/demo`](examples/demo). Sie verwendet
Dokumentations-Adressbereiche und erfundene Namen.

## Erste Schritte

### Variante A: Fertige Anwendung (ohne Python)
Laden Sie `nsviz-windows-x64.exe`, `nsviz-macos-arm64.dmg` (Apple Silicon) oder `nsviz-macos-x64.dmg` (Intel) von der
[Releases](../../releases)-Seite. Unter Windows starten Sie die Datei. Unter macOS öffnen Sie das DMG, ziehen `nsviz` nach
*Programme* und starten die App. Im Browser öffnet sich eine lokale Seite. Unter macOS gehört die Kommandozeile zur App:
`/Applications/nsviz.app/Contents/MacOS/nsviz`.

Die macOS-App ist signiert und notarisiert und startet ohne Warnung. Der Windows-Build ist nicht codesigniert, Windows zeigt
deshalb beim ersten Start eine Warnung:
- **Windows:** SmartScreen meldet „Der PC wurde durch Windows geschützt“. Wählen Sie *Weitere Informationen* und danach
  *Trotzdem ausführen*.

Vergleichen Sie vor dem Start die SHA-256-Prüfsumme von der Release-Seite mit der heruntergeladenen Datei.
Hintergründe zur Signierung: [docs/SIGNING.de.md](docs/SIGNING.de.md).

### Variante B: Mit Python 3.10 oder neuer (keine Pakete erforderlich)
```bash
git clone https://github.com/ITCMA/NetScaler-Visualizer.git && cd NetScaler-Visualizer
python3 -m nsviz gui                                   # lokale Seite: Konfigurationen hinzufügen, Optionen setzen, Report erzeugen
python3 -m nsviz analyze examples/demo -o demo.html   # oder direkt per Kommandozeile mit den Demo-Daten
```

### Ersten Report erzeugen
1. Speichern Sie auf jeder NetScaler die laufende Konfiguration (`save ns config`) und kopieren Sie `/nsconfig/ns.conf`.
2. Starten Sie `nsviz gui`, fügen Sie die Dateien hinzu, markieren Sie nicht erkannte HA-Paare und erzeugen Sie den Report.
3. Öffnen Sie die HTML-Datei. Beginnen Sie mit **Übersicht**, danach **Topologie**, **Gateway** und **nFactor**.

Der Report enthält die Topologie der Umgebung. Bewahren Sie ihn auf und geben Sie ihn weiter wie Kundendaten.

## Kommandozeile
```bash
# ein Gerät, ein Ordner mit mehreren Konfigurationen oder beides
python3 -m nsviz analyze adc01.conf adc02.conf -o report.html --csv findings.csv

# HA-Paar explizit angeben (sonst Erkennung über `add ha node`) und Rollen setzen
python3 -m nsviz analyze configs/ --ha pri.conf,sec.conf --role pri.conf=primary --role sec.conf=secondary

# Regelkonfiguration anwenden; CI-Job bei kritischen Befunden fehlschlagen lassen (Exit-Code 2)
python3 -m nsviz analyze configs/ -o report.html --rules rules.json --fail-on critical

# zwei Stände vergleichen, zum Beispiel vor und nach einem Wartungsfenster
python3 -m nsviz compare before/ after/ -o compare.html

# anonymisierte Kopien von Konfigurationen, siehe docs/PRIVACY.de.md
python3 -m nsviz anonymize configs/ -o anonymized/
python3 -m nsviz anonymize configs/ -o anonymized/ --keep ips --remove comments,timezone,location

# Regelkatalog
python3 -m nsviz rules --markdown --lang de > docs/RULES.de.md
```

### Regelkonfiguration
Eine JSON-Datei steuert, welche Befunde erscheinen:
```json
{
  "format": "nsviz-rules", "version": 1,
  "disable": ["QA-003"],
  "severity": {"MGMT-013": "info"},
  "exceptions": [
    {"rule": "QA-001", "object": "lb_legacy*", "device": "*", "reason": "Vom Kunden akzeptiert", "expires": "2027-06-30"}
  ]
}
```
Akzeptierte Ausnahmen werden mit ihrer Begründung am Ende des Tabs „Befunde“ aufgeführt. Nach dem Ablaufdatum erscheint der
Befund wieder. In der lokalen Oberfläche wird die Datei unter *Optionen* ausgewählt.

## Funktionen im Detail

### Topologie und mehrere Geräte
- Geschichtete Karte aller Objekte mit Zoom, Einklappen, Ebenen 1 bis 4, Filtern nach Objekttyp, Suche nach Name, Adresse
  oder Konfigurationstext, Hervorhebung verbundener Objekte, Minimap und Tastaturbedienung.
- HA-Paare werden über `add ha node` erkannt oder mit `--ha` angegeben und als eine Gruppe mit Konfigurationsvergleich
  dargestellt.
- Backend-Ziele, die einem vServer eines anderen Geräts entsprechen, werden als Double-Hop-Ketten verknüpft. Eine
  Übereinstimmung von Adresse und Port ist sicher; eine Übereinstimmung nur der Adresse wird als Annahme gekennzeichnet.
  Hostnamen lassen sich über eine Verknüpfungstabelle oder eine optionale, manuell gestartete DNS-Abfrage verknüpfen.

### Gateway und nFactor
- Der Tab Gateway zeigt je Gateway die Zugriffsprofile (Session-Policies) mit ICA-Proxy, VPN und Clientless-Modus, die
  StoreFront-Ziele und ihre Herkunft, SSO, Split-Tunnel und Standardautorisierung sowie STA-Server, ICA-Policies,
  Intranetanwendungen, Autorisierungs-Policies, AAA-Gruppen, EPA und Clientzertifikat-Authentifizierung. Parameter von
  Session- und Authentifizierungsaktionen öffnen sich in einem Overlay, zusammen mit den globalen VPN-Einstellungen.
- Der Tab nFactor zeigt den Anmeldeablauf je Einstiegspunkt (Gateway, LB- oder CS-vServer mit Authentifizierung,
  Authentication-vServer) als Faktorspalten mit Login-Schema, Policies in Prioritätsreihenfolge, Aktionstyp und dem
  nächsten Schritt bei Erfolg oder Fehler. Die klassische Gateway-Authentifizierung wird ebenfalls dargestellt.

### Prüfungen
- Mehr als 80 Regeln in den Kategorien Fehlkonfiguration, Best Practice und Compliance-Hinweise, jeweils mit Schweregrad,
  Konfidenz (`certain`, `likely`, `heuristic`), Begründung, Abhilfe und Quelle. Der Katalog steht in
  [docs/RULES.de.md](docs/RULES.de.md).
- Der Tab Befunde lässt sich filtern und als CSV exportieren. Die Übersicht zeigt einen Health-Score und die Objekte mit
  dem höchsten Risiko.
- Das Inventar listet alle vServer; der Tab Projekt zeigt Geräte, HA-Unterschiede und Ketten.

### Bereinigung
Die Bereinigungsanalyse findet Konfiguration, die kein erreichbarer vServer, keine GSLB-Domain, keine globale Bindung und
keine Benutzer- oder Gruppenbindung direkt oder über andere Objekte erreicht, sowie Konfiguration, die nur von
deaktivierten Objekten genutzt wird. Beides wird in der Topologie hervorgehoben. Der Exportdialog erzeugt einen
Bereinigungs-Batch mit `unbind`- und `rm`-Befehlen in einer funktionierenden Reihenfolge und einen passenden
Rollback-Batch. Objekte, deren Name auch in einer verbleibenden Zeile vorkommt, werden nur zur Prüfung aufgelistet. Zeilen
mit maskierten Geheimnissen sind im Rollback-Batch auskommentiert und müssen aus der gesicherten `ns.conf` wiederhergestellt
werden.

### Vergleich zweier Stände
`nsviz compare` ordnet die Geräte zweier Stände über den Hostnamen zu und listet je Gerät die hinzugefügten, entfernten und
geänderten Objekte bis auf die geänderten Zeilen, gefolgt von neuen und behobenen Befunden. Geheimnisse sind maskiert.

### Export
Topologie als PNG-, SVG-, PDF- oder draw.io-Datei; Gateway- und nFactor-Seiten als PNG, SVG oder PDF; Befunde, Inventar und
Projekt als CSV; das Modell als JSON; eine Zusammenfassung als Markdown; ausgewählte Objekte als NetScaler-Konfiguration,
wahlweise mit allen Objekten, von denen sie abhängen, in der Reihenfolge der Quelldatei. Jeder Export fragt, ob Originalnamen
oder anonymisierte Namen verwendet werden.

### Anonymisierung
`nsviz anonymize` (oder Abschnitt 5 der lokalen Oberfläche) ersetzt Namen, Adressen, Hostnamen, Benutzer und andere Werte
durch konsistente Pseudonyme, entfernt Geheimnisse immer und vergleicht die Struktur vor und nach der Anonymisierung.
Kommentare, Zeitzone und Standortdaten bleiben erhalten, sofern Sie sie nicht entfernen lassen. Siehe
[docs/PRIVACY.de.md](docs/PRIVACY.de.md).

### Sprachen und Barrierefreiheit
Die Oberfläche steht in Englisch, Deutsch, Französisch, Spanisch, Portugiesisch, Japanisch, Chinesisch und Hindi zur
Verfügung; sie folgt der Browsersprache und lässt sich umschalten. Regeltexte und Befundmeldungen liegen in Englisch und
Deutsch vor; die Übersetzungen in die übrigen Sprachen sind maschinell unterstützt und nicht von Muttersprachlern geprüft.
Heller und dunkler Modus folgen der Systemeinstellung. Die Oberfläche bietet einen Skip-Link, ARIA-Rollen, Fokusrahmen,
Tastaturbedienung in der Karte (`?` zeigt die Tastenkürzel) und Unterstützung für reduzierte Bewegung.

## Dokumentation
[Architektur](docs/ARCHITECTURE.de.md) · [Regeln](docs/RULES.de.md) · [Quellen und Lizenzen](docs/SOURCES.de.md) ·
[Kundendaten](docs/PRIVACY.de.md) · [Rechtliche Hinweise](docs/LEGAL.de.md) · [Release-Signierung](docs/SIGNING.de.md) ·
[Sicherheit](SECURITY.md) · [Mitarbeit](CONTRIBUTING.md) · [Änderungsprotokoll](CHANGELOG.md) ·
[Drittkomponenten](THIRD_PARTY_NOTICES.md)

## Marken
NetScaler und Citrix sind Marken ihrer jeweiligen Inhaber. Dieses Projekt ist unabhängig und weder mit ihnen verbunden noch
von ihnen empfohlen oder unterstützt. Ergebnisse sind automatisierte Hinweise ohne Gewähr; siehe
[docs/LEGAL.de.md](docs/LEGAL.de.md).

## Lizenz
Proprietär, alle Rechte vorbehalten. Siehe [LICENSE](LICENSE).
