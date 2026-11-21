# Architektur

🇬🇧 [English version](ARCHITECTURE.md)

nsviz liest NetScaler-`ns.conf`-Dateien, baut ein Modell der Objekte und ihrer Beziehungen auf, wertet Regeln darauf aus und
schreibt das Ergebnis als eine in sich geschlossene HTML-Datei. Alles läuft lokal und nutzt nur die Python-Standardbibliothek.

## Datenfluss
```
ns.conf ──► parser.py ──► Config (Entitäten, Bindungen, Features)
                              │
                 model.py ◄───┘  Graph: Knoten (Objekte) + Kanten (Bindungen, Verweise)
                              │
 rules/*.py  ◄── Ctx(cfg, graph) ── Befunde (Regel-ID, Schweregrad, Objekt, Beleg; Meldungen in en und de)
                              │
 project.py: mehrere Dateien → Geräte → HA-Gruppen (Diff) → Double-Hop-Verbindungen → JSON
                              │
 report.py + assets/ ──► eine HTML-Datei (Daten als JSON, Cytoscape, dagre und die Anwendung eingebettet)
```

## Komponenten
| Modul | Aufgabe |
|---|---|
| `parser.py` | Generischer Zeilenparser: Verb, Objekttyp, positionale Argumente und `-Optionen`. Es gibt kein Schema je Befehl, daher bleiben auch Befehle neuer Firmware-Versionen erhalten. `add`, `set`, `unset`, `rm`, `bind`, `unbind`, `link`, `enable` und `disable` werden der Reihe nach angewendet. HTML-kodierte Dateien werden dekodiert. |
| `model.py` | Übersetzt Entitäten in Knoten (vServer aller Arten, Services, Server, Monitore, Zertifikate, Profile, Policies, Actions, nFactor-Labels und -Schemas, Netzwerkobjekte u. a.) und Kanten (Bindungen, Policy-Verweise, Zertifikatsketten, Backend-Ziele, Authentifizierungsketten). Verweise auf nicht definierte Objekte werden als fehlend markiert. Baut außerdem die Ansichten Gateway und nFactor auf. |
| `rules/` | Ein Modul je Thema. Eine Regel ist eine Funktion, die mit `@rule(id, severity, category, refs, confidence)` registriert wird. Titel, Begründung und Behebung stehen in Sprachkatalogen (`rules/i18n/`). Module werden automatisch geladen. |
| `ruleconfig.py` | Regelkonfiguration: Regeln abschalten, Schweregrade ändern, akzeptierte Risiken mit Begründung und optionalem Ablaufdatum festhalten. |
| `project.py` | Führt mehrere Dateien zusammen: Geräte, HA-Gruppen mit Konfigurations-Diff, Double-Hop-Ketten, Verknüpfungsdateien, Bereinigungsanalyse. Erzeugt das JSON für den Report. |
| `linking.py` | Geräteübergreifende Verknüpfung: FQDN-Ziele, Verknüpfungsdateien, optionale DNS-Auflösung (manuell gestartet). |
| `compare.py` | Vergleich zweier Konfigurationsstände: hinzugefügte, entfernte und geänderte Objekte, neue und behobene Befunde. |
| `anonymize.py` | Konsistente Pseudonymisierung von Konfigurationen mit Strukturprüfung vorher und nachher. |
| `report.py`, `assets/` | Bettet Daten, Texte (`assets/i18n/`, 8 Sprachen) und Bibliotheken in eine HTML-Datei ein. |
| `gui.py` | Lokale Weboberfläche (nur 127.0.0.1, Zugriffstoken, Host-Prüfung, Upload-Limits). |
| `cli.py` | Kommandozeile: `analyze`, `compare`, `anonymize`, `gui`, `resolve`, `rules`. |

## Regeln
Eine Regel wertet nur Tatsachen aus, die ausdrücklich in der Konfiguration stehen. Hängt eine Aussage von Standardwerten oder
vom Laufzeitzustand ab, trägt die Regel die Sicherheit `likely` oder `heuristic`; `certain` bedeutet, dass die Aussage allein
aus der Konfiguration folgt. Der Regelkatalog wird erzeugt (`python3 -m nsviz rules --markdown`, siehe [RULES.de.md](RULES.de.md))
und in der CI geprüft.

Eine neue Regel besteht aus einer Funktion in einem Modul unter `nsviz/rules/` und Einträgen in `i18n/en.json`, `i18n/de.json`,
`i18n/messages_en.json` und `i18n/messages_de.json`. Ein Test prüft, dass jede Regel Texte in beiden Sprachen hat.

## Mehrere Geräte
- **HA-Paare** werden über `add ha node` (Partner-NSIP) erkannt oder mit `--ha` angegeben. Der Konfigurations-Diff lässt
  knotenspezifische Objekte aus (NSIP, Hostname, Interfaces, `rpcNode`).
- **Double Hop:** Ein Backend-Ziel (Mitglied eines Service oder einer Service Group), dessen Adresse zu einem vServer eines
  anderen Geräts passt, erzeugt eine `double-hop`-Kante. Passen Adresse und Port, ist die Zuordnung sicher; passt nur die
  Adresse, ist sie als Annahme markiert.
- **FQDN-Ziele** werden nicht automatisch aufgelöst. Sie stehen im Reiter Verknüpfungen; eine Verknüpfungsdatei oder die
  optionale DNS-Auflösung macht daraus Verbindungen.

## Ansichten im Report
Übersicht, Topologie (Ebenenkarte mit Stufen, Filtern und Suche), Gateway, nFactor, Befunde, Inventar, Projekt (Geräte,
HA-Diff, Ketten), Verknüpfungen, Regeln. Gateway und nFactor lassen sich als PNG, SVG oder PDF exportieren. Die Topologie
kann zusätzlich als draw.io-Datei exportiert werden; ausgewählte Objekte lassen sich als NetScaler-Konfiguration exportieren,
bei Bedarf mit ihren Abhängigkeiten.

## Sicherheitseigenschaften
- Der Report ist eine statische Datei ohne Netzzugriff; seine Content-Security-Policy verbietet externe Ressourcen.
- Passwörter und Schlüssel in eingebetteten Konfigurationszeilen werden standardmäßig maskiert.
- Die lokale Oberfläche bindet an 127.0.0.1, verlangt ein zufälliges Token, prüft den `Host`-Header, begrenzt Anfragegrößen
  und legt Uploads in einem temporären Ordner ab.
- Der einzige optionale Netzzugriff ist die manuell gestartete DNS-Auflösung von Hostnamen im Reiter Verknüpfungen.

## Skalierung
Analyse und Report wurden mit synthetischen Konfigurationen gemessen: Rund 9.000 Objekte werden in etwa 4 Sekunden analysiert
und öffnen im Browser in etwa 4 Sekunden; rund 24.000 Objekte benötigen etwa 10 Sekunden und öffnen in etwa 11 Sekunden (hinzu
kommt der Layout-Lauf der Topologie). Für sehr große Umgebungen die Ebenenauswahl und die Filter nutzen.
