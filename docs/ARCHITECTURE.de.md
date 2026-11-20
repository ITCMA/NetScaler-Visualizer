# Architektur, Empfehlung und Phasenplan

🇬🇧 [English version](ARCHITECTURE.md)

## Empfehlung: Offline-HTML-Report reicht (Phase 1) – keine App nötig
**Annahme:** Kunden-Configs sind sensibel und werden auf dem Consultant-Laptop analysiert; der Report geht evtl. per Mail/Share an den Kunden.

Dafür spricht:
- Eine Datei, offline, ohne Installation beim Empfänger, ohne Cloud/Server → keine Datenabflüsse, einfache Freigabe beim Kunden.
- Aufklappen, Zoomen, Ein-/Ausblenden, Suche, Filter, Pfad-Hervorhebung sind im Browser mit eingebettetem JS (Cytoscape) vollständig machbar; getestet bis ~750 Knoten, die Bibliothek skaliert deutlich weiter.
- Erzeugt wird der Report von einer kleinen lokalen CLI (`python3 -m nsviz`), die nur die Standardbibliothek braucht.

Eine App/ein lokaler Server lohnt erst, wenn gewünscht ist: (a) Configs per Drag & Drop im Browser laden (dann müsste der Parser nach JS portiert oder ein lokaler Mini-Server `nsviz serve` gebaut werden), (b) Verlauf/Vergleich mehrerer Config-Stände mit Datenhaltung, (c) sehr große Umgebungen (> ca. 10.000 Objekte, dann Lazy-Loading/Clustering), (d) Config-Änderungen/Generierung. Das ist als Phase 3 vorgesehen, die Architektur (JSON-Modell zwischen Analyse und Ansicht) lässt das zu.

## Aufbau
```
ns.conf ──► parser.py ──► Config (Entitäten, Bindungen, Features)
                              │
                 model.py ◄───┘  Graph: Knoten (Objekte) + Kanten (Bindungen/Referenzen)
                              │
 rules/*.py  ◄── Ctx(cfg, graph) ── Findings (Regel-ID, Schwere, Stelle, Beleg)
                              │
 project.py: mehrere Dateien → Geräte → HA-Gruppen (Diff) → Double-Hop-Links → JSON
                              │
 report.py + assets/ ──► ein HTML (Daten als JSON, Cytoscape/dagre/App-JS inline)
```
- **parser.py** – generisch (Verb, Objekttyp, Positionsargumente, `-Optionen`), kein Schema je Befehl → unbekannte/neue Befehle (14.1/15.1) gehen nicht verloren. `add/set/unset/rm/bind/unbind/link/enable/disable` werden angewendet.
- **model.py** – übersetzt Objekte in Knotenarten (CS/LB/GW/AAA/GSLB-vServer, Service(Group), Server, Monitor, Zertifikat, SSL-Profil, Policies, nFactor-Labels/-Schemas, WAF-Profile …) und Kanten (CS→Policy→LB, LB→Service→Server, vServer→Zertifikat, Gateway→Authn-Profil→Auth-vServer→Policy→nextFactor-Label→Login-Schema, GSLB-Service→lokaler vServer …). Tote Referenzen werden als „fehlend“ markiert.
- **rules/** – eine Datei pro Themenbereich; neue Regel = Funktion mit `@rule(id, severity, category, refs, confidence)`; Titel, Begründung, Behebung und Befundmeldungen stehen in den Katalogen `rules/i18n/{en,de}.json` und `messages_{en,de}.json` (Englisch führend, Deutsch ergänzt; ein Test prüft Vollständigkeit). Module werden automatisch geladen. `python3 -m nsviz rules --markdown [--lang de]` erzeugt den Katalog.
- **project.py** – HA-Erkennung über `add ha node` (NSIP des Partners) oder `--ha`; Ähnlichkeit gleicher vServer-Adressen wird nur als *Hinweis* ausgegeben (keine automatische Zuordnung). HA-Diff ohne knotenspezifische Objekte (NSIP, Hostname, Interfaces, rpcNode …). **Double-Hop:** Backend-Ziel (Service/Service-Group-Member) eines Geräts = vServer-Adresse eines anderen Geräts → Kante `Double-Hop`; IP+Port = sicher, nur IP = als Annahme markiert. FQDN-Ziele werden nicht aufgelöst.

## Phasenplan
| Phase | Inhalt | Status |
|---|---|---|
| 1 | Parser, Modell, Topologie-Ansicht, ca. 58 Regeln, HA-Diff, Double-Hop, CSV/JSON | umgesetzt |
| 2 | Gateway tiefer (Session-Policies/-Actions, STA, ICA-Proxy, StoreFront, EPA), nFactor-Flussansicht mit Regelausdrücken, AppFW-Checks/Signaturen, Rewrite/Responder-Actions als Knoten, Netzwerk-Ansicht (VLAN/SNIP/Routen/TD/Cluster), Versions-Defaulttabellen 13.1/14.1/15.1, Regeln anpassbar (Schwere ändern, abschalten, Ausnahmen), ca. 120 Regeln | offen |
| 3 | Vergleich zweier Config-Stände, optional `nsviz serve` (Upload im Browser), Draw.io/SVG-Export, Performance > 10k Objekte | offen |

## Offene Fragen
1. Welche BSI-Basis soll gelten: IT-Grundschutz-Bausteine (NET.1.1/1.2, OPS.1.1.5, ORP.4, APP.3.1 …), nur TR-02102-2 (TLS), oder ein Kunden-Sicherheitskonzept? Aktuell sind Bausteine **auf Themenebene** zugeordnet, keine Anforderungs-IDs.
2. Soll zusätzlich Ausgabe von `show ssl certKey` o. Ä. eingelesen werden, um Ablaufdaten zu prüfen? (In der ns.conf nicht enthalten.)
3. Dateinamen-Konventionen der Kundenumgebungen (z.B. `*_pri`/`*_sec`) für die Rollenerkennung?
4. Wie sollen Ausnahmen („Kunde akzeptiert Risiko“) dokumentiert werden (Datei neben der Config)?
5. Projektname: „NetScaler“ im Namen ist ein Markenrisiko, siehe [LEGAL.de.md](LEGAL.de.md).
