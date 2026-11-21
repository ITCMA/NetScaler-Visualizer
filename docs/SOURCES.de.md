# Quellen und Lizenzen

🇬🇧 [English version](SOURCES.md)

## Beispiel-Konfigurationen (nicht Teil dieses Repositorys)
`python3 scripts/fetch_testdata.py` lädt öffentliche Beispiel-Konfigurationen in den Ordner `testdata/`, der von git
ausgeschlossen ist. Tests, die sie nutzen, werden übersprungen, wenn der Ordner fehlt.

- **Quelle:** <https://github.com/f5devcentral/vscode-f5-flipper>, Verzeichnis `tests/artifacts/`, auf einen festen Commit festgelegt.
- **Lizenz:** Apache License 2.0; das Skript lädt auch den Lizenztext.
- **Inhalt:** 38 Dateien zu Load Balancing, Content Switching, GSLB, Application Firewall, Authentifizierung (LDAP, RADIUS, SAML,
  OAuth, nFactor), Caching, Kompression, Rate Limiting, HA und Cluster, SSL-Profilen, Monitoren, Persistenz, Audit und
  Netzwerkobjekten. Die meisten Dateien sind NetScaler-13.1-Konfigurationen.
- **Behandlung:** Das Skript ersetzt lange Hex-Werte (Kennwort-Hashes, Schlüsselwerte) durch Nullen gleicher Länge.
- **Von den Beispielen nicht abgedeckt:** Gateway (`vpn vserver`), NetScaler 14.1 und 15.1 sowie IP-Reputation. Die synthetischen
  Konfigurationen in `examples/demo/` decken diese ab.

Beispiele aus Herstellerdokumentation und Support-Artikeln werden nicht verwendet, da sie urheberrechtlich geschützt sind. Sie
dienten nur als Syntaxreferenz für die synthetischen Konfigurationen.

## Eingebettete Bibliotheken (`nsviz/assets/vendor/`)
| Bibliothek | Lizenz |
|---|---|
| Cytoscape.js 3.x | MIT |
| dagre 0.8.x (enthält graphlib und lodash) | MIT |
| cytoscape-dagre 2.x | MIT |

Die Lizenztexte liegen neben den Dateien (`LICENSE-*.txt`); siehe auch [THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md).

## Regelverweise
Regeln verweisen auf die BSI TR-02102-2, Bausteine des BSI IT-Grundschutzes und die Secure-Deployment-Hinweise des Herstellers
auf Themenebene; siehe [RULES.de.md](RULES.de.md). Die Zuordnung ist eine fachliche Einordnung und muss vor der Verwendung in
einem Audit gegen die aktuelle Fassung des Dokuments geprüft werden.
