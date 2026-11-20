# Quellen und Lizenzen

🇬🇧 [English version](SOURCES.md)

## Test-/Trainingsdaten (nicht Teil des Repositorys)
Öffentliche Beispiel-Configs liegen **nicht** im Repository. `python3 scripts/fetch_testdata.py` lädt sie in den per Git
ignorierten Ordner `testdata/`; die Korpus-Tests werden übersprungen, wenn er fehlt.

Quelle: <https://github.com/f5devcentral/vscode-f5-flipper>, Verzeichnis `tests/artifacts/` (festgelegt auf Commit `e89eb68d6790`),
**Apache License 2.0** (das Skript lädt auch den Lizenztext). 38 Dateien (`*.ns.conf`, `namaste.conf`, `ns1_v13.1*.conf`); Versionskopf
(`#NS…`) steht in 28 davon: 13.0 (1), 13.1 (27), die übrigen haben keinen Kopf. Laut Upstream-README teils auf echter NetScaler-VPX
deployt („verified“), teils synthetisch. Das Skript ersetzt lange Hex-Blobs (≥ 40 Hex-Zeichen: nsroot-Hash, `encryptionParams -keyValue`,
`rpcNode -password`) durch Nullen gleicher Länge. Geprüft wurde auf E-Mail-Adressen (nur `example.com`), Hex-Secrets und öffentliche
IPs/Domains (Beispielwerte, DNS-Root-Server, `example.com`, `f5flipper.com`); ein vollständiges Audit auf echte Kundendaten ist das **nicht**.
Die Herkunft der Inhalte der einzelnen Upstream-Dateien ist nicht verifiziert.

Abdeckung: LB, CS, GSLB, AppFW, Authentifizierung (LDAP/RADIUS/SAML/OAuth/nFactor), Caching, Kompression, Rate Limiting, HA/Cluster,
SSL-Profile, Monitore, Persistenz, Audit, Netzwerkobjekte.
**Lücken:** kein Gateway (`vpn vserver`), keine Version 14.1/15.1, kein IP-Reputation-Beispiel. Dafür gibt es `examples/demo/` (eigene,
vollständig synthetische Configs; 14.1-Header).

Nicht übernommen: Beispiele aus Herstellerdokumentation und Support-Artikeln (Urheberrecht, keine Weiterverwendungslizenz) – sie dienten
nur als Syntax-Referenz für eigene synthetische Configs. Weitere gefundene Projekte (z. B. Skript-Repositories des Herstellers,
Ansible-/Puppet-Module) wurden nicht auf Beispiel-Configs und Lizenz geprüft.

## Eingebettete Bibliotheken (`nsviz/assets/vendor/`)
| Bibliothek | Lizenz |
|---|---|
| cytoscape 3.x | MIT |
| dagre 0.8.x (enthält graphlib, lodash) | MIT |
| cytoscape-dagre 2.x | MIT |

Lizenztexte liegen daneben (`LICENSE-*.txt`); siehe auch [THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md).

## Regel-Referenzen
Siehe [RULES.de.md](RULES.de.md). Genannt werden BSI TR-02102-2, BSI-IT-Grundschutz-Bausteine (Themenebene) und der Citrix/NetScaler
Secure Deployment Guide. Die Zuordnung ist eine fachliche Einordnung des Autors und **nicht gegen die aktuellen Dokumente verifiziert**
(kein Zugriff während der Erstellung) – bitte vor Audit-Nutzung prüfen und die Ausgabe/Edition angeben.
