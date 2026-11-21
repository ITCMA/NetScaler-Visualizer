# Umgang mit Kundendaten

🇬🇧 [English version](PRIVACY.md)

Dieses Dokument beschreibt, wie man mit Kundenkonfigurationen sicher arbeitet. Es ist keine Rechtsberatung (siehe [LEGAL.de.md](LEGAL.de.md)).

## Was ist sensibel
Eine `ns.conf` kann interne IP-Adressen und Topologie, Host- und Domänennamen, Benutzer- und Administratornamen, LDAP-Bind-DNs,
SNMP-Community-Strings, E-Mail-Adressen, Zertifikats- und Schlüsselnamen, verschlüsselte Kennwort- und Schlüsselwerte sowie
Kommentare von Administratoren enthalten. Der erzeugte Report enthält Topologie und Konfigurationszeilen der Umgebung.
Konfigurationen, Reports, CSV- und JSON-Exporte und Screenshots wie Kundendaten behandeln.

## Grundsätze
1. **Lokale Verarbeitung.** nsviz läuft auf dem eigenen Rechner und sendet nichts. Der Report nutzt nie das Netzwerk.
2. **Kundendaten gehören nicht in Repositorys.** Weder in Code, Tests, Dokumentation, Beispiele, Issues, Commit-Texte noch in die
   CI. Tests und Beispiele nutzen synthetische Daten (Dokumentationsbereiche `192.0.2.0/24`, `198.51.100.0/24`,
   `203.0.113.0/24`, `example.com`) oder öffentliche Beispiel-Konfigurationen, die bei Bedarf geladen werden.
3. **Getrennte Ablage.** Kundenmaterial in einem Ordner außerhalb der Arbeitskopie halten, benannt mit neutralen Projekt-IDs
   statt Kundennamen. Muss es in die Arbeitskopie, `private/` verwenden, das von git ausgeschlossen ist.
4. **Schutz vor Versehen.**
   - `.gitignore` schließt `private/`, `customer*/`, `local/`, `anonymized/`, Reports, Exporte und Archive aus.
   - `scripts/hooks/pre-commit` (Installation: `sh scripts/install-hooks.sh`) blockiert gestagte Kundenpfade, lange Hex-Werte,
     Private-Key-Header und absolute Benutzerpfade und führt die Tests aus.
   - Die Hygiene-Tests durchsuchen Code, Dokumentation, Beispiele und Skripte nach Secrets, E-Mail-Adressen, absoluten Pfaden
     und unzulässigen Verweisen.
   - GitHub Secret Scanning und Push Protection für das Repository aktivieren.
5. **Maskierung.** Reports maskieren Kennwörter und Schlüssel in eingebetteten Konfigurationszeilen standardmäßig. Die
   Maskierung beruht auf bekannten Optionsnamen und ist keine Garantie. `--no-redact` nicht für Material verwenden, das den
   eigenen Rechner verlässt.
6. **Weitergabe eines Reports** an den Kunden ist eine Entscheidung je Projekt; vorher Vertrag und etwaige
   Geheimhaltungsvereinbarung prüfen und den Report nur dem Kunden geben, dem die Daten gehören.
7. **Minimieren und löschen.** Nur aufbewahren, was das Projekt braucht, und Konfigurationen und Reports nach Projektende
   löschen, entsprechend der mit dem Kunden vereinbarten Aufbewahrung.

## Konfigurationen anonymisieren
Um eine Konfiguration weiterzugeben, etwa zur Nachstellung eines Problems, wird sie zuerst anonymisiert, und nur mit
Einverständnis des Kunden.

```bash
python3 -m nsviz anonymize ~/nsviz-private/configs -o ~/nsviz-private/anonymized
```
Standardmäßig wird so viel wie möglich anonymisiert:
- Objektnamen und jeder andere Wert, der kein Schlüsselwort, keine Zahl und keine Konstante ist, werden zu einheitlichen
  Pseudonymen wie `lbvserver_0012`.
- IPv4-Adressen werden zu synthetischen `10.x.y.z`-Adressen; Hosts eines /24 bleiben in einem /24, Netzmasken und `0.0.0.0`
  bleiben erhalten. IPv6-Adressen werden zu `2001:db8::N`; Hostnamen und E-Mail-Adressen werden zu `hostN.example.com` und
  `userN@example.com`.
- Kennwörter, Schlüssel und lange Hex-Werte werden entfernt; Beschreibungen, LDAP-DNs und -Filter sowie Zertifikats- und
  Schlüsseldateinamen werden ersetzt.
- Kommentare, Zeitzone und Standortdaten bleiben standardmäßig erhalten, wobei IP-Adressen, Hostnamen und Objektnamen in
  Kommentaren ersetzt werden. `--remove comments,timezone,location` (in der Oberfläche: die „Entfernen“-Kontrollkästchen)
  löscht sie. Kommentare können Kundennamen enthalten; vor der Weitergabe entfernen.
- Zeichenketten in Policy-Ausdrücken werden durch `lit` ersetzt; `--keep-literals` behält sie, wobei Hosts, IPs und Namen
  weiterhin ersetzt werden.
- Dieselbe Eingabe ergibt über alle Dateien eines Laufs dasselbe Pseudonym, sodass HA-Paare und Double-Hop-Ketten verbunden
  bleiben.
- Eine Rückabbildung wird nur mit `--map-file` gespeichert; diese Datei ist so sensibel wie die Eingabe.

Das Werkzeug vergleicht die Zahl der Anweisungen vorher und nachher und listet mögliche Reste auf. Das Ergebnis vor der
Weitergabe manuell prüfen: Werte, die nur aus dem Zusammenhang erkennbar sind, etwa interne Namensschemata in Kommentaren,
können übersehen werden.

## Statistik ohne Inhalte
`python3 scripts/corpus_stats.py <Ordner>` erkennt doppelte Konfigurationen (gleicher Inhalt bis auf Kommentare, Leerzeilen,
Formatierung und Reihenfolge) und gibt nur Zahlen aus, ohne Dateinamen, Hostnamen, Werte oder Konfigurationszeilen. Auf dem
Rechner ausführen, auf dem die Daten liegen.

## Verknüpfungsdateien und DNS
Eine Verknüpfungsdatei (`nsviz-links.json`) und eine Hosts-Datei enthalten Objekt- und Hostnamen aus Kundenkonfigurationen;
privat halten (sie sind von git ausgeschlossen). `nsviz resolve` sendet die in den Konfigurationen gefundenen Hostnamen an einen
DNS-Server; es zeigt zuvor die Namen und den Server an und fragt nach. Es wird nichts automatisch abgefragt.

## Checkliste vor jedem Push
- [ ] `git status` zeigt keine Dateien aus `private/` und keine Exporte
- [ ] `python3 -m unittest discover -s tests` läuft durch (enthält den Hygiene-Test)
- [ ] die Änderungen enthalten keine echten Namen, Hostnamen, IP-Adressen, Hashes, Zertifikate oder Pfade
- [ ] die Git-Identität ist die vorgesehene
