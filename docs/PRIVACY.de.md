# Umgang mit Kundendaten (Datenschutzkonzept)

🇬🇧 [English version](PRIVACY.md)

Stand: Vorschlag, mit dem Projektinhaber abzustimmen. Keine Rechtsberatung (siehe [LEGAL.de.md](LEGAL.de.md)).

## Was ist sensibel
Eine `ns.conf` kann enthalten: interne IP-Adressen und Topologie, Host- und Domänennamen, Benutzer- und Admin-Namen, LDAP-Bind-DNs,
SNMP-Community-Strings, E-Mail-Adressen, Zertifikats-/Schlüsselnamen, verschlüsselte (aber angreifbare) Kennwort-/Schlüssel-Blobs und
Kommentare der Administratoren. Der erzeugte **Report** enthält Topologie und Config-Zeilen des Kunden.
Configs, Reports, CSV/JSON-Exporte und Screenshots wie Kundendaten behandeln.

## Grundsätze
1. **Lokal zuerst.** Das Werkzeug läuft lokal und sendet nichts. Kunden-Configs werden auf dem Rechner des Consultants analysiert.
2. **Kundendaten gelangen nie ins Repository** – weder in Code, Tests, Doku, Beispiele, Issues, Commit-Texte noch CI.
   Tests und Beispiele nutzen synthetische Daten (Dokumentationsbereiche `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`, `example.com`)
   oder öffentliche Beispiel-Configs, die bei Bedarf geladen werden.
3. **Eigener Ablageort außerhalb des Repositorys.** Kundenmaterial in einem Ordner *außerhalb* der Arbeitskopie halten
   (z. B. `~/nsviz-private/<projekt-id>/`, neutrale Projekt-IDs statt Kundennamen). Muss es in die Arbeitskopie, nur unter `private/` (git-ignoriert).
4. **Mehrere Schutzschichten gegen Versehen:**
   - `.gitignore` schließt `private/`, `customer*/`, `local/`, `anonymized/`, Reports, CSV-Exporte und Archive aus.
   - `scripts/hooks/pre-commit` (Installation: `sh scripts/install-hooks.sh`) blockiert gestagte Kundenpfade, lange Hex-Blobs,
     Private-Key-Header und absolute Benutzerpfade und führt die Tests aus.
   - Die Hygiene-Tests durchsuchen Code, Doku, Beispiele und Skripte nach Geheimnissen, E-Mail-Adressen, absoluten Pfaden und unzulässigen Verweisen.
   - GitHub *Secret scanning* und *Push protection* für das Repository aktivieren (Repository-Einstellungen; erfordert Owner-Rechte).
5. **Maskierung.** Reports maskieren Kennwörter und Schlüssel in den eingebetteten Config-Zeilen standardmäßig (Muster anhand bekannter
   Optionsnamen – keine Garantie). `--no-redact` nicht verwenden, wenn etwas den eigenen Rechner verlässt.
6. **Weitergabe eines Reports** an den Kunden ist eine Entscheidung je Projekt; vorher Vertrag/NDA prüfen. Den HTML-Report nur an den Kunden geben, dem die Daten gehören.
7. **Minimieren und löschen.** Nur aufbewahren, was das Projekt braucht; Configs und Reports nach Projektende löschen (Aufbewahrung mit dem Kunden vereinbaren).

## Kunden-Configs für die Entwicklung nutzen (z. B. um Regeln zu verbessern)
Nur nach **Anonymisierung** und nur mit Zustimmung des Kunden.

```bash
python3 -m nsviz anonymize ~/nsviz-private/configs -o ~/nsviz-private/anonymized
```
Was der Befehl tut (sicher als Standard – lieber zu viel anonymisieren als etwas durchlassen):
- alle Objektnamen (und jeder andere Wert, der kein Schlüsselwort, keine Zahl und keine Enum-Konstante ist) → konsistente Pseudonyme wie `lbvserver_0012`;
- IPv4-Adressen → synthetische `10.x.y.z`-Adressen; Hosts im selben /24 bleiben im selben /24 (Netzmasken und `0.0.0.0` bleiben); IPv6 → `2001:db8::N`;
  Hostnamen und E-Mail-Adressen → `hostN.example.com` / `userN@example.com`;
- Kennwörter, Schlüssel und lange Hex-Blobs entfernt; Kommentare, Beschreibungen, LDAP-DNs/-Filter, Zertifikats-/Schlüsseldateinamen ersetzt;
- Zeichenketten in Policy-Ausdrücken durch `lit` ersetzt (`--keep-literals` behält sie, Hosts/IPs/Namen werden trotzdem ersetzt);
- gleiche Eingabe ergibt über **alle Dateien eines Laufs** dasselbe Pseudonym, HA-Paare und Double-Hop-Ketten bleiben also verbunden;
- eine Rückabbildung wird nur mit `--map-file` gespeichert (diese Datei ist so sensibel wie die Eingabe).

Prüfungen: das Werkzeug vergleicht die Anzahl der Anweisungen vor/nach der Anonymisierung und meldet mögliche Reste (Originalstrings, die noch
vorkommen); auf dem öffentlichen Beispielkorpus bleibt die Zahl der Befunde innerhalb von ca. 3 % des Originals. **Ein Mensch muss das Ergebnis
trotzdem prüfen**, bevor es den privaten Ordner verlässt; automatische Anonymisierung kann Werte übersehen, die nur im Kontext erkennbar sind
(z. B. interne Namensschemata in Kommentaren, ungewöhnliche Optionsnamen). Auch dann bleibt das anonymisierte Ergebnis im privaten Ordner;
nur *abgeleitete, generische* Erkenntnisse (z. B. „Regel X erkennt Muster Y nicht“) kommen als neue synthetische Testfälle ins Repository.

## Dubletten und inhaltsfreie Statistik
`python3 scripts/corpus_stats.py <privater-Ordner>` erkennt doppelte Configs (gleicher Inhalt nach Entfernen von Kommentaren, Leerzeilen
und Formatierungsunterschieden; auch gleiche Zeilen in anderer Reihenfolge) und gibt **nur Zahlen** aus: keine Dateinamen, Hostnamen, Werte
oder Config-Zeilen. Jede eindeutige Config wird einmal verarbeitet. Auf dem Rechner ausführen, auf dem die Daten liegen; `--manifest`
nur verwenden, um die Liste der eindeutigen Dateien in eine lokale Datei zu schreiben.

## Checkliste vor jedem Push
- [ ] `git status` zeigt keine Dateien aus `private/` oder Exporte
- [ ] `python3 -m unittest discover -s tests` ist grün (enthält den Hygiene-Test)
- [ ] keine echten Namen, Hostnamen, IPs, Hashes, Zertifikate, Pfade im Diff
- [ ] Git-Identität ist die gewünschte
