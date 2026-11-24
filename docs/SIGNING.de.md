# Release-Signierung

🇬🇧 [English version](SIGNING.md)

Dieses Dokument beschreibt, wie die Release-Dateien signiert werden und was Anwender bei einer nicht signierten Datei
sehen. Es enthält keine Geheimnisse. Zertifikate, Kennwörter und Schlüssel gehören weder in das Repository noch in Logs
noch im Klartext in die CI-Konfiguration.

## Überblick
| Plattform | Status | Auswirkung für Anwender |
|---|---|---|
| Windows | Nicht codesigniert | SmartScreen zeigt beim ersten Start eine Warnung (siehe unten). |
| macOS | App (DMG, Kommandozeile enthalten), mit Developer ID Application signiert und notarisiert, sofern die Release-Hinweise dies angeben | Keine Warnung. Ohne Notarisierung blockiert Gatekeeper den ersten Start. |

Jedes Release führt die SHA-256-Prüfsummen in `SHA256SUMS.txt`. Vergleichen Sie die Prüfsumme vor dem ersten Start mit der
heruntergeladenen Datei.

## Windows (nicht signiert)
Ein Codesigning-Zertifikat für Windows verursacht laufende Kosten, und SmartScreen baut seine Reputation je Datei und
Herausgeber auf. Der Windows-Build wird deshalb unsigniert ausgeliefert.

Erster Start:
1. SmartScreen meldet „Der PC wurde durch Windows geschützt“.
2. Wählen Sie *Weitere Informationen* und danach *Trotzdem ausführen*.

In verwalteten Umgebungen kann die Datei in der Richtlinie zur Anwendungssteuerung (zum Beispiel AppLocker oder Windows
Defender Application Control) per Hash (SHA-256 aus `SHA256SUMS.txt`) zugelassen werden. Alternativ kann die Organisation die
Datei mit einem eigenen, internen Codesigning-Zertifikat signieren.

## Ganzes Release in einem geführten Befehl (macOS)
`scripts/release.sh` erledigt alles vom Tag bis zum veröffentlichten Release, auf dem Signier-Mac, auf `main`:
Prüfungen (sauberer Arbeitsstand, synchron mit origin, CHANGELOG-Abschnitt, CI grün, Tag frei) → Tag setzen und pushen →
Build abwarten → `publish_release.sh` (signieren, notarisieren, hochladen) → veröffentlichen → die vier Dateien prüfen.
`scripts/release.sh --dry-run` führt nur die Prüfungen aus und zeigt den Release-Text, der aus dem CHANGELOG-Abschnitt
entsteht.

Zwei Schritte fragen im Terminal nach und verlangen die Eingabe des Tag-Namens: das Setzen des Tags und das Veröffentlichen.
Ohne diese Eingabe wird nichts getaggt oder veröffentlicht. Nach einem Fehler setzt ein neuer Aufruf dort fort, wo der Lauf
stand (vorhandener Tag und Entwurf werden weiterverwendet). Die Version kommt aus `nsviz/__init__.py`; vor dem Start Version
erhöhen und CHANGELOG-Abschnitt füllen. Mit `NSVIZ_RELEASE_DIR` legst du einmal fest, wohin signierte Dateien und Logs
kommen (Standard `~/NetScaler-Visualizer-Release`).

## Kurzfassung (macOS, ein Lauf pro Architektur)
macOS-Nutzer erhalten pro Architektur einen Download: die **App** `nsviz-macos-<arch>.dmg`. `nsviz` nach *Programme*
ziehen; Doppelklick öffnet die lokale Oberfläche. Die Kommandozeile gehört zur App, mit dem Pfad
`/Applications/nsviz.app/Contents/MacOS/nsviz` (mit Argumenten verhält sie sich wie `python -m nsviz`); einen separaten
Kommandozeilen-Download gibt es nicht.

```bash
export NSVIZ_SIGN_IDENTITY="Developer ID Application: <Organisation> (<Team-ID>)"
scripts/release_macos.sh --arch arm64 --app ~/Downloads/nsviz-macos-arm64-app.zip
scripts/release_macos.sh --arch x64   --app ~/Downloads/nsviz-macos-x64-app.zip
```
Pro Architektur signiert das Skript das App-Bundle (zuerst jede eingebettete Datei, dann das Bundle; Hardened Runtime,
sicherer Zeitstempel), baut das DMG mit der App und einem *Programme*-Link, gibt dem DMG das App-Icon als Volume-Icon,
signiert das DMG, notarisiert es, heftet das Ticket und validiert. Beim ersten Fehler bricht es ab. `--dry-run` gibt nur
die Befehle aus, entpackt und prüft die Eingabe aber in einem temporären Ordner. `--app` nimmt das ZIP aus dem
Release-Workflow (auch wie von GitHub geladen, ein ZIP im ZIP) oder einen `nsviz.app`-Ordner. Weitere Optionen: `--out`
(Release-Ordner, Standard `$NSVIZ_RELEASE_DIR` oder `~/NetScaler-Visualizer-Release`; muss außerhalb des Repositorys
liegen) und `--profile` (Standard `nsviz-notary`, einmalig angelegt, Schritt 3).

Warum ein App-Bundle im DMG: Gatekeeper konnte die frühere DMG-Variante mit einer einzelnen Kommandozeilen-Binärdatei darin
nicht beurteilen (`spctl` meldete „invalid API object reference“). Ein App-Bundle ist die Form, die Gatekeeper für per
Doppelklick gestartete Programme erwartet. Ob das Bundle `spctl --assess --type execute` besteht, bestätigt der
Release-Lauf.

Wo die Dateien landen:
- Endprodukte direkt im Release-Ordner: `nsviz-macos-arm64.dmg`, `nsviz-macos-x64.dmg` und `SHA256SUMS.txt`.
- Zwischenstände in `<Release-Ordner>/work/<arch>/`; nach Erfolg gelöscht, bei Fehlern zur Analyse behalten.
- Danach: DMGs in den Release-Entwurf hochladen, die unsignierten macOS-Dateien ersetzen und die Prüfsummen
  zusammenführen (Schritt 7). Nichts aus dem Release-Ordner wird je committet.

## Automatische Freigabe (macOS, ein Befehl)
Wenn der Release-Workflow für einen gepushten Tag `vX.Y.Z` den Entwurf erstellt hat, erledigt ein Befehl auf dem
Signier-Mac alles Folgende ohne Parameter:

```bash
scripts/publish_release.sh --dry-run    # optional: nur prüfen und Plan anzeigen, ändert nichts
scripts/publish_release.sh              # der eine vorhandene Entwurf; oder: scripts/publish_release.sh v0.4.1
```
Er lädt die unsignierten App-ZIPs aus dem Entwurf, führt `release_macos.sh` für beide Architekturen aus, prüft die DMGs
erneut, führt `SHA256SUMS.txt` zusammen (die Windows-Zeile bleibt, die macOS-Zeilen werden ersetzt), lädt DMGs und
Prüfsummen in den Entwurf hoch, prüft den Upload und entfernt die unsignierten App-ZIPs aus dem Entwurf. **Er
veröffentlicht den Release nie.** Danach: Hinweis ergänzen, dass die macOS-Dateien signiert und notarisiert sind,
Release-Notes prüfen, von Hand veröffentlichen.

Automatisch gefunden werden: die Signaturidentität (die einzige *Developer ID Application*-Identität im Schlüsselbund;
bei mehreren `NSVIZ_SIGN_IDENTITY` setzen), das Notarisierungsprofil `nsviz-notary` (Schritt 3, wird zuerst geprüft)
und die GitHub-Anmeldung von `gh` (einmalig `gh auth login`). Netzwerkfehler werden wiederholt (Download, Upload,
Notarisierung); ein Notarisierungsergebnis *Invalid* nicht. Übrig gebliebene eingehängte Volumes werden beim Beenden
ausgehängt. Jeder Lauf beginnt sauber und ersetzt frühere Uploads; nach einem Fehler kann derselbe Befehl gefahrlos
erneut laufen.

Ordner: `<Release-Ordner>/<Tag>/` enthält die geladenen Eingaben, die signierten DMGs und die zusammengeführte
`SHA256SUMS.txt`; `<Release-Ordner>/logs/publish-<Zeit>.log` ist das Protokoll mit Zeitstempel zu jedem Schritt (es
werden nie Zugangsdaten geschrieben). Optionen: `--no-upload` (nur bauen und prüfen), `--out`, `--repo`, `--profile`.
Die manuellen Schritte unten bleiben die Referenz zur Fehlersuche.

Die Einzelschritte folgen unten. Sie beschreiben den gleichwertigen manuellen Weg, zum Beispiel zur Fehlersuche.

## macOS (Developer ID Application und Notarisierung)

### Voraussetzungen
- Mitgliedschaft im Apple Developer Program (Organisation).
- Ein Zertifikat vom Typ **Developer ID Application** im Anmeldeschlüsselbund des signierenden Macs. Der Account Holder
  erstellt es auf developer.apple.com unter *Certificates, Identifiers & Profiles* → *Certificates* → *+* →
  *Developer ID Application*, mit einer in der Schlüsselbundverwaltung erzeugten Zertifikatsanforderung.
- Xcode Command Line Tools (`xcode-select --install`) für `codesign` und `xcrun notarytool`.

Zertifikat prüfen:
```bash
security find-identity -v -p codesigning
```
Die Ausgabe führt eine Identität wie `Developer ID Application: <Organisation> (<Team-ID>)` auf.

### 1. App bauen
Der Release-Workflow erzeugt pro Architektur (arm64, x64) das App-Bundle als `nsviz-macos-<arch>-app.zip` (PyInstaller,
`scripts/build_app.py --bundle`; das ZIP enthält den Ordner `nsviz.app`). Laden Sie es aus dem Workflow-Lauf oder dem
Release-Entwurf in einen leeren Ordner.

### 2. Signieren
Das Repository enthält `scripts/sign_app_macos.sh` und die Entitlements-Datei `scripts/entitlements.plist`. Ein
PyInstaller-Programm entpackt und lädt zur Laufzeit Code, daher braucht die Hardened Runtime zwei Entitlements
(`allow-unsigned-executable-memory`, `disable-library-validation`). Prüfen Sie beim ersten Lauf, ob beide nötig sind, und
entfernen Sie nicht benötigte.

```bash
export NSVIZ_SIGN_IDENTITY="Developer ID Application: <Organisation> (<Team-ID>)"
ditto -x -k nsviz-macos-arm64-app.zip .          # entpackt nsviz.app
scripts/sign_app_macos.sh nsviz.app
```
Das Skript signiert jede eingebettete Mach-O-Datei (die tiefste zuerst)
```bash
codesign --force --timestamp --options runtime --sign "$NSVIZ_SIGN_IDENTITY" <Datei>
```
und danach das Bundle mit den Entitlements:
```bash
codesign --force --timestamp --options runtime \
         --entitlements scripts/entitlements.plist \
         --sign "$NSVIZ_SIGN_IDENTITY" nsviz.app
codesign --verify --deep --strict --verbose=2 nsviz.app
```
`codesign --deep` wird zum Signieren nicht verwendet.

### 3. Zugangsdaten für die Notarisierung hinterlegen (einmalig)
Die Notarisierung braucht eine Apple-ID mit einem **App-spezifischen Kennwort** oder einen **App Store Connect API-Schlüssel**.
Die Zugangsdaten werden unter einem Profilnamen im Schlüsselbund gespeichert; spätere Befehle nennen nur den Profilnamen.

Option A, App-spezifisches Kennwort (erstellt auf account.apple.com unter *Anmeldung und Sicherheit* →
*App-spezifische Kennwörter*):
```bash
xcrun notarytool store-credentials "nsviz-notary" \
      --apple-id "<Apple-ID>" --team-id "<Team-ID>"
```
Der Befehl fragt das Kennwort interaktiv ab. Übergeben Sie es nicht auf der Kommandozeile.

Option B, API-Schlüssel (erstellt in App Store Connect unter *Benutzer und Zugriff* → *Integrationen*; die `.p8`-Datei lässt
sich nur einmal laden):
```bash
xcrun notarytool store-credentials "nsviz-notary" \
      --key /pfad/zu/AuthKey_<Key-ID>.p8 --key-id "<Key-ID>" --issuer "<Issuer-ID>"
```
Legen Sie die Schlüsseldatei außerhalb des Repositorys ab.

### 4. DMG bauen und signieren
```bash
mkdir dmg && ditto nsviz.app dmg/nsviz.app && ln -s /Applications dmg/Applications
hdiutil create -volname nsviz -srcfolder dmg -ov -format UDZO nsviz-macos-arm64.dmg
codesign --force --timestamp --sign "$NSVIZ_SIGN_IDENTITY" nsviz-macos-arm64.dmg
```
Das Skript kopiert zusätzlich die Icon-Datei des Bundles als `.VolumeIcon.icns` in das Image und setzt am eingehängten
Volume das Flag für ein eigenes Icon (`SetFile -a C`), bevor das endgültige Image entsteht.

### 5. Notarisieren und heften
`notarytool` akzeptiert Disk-Images, ZIP-Archive und Installationspakete, keine einzelne Binärdatei:
```bash
xcrun notarytool submit nsviz-macos-arm64.dmg --keychain-profile "nsviz-notary" --wait
```
Bei `Accepted` heften Sie das Ticket, damit sich die App auch offline öffnen lässt:
```bash
xcrun stapler staple nsviz-macos-arm64.dmg
```
Bei `Invalid` lesen Sie das Protokoll:
```bash
xcrun notarytool log <Submission-ID> --keychain-profile "nsviz-notary"
```
Typische Ursachen sind ein fehlender sicherer Zeitstempel, eine fehlende Hardened Runtime oder eine unsignierte
eingebettete Datei.

### 6. Prüfen
```bash
xcrun stapler validate nsviz-macos-arm64.dmg
spctl --assess --type open --context context:primary-signature --verbose nsviz-macos-arm64.dmg   # accepted, Notarized Developer ID
spctl --assess --type execute --verbose nsviz.app                                                  # accepted, Notarized Developer ID
```
Testen Sie auf einem zweiten Mac, der die Datei noch nicht kennt, mit einer per Browser geladenen Datei, damit das
Quarantäne-Attribut gesetzt ist: DMG öffnen, `nsviz` nach *Programme* ziehen, starten; die Oberfläche öffnet sich ohne
Warnung im Browser. Die Kommandozeile: `/Applications/nsviz.app/Contents/MacOS/nsviz --version`.

### 7. Veröffentlichen
Ersetzen Sie die unsignierten macOS-Dateien im Release-Entwurf durch die signierten DMGs und vermerken Sie in den
Release-Hinweisen, dass die macOS-Dateien signiert und notarisiert sind.

Die `SHA256SUMS.txt` des Entwurfs erzeugt der Release-Workflow und enthält auch die Windows-Datei. Die `SHA256SUMS.txt` des
Skripts enthält nur die DMGs. Laden Sie sie nicht als Ersatz hoch. Laden Sie stattdessen die Datei des Entwurfs herunter,
lassen Sie die Windows-Zeile unverändert, ersetzen Sie die beiden macOS-Zeilen durch die Zeilen der DMGs aus dem
Release-Ordner und laden Sie die zusammengeführte Datei hoch.

### Signierung in der CI (optional)
Die Signierung in GitHub Actions braucht das Zertifikat als Base64-kodiertes `.p12`-Secret, einen temporären Schlüsselbund auf
dem Runner und die Zugangsdaten der Notarisierung als Secrets. Das ist optional und nicht Teil des aktuellen Workflows.
Wird es ergänzt, beschränken Sie die Secrets auf die Release-Umgebung und geben Sie sie nie in Logs aus.

## Hinweise
- Signaturidentität, Team-ID, Apple-ID und Schlüssel sind Organisationsdaten und bleiben außerhalb des Repositorys.
- Signieren und notarisieren Sie jedes Release neu; ein Notarisierungsticket ist an den exakten Dateiinhalt gebunden.
- Apple ändert Werkzeuge und Portalmenüs gelegentlich. Weicht ein Befehl oder Menü ab, folgen Sie der aktuellen
  Apple-Dokumentation „Notarizing macOS software before distribution“.
