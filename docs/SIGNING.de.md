# Release-Signierung

🇬🇧 [English version](SIGNING.md)

Dieses Dokument beschreibt, wie die Release-Dateien signiert werden und was Anwender bei einer nicht signierten Datei
sehen. Es enthält keine Geheimnisse. Zertifikate, Kennwörter und Schlüssel gehören weder in das Repository noch in Logs
noch im Klartext in die CI-Konfiguration.

## Überblick
| Plattform | Status | Auswirkung für Anwender |
|---|---|---|
| Windows | Nicht codesigniert | SmartScreen zeigt beim ersten Start eine Warnung (siehe unten). |
| macOS | App (DMG) und Kommandozeilen-Binärdatei (ZIP), mit Developer ID Application signiert und notarisiert, sofern die Release-Hinweise dies angeben | Keine Warnung. Ohne Notarisierung blockiert Gatekeeper den ersten Start. |

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

## Kurzfassung (macOS, ein Lauf pro Architektur)
macOS-Nutzer erhalten zwei Downloads: die **App** `nsviz-macos-<arch>.dmg` (`nsviz` nach *Programme* ziehen, Doppelklick
öffnet die lokale Oberfläche) und die **Kommandozeilen-Binärdatei** `nsviz-macos-<arch>-cli.zip` (Datei `nsviz`, für
Terminal und Skripte).

```bash
export NSVIZ_SIGN_IDENTITY="Developer ID Application: <Organisation> (<Team-ID>)"
scripts/release_macos.sh --arch arm64 --app ~/Downloads/nsviz-macos-arm64-app.zip --binary ~/Downloads/nsviz-macos-arm64
scripts/release_macos.sh --arch x64   --app ~/Downloads/nsviz-macos-x64-app.zip   --binary ~/Downloads/nsviz-macos-x64
```
Pro Architektur
- signiert das Skript das App-Bundle (zuerst jede eingebettete Datei, dann das Bundle; Hardened Runtime, sicherer
  Zeitstempel), baut das DMG mit der App und einem *Programme*-Link, signiert das DMG, notarisiert es, heftet das Ticket und
  validiert;
- signiert es die Kommandozeilen-Binärdatei, packt sie in ein ZIP und notarisiert das ZIP. Ein ZIP lässt sich nicht
  heften, Gatekeeper prüft das Ticket für diese Datei daher online.

Das Skript bricht beim ersten Fehler ab. `--dry-run` gibt nur die Befehle aus. `--app` und `--binary` lassen sich auch
einzeln verwenden. Weitere Optionen: `--out` (Release-Ordner, Standard `$NSVIZ_RELEASE_DIR` oder
`~/NetScaler-Visualizer-Release`; muss außerhalb des Repositorys liegen) und `--profile` (Standard `nsviz-notary`,
einmalig angelegt, Schritt 3).

Warum ein App-Bundle im DMG: Gatekeeper konnte die frühere DMG-Variante mit einer einzelnen Kommandozeilen-Binärdatei darin
nicht beurteilen (`spctl` meldete „invalid API object reference“). Ein App-Bundle ist die Form, die Gatekeeper für per
Doppelklick gestartete Programme erwartet. Ob das Bundle `spctl --assess --type execute` besteht, ist durch den ersten
Release-Lauf zu bestätigen.

Wo die Dateien landen:
- Endprodukte direkt im Release-Ordner: `nsviz-macos-arm64.dmg`, `nsviz-macos-x64.dmg`, `nsviz-macos-arm64-cli.zip`,
  `nsviz-macos-x64-cli.zip` und `SHA256SUMS.txt`.
- Zwischenstände in `<Release-Ordner>/work/<arch>/`; nach Erfolg gelöscht, bei Fehlern zur Analyse behalten.
- Danach: DMGs und CLI-ZIPs in den Release-Entwurf hochladen, die unsignierten macOS-Dateien ersetzen und die
  Prüfsummen zusammenführen (Schritt 7). Nichts aus dem Release-Ordner wird je committet.

Die Einzelschritte folgen unten. Sie beschreiben den gleichwertigen manuellen Weg, zum Beispiel zur Fehlersuche.

## macOS (Developer ID Application und Notarisierung)

### Voraussetzungen
- Mitgliedschaft im Apple Developer Program (Organisation).
- Ein Zertifikat vom Typ **Developer ID Application** im Anmeldeschlüsselbund des signierenden Macs. Der Account Holder
  erstellt es auf developer.apple.com unter *Certificates, Identifiers & Profiles* → *Certificates* → *+* →
  *Developer ID Application*, mit einer in der Schlüsselbundverwaltung erzeugten Zertifikatsanforderung.
- Ein Zertifikat *Developer ID Installer* wird nicht benötigt: nsviz wird als App im DMG und als ZIP ausgeliefert, nicht als
  `.pkg`-Installer.
- Xcode Command Line Tools (`xcode-select --install`) für `codesign` und `xcrun notarytool`.

Zertifikat prüfen:
```bash
security find-identity -v -p codesigning
```
Die Ausgabe führt eine Identität wie `Developer ID Application: <Organisation> (<Team-ID>)` auf.

### 1. App und Binärdatei bauen
Der Release-Workflow erzeugt pro Architektur (arm64, x64) die Kommandozeilen-Binärdatei `nsviz-macos-<arch>` als Einzeldatei
und das App-Bundle als `nsviz-macos-<arch>-app.zip` (PyInstaller; das Bundle entsteht mit
`scripts/build_app.py --bundle` und enthält den Ordner `nsviz.app`). Laden Sie sie aus dem Workflow-Lauf oder dem
Release-Entwurf in einen leeren Ordner.

### 2. Signieren
Das Repository enthält `scripts/sign_macos.sh` (Einzeldatei), `scripts/sign_app_macos.sh` (App-Bundle) und die
Entitlements-Datei `scripts/entitlements.plist`. Ein PyInstaller-Programm entpackt und lädt zur Laufzeit Code, daher braucht
die Hardened Runtime zwei Entitlements (`allow-unsigned-executable-memory`, `disable-library-validation`). Prüfen Sie beim
ersten Lauf, ob beide nötig sind, und entfernen Sie nicht benötigte.

```bash
export NSVIZ_SIGN_IDENTITY="Developer ID Application: <Organisation> (<Team-ID>)"
ditto -x -k nsviz-macos-arm64-app.zip .          # entpackt nsviz.app
scripts/sign_app_macos.sh nsviz.app              # App-Bundle
scripts/sign_macos.sh nsviz-macos-arm64          # Kommandozeilen-Binärdatei
```
Die Binärdatei wird im Kern so signiert:
```bash
codesign --force --timestamp --options runtime \
         --entitlements scripts/entitlements.plist \
         --sign "$NSVIZ_SIGN_IDENTITY" nsviz-macos-arm64
codesign --verify --strict --verbose=2 nsviz-macos-arm64
```
Beim Bundle signiert `sign_app_macos.sh` jede eingebettete Mach-O-Datei auf dieselbe Weise (ohne Entitlements), die tiefste
zuerst, und zuletzt das Bundle mit den Entitlements. `codesign --deep` wird nicht verwendet. Am Ende läuft
`codesign --verify --deep --strict` über das Bundle.

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
Die Kommandozeilen-Binärdatei packen Sie in ein ZIP (nur die Datei `nsviz`):
```bash
ditto -c -k nsviz-macos-arm64 nsviz-macos-arm64-cli.zip     # Name im ZIP: nsviz (Datei vorher umbenennen)
```

### 5. Notarisieren und heften
`notarytool` akzeptiert `.dmg`, `.zip` und `.pkg`, keine einzelne Binärdatei:
```bash
xcrun notarytool submit nsviz-macos-arm64.dmg --keychain-profile "nsviz-notary" --wait
xcrun notarytool submit nsviz-macos-arm64-cli.zip --keychain-profile "nsviz-notary" --wait
```
Bei `Accepted` für das DMG heften Sie das Ticket, damit sich die App auch offline öffnen lässt. Ein ZIP lässt sich nicht
heften:
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
Warnung im Browser. Das ZIP entpacken Sie und starten im Terminal `./nsviz --version`.

### 7. Veröffentlichen
Ersetzen Sie die unsignierten macOS-Dateien im Release-Entwurf durch die signierten DMGs und CLI-ZIPs und vermerken Sie in den
Release-Hinweisen, dass die macOS-Dateien signiert und notarisiert sind.

Die `SHA256SUMS.txt` des Entwurfs erzeugt der Release-Workflow und enthält auch die Windows-Datei. Die `SHA256SUMS.txt` des
Skripts enthält nur die DMGs und ZIPs. Laden Sie sie nicht als Ersatz hoch. Laden Sie stattdessen die Datei des Entwurfs herunter,
lassen Sie die Windows-Zeile unverändert, ersetzen Sie die beiden macOS-Zeilen durch die Zeilen der DMGs und ZIPs aus dem
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
