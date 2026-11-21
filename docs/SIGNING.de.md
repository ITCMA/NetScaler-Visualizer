# Release-Signierung

🇬🇧 [English version](SIGNING.md)

Dieses Dokument beschreibt, wie die Release-Dateien signiert werden und was Anwender bei einer nicht signierten Datei
sehen. Es enthält keine Geheimnisse. Zertifikate, Kennwörter und Schlüssel gehören weder in das Repository noch in Logs
noch im Klartext in die CI-Konfiguration.

## Überblick
| Plattform | Status | Auswirkung für Anwender |
|---|---|---|
| Windows | Nicht codesigniert | SmartScreen zeigt beim ersten Start eine Warnung (siehe unten). |
| macOS | Mit Developer ID Application signiert und notarisiert, sofern die Release-Hinweise dies angeben | Keine Warnung. Ohne Notarisierung blockiert Gatekeeper den ersten Start. |

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

## macOS (Developer ID Application und Notarisierung)

### Voraussetzungen
- Mitgliedschaft im Apple Developer Program (Organisation).
- Ein Zertifikat vom Typ **Developer ID Application** im Anmeldeschlüsselbund des signierenden Macs. Der Account Holder
  erstellt es auf developer.apple.com unter *Certificates, Identifiers & Profiles* → *Certificates* → *+* →
  *Developer ID Application*, mit einer in der Schlüsselbundverwaltung erzeugten Zertifikatsanforderung.
  (Ein Zertifikat *Developer ID Installer* wird nur für `.pkg`-Installer benötigt.)
- Xcode Command Line Tools (`xcode-select --install`) für `codesign` und `xcrun notarytool`.

Zertifikat prüfen:
```bash
security find-identity -v -p codesigning
```
Die Ausgabe führt eine Identität wie `Developer ID Application: <Organisation> (<Team-ID>)` auf.

### 1. Binärdateien bauen
Der Release-Workflow erzeugt `nsviz-macos-arm64` und `nsviz-macos-x64` (PyInstaller, Einzeldatei). Laden Sie sie aus dem
Workflow-Lauf oder dem Release-Entwurf in einen leeren Ordner.

### 2. Signieren
Das Repository enthält `scripts/sign_macos.sh` und die Entitlements-Datei `scripts/entitlements.plist`. Eine
PyInstaller-Einzeldatei entpackt und lädt zur Laufzeit Code; die Hardened Runtime braucht daher zwei Entitlements
(`allow-unsigned-executable-memory`, `disable-library-validation`). Prüfen Sie beim ersten Lauf, ob beide nötig sind, und
entfernen Sie nicht benötigte.

```bash
export NSVIZ_SIGN_IDENTITY="Developer ID Application: <Organisation> (<Team-ID>)"
scripts/sign_macos.sh nsviz-macos-arm64
```
Das Skript führt im Kern aus:
```bash
codesign --force --timestamp --options runtime \
         --entitlements scripts/entitlements.plist \
         --sign "$NSVIZ_SIGN_IDENTITY" nsviz-macos-arm64
codesign --verify --strict --verbose=2 nsviz-macos-arm64
```

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

### 4. Notarisieren
`notarytool` akzeptiert `.zip`, `.dmg` und `.pkg`, keine einzelne Binärdatei. Packen Sie die signierte Datei mit `ditto`:
```bash
ditto -c -k --keepParent nsviz-macos-arm64 nsviz-macos-arm64.zip
xcrun notarytool submit nsviz-macos-arm64.zip --keychain-profile "nsviz-notary" --wait
```
Bei `Accepted` ist der Vorgang abgeschlossen. Bei `Invalid` lesen Sie das Protokoll:
```bash
xcrun notarytool log <Submission-ID> --keychain-profile "nsviz-notary"
```
Typische Ursachen sind ein fehlender sicherer Zeitstempel, eine fehlende Hardened Runtime oder eine unsignierte
eingebettete Binärdatei.

### 5. Heften und verteilen
Ein Ticket lässt sich an `.app`, `.dmg` und `.pkg` heften, nicht an eine einzelne Binärdatei. Eine notarisierte einzelne
Binärdatei startet trotzdem ohne Warnung, weil Gatekeeper das Notarisierungsticket online abruft; Rechner ohne
Netzverbindung zeigen die Warnung. Für den Offline-Einsatz liefern Sie ein `.dmg` aus und heften das Ticket:
```bash
hdiutil create -volname nsviz -srcfolder <Ordner mit der signierten Binärdatei> -ov -format UDZO nsviz.dmg
codesign --force --timestamp --sign "$NSVIZ_SIGN_IDENTITY" nsviz.dmg
xcrun notarytool submit nsviz.dmg --keychain-profile "nsviz-notary" --wait
xcrun stapler staple nsviz.dmg
```

### 6. Prüfen
```bash
spctl --assess --type execute --verbose nsviz-macos-arm64     # "accepted, source=Notarized Developer ID"
xcrun stapler validate nsviz.dmg
```
Testen Sie auf einem zweiten Mac, der die Datei noch nicht kennt, mit einer per Browser geladenen Datei, damit das
Quarantäne-Attribut gesetzt ist.

### 7. Veröffentlichen
Ersetzen Sie die unsignierten Dateien im Release-Entwurf durch die signierten, erzeugen Sie `SHA256SUMS.txt` neu
(`shasum -a 256 <Dateien> > SHA256SUMS.txt`) und vermerken Sie in den Release-Hinweisen, dass die macOS-Dateien signiert und
notarisiert sind.

### Signierung in der CI (optional)
Die Signierung in GitHub Actions braucht das Zertifikat als Base64-kodiertes `.p12`-Secret, einen temporären Schlüsselbund auf
dem Runner und die Zugangsdaten der Notarisierung als Secrets. Das ist optional und nicht Teil des aktuellen Workflows.
Wird es ergänzt, beschränken Sie die Secrets auf die Release-Umgebung und geben Sie sie nie in Logs aus.

## Hinweise
- Signaturidentität, Team-ID, Apple-ID und Schlüssel sind Organisationsdaten und bleiben außerhalb des Repositorys.
- Signieren und notarisieren Sie jedes Release neu; ein Notarisierungsticket ist an den exakten Dateiinhalt gebunden.
- Apple ändert Werkzeuge und Portalmenüs gelegentlich. Weicht ein Befehl oder Menü ab, folgen Sie der aktuellen
  Apple-Dokumentation „Notarizing macOS software before distribution“.
