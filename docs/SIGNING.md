# Release signing

🇩🇪 [Deutsche Version](SIGNING.de.md)

This document describes how the release files are signed and what users see when a file is not signed.
It contains no secrets. Certificates, passwords and keys never belong in the repository, in logs or in the CI configuration
as plain text.

## Overview
| Platform | Status | Effect for users |
|---|---|---|
| Windows | Not code-signed | SmartScreen shows a warning on first start (see below). |
| macOS | App (DMG, command line included), signed with Developer ID Application and notarized, when the release notes say so | No warning. Without notarization Gatekeeper blocks the first start. |

Each release lists the SHA-256 checksums in `SHA256SUMS.txt`. Compare the checksum with the downloaded file before the
first start.

## Windows (not signed)
A code-signing certificate for Windows is a recurring cost, and SmartScreen builds its reputation per file and publisher.
The Windows build is therefore delivered unsigned.

First start:
1. SmartScreen displays "Windows protected your PC".
2. Select *More info*, then *Run anyway*.

In managed environments the file can be allowed by hash (SHA-256 from `SHA256SUMS.txt`) in the application control
policy, for example AppLocker or Windows Defender Application Control. Alternatively, the organization can sign the file
with its own internal code-signing certificate.

## Quick reference (macOS, one run per architecture)
macOS users get one download per architecture: the **app** `nsviz-macos-<arch>.dmg`. Drag `nsviz` to *Applications*;
double-click opens the local GUI. The command line is part of the app, with the path
`/Applications/nsviz.app/Contents/MacOS/nsviz` (with arguments it behaves like `python -m nsviz`); there is no separate
command-line download.

```bash
export NSVIZ_SIGN_IDENTITY="Developer ID Application: <organization> (<team ID>)"
scripts/release_macos.sh --arch arm64 --app ~/Downloads/nsviz-macos-arm64-app.zip
scripts/release_macos.sh --arch x64   --app ~/Downloads/nsviz-macos-x64-app.zip
```
Per architecture the script signs the app bundle (every nested file first, then the bundle; hardened runtime, secure
timestamp), builds the DMG with the app and an *Applications* link, gives the DMG the app icon as volume icon, signs the
DMG, notarizes it, staples the ticket and validates. It stops on the first error. `--dry-run` only prints the commands,
but unpacks and checks the input in a temporary folder. `--app` takes the ZIP from the release workflow (also as downloaded
from GitHub, a ZIP inside a ZIP) or an `nsviz.app` folder. Other options: `--out` (release folder, default
`$NSVIZ_RELEASE_DIR` or `~/NetScaler-Visualizer-Release`; must be outside the repository) and `--profile` (default
`nsviz-notary`, created once, step 3).

Why an app bundle in a DMG: Gatekeeper could not assess the earlier DMG variant with a bare command-line binary inside
(`spctl` answered "invalid API object reference"). An app bundle is the form Gatekeeper expects for programs started by
double-click. Whether the bundle passes `spctl --assess --type execute` is confirmed by the release run.

Where files end up:
- Final products, directly in the release folder: `nsviz-macos-arm64.dmg`, `nsviz-macos-x64.dmg` and `SHA256SUMS.txt`.
- Intermediate files in `<release folder>/work/<arch>/`; deleted after success, kept on failure.
- Next: upload the DMGs to the release draft, replacing the unsigned macOS files, and merge the checksums (step 7).
  Nothing from the release folder is ever committed.

## Automatic release (macOS, one command)
After the release workflow has created the draft for a pushed tag `vX.Y.Z`, one command on the signing Mac does everything
below without parameters:

```bash
scripts/publish_release.sh --dry-run    # optional: read-only checks and plan, changes nothing
scripts/publish_release.sh              # the one existing draft; or: scripts/publish_release.sh v0.4.1
```
It downloads the unsigned app ZIPs from the draft, runs `release_macos.sh` for both architectures, re-verifies the DMGs,
merges `SHA256SUMS.txt` (the Windows line stays, the macOS lines are replaced), uploads the DMGs and the checksums to the
draft, verifies the uploads and removes the unsigned app ZIPs from the draft. **It never publishes the release.**
Afterwards: add the note that the macOS files are signed and notarized, review the release notes, publish by hand.

Found automatically: the signing identity (the only *Developer ID Application* identity in the keychain; with several,
set `NSVIZ_SIGN_IDENTITY`), the notary profile `nsviz-notary` (step 3, checked first), and the GitHub login of `gh`
(`gh auth login` once). Network errors are retried (downloads, uploads, notarization); a notarization verdict of
*Invalid* is not. Leftover mounted volumes are detached on exit. Every run starts clean and replaces earlier uploads, so
after an error it is safe to run the same command again.

Folders: `<release folder>/<tag>/` holds the downloaded input, the signed DMGs and the merged `SHA256SUMS.txt`;
`<release folder>/logs/publish-<time>.log` is the timestamped log of every step (no credentials are ever written).
Options: `--no-upload` (build and verify only), `--out`, `--repo`, `--profile`. The manual steps below remain the reference
for troubleshooting.

The individual steps follow below. They describe the equivalent manual way, for example for troubleshooting.

## macOS (Developer ID Application and notarization)

### Prerequisites
- Membership in the Apple Developer Program (organization).
- A certificate of type **Developer ID Application** in the login keychain of the signing Mac. The Account Holder
  creates it at developer.apple.com under *Certificates, Identifiers & Profiles* → *Certificates* → *+* →
  *Developer ID Application*, using a certificate signing request created with Keychain Access.
- Xcode command line tools (`xcode-select --install`) for `codesign` and `xcrun notarytool`.

Check the certificate:
```bash
security find-identity -v -p codesigning
```
The output lists an identity such as `Developer ID Application: <organization> (<team ID>)`.

### 1. Build the app
The release workflow produces, per architecture (arm64, x64), the app bundle as `nsviz-macos-<arch>-app.zip` (PyInstaller,
`scripts/build_app.py --bundle`; the ZIP contains the folder `nsviz.app`). Download it from the workflow run or the draft
release into an empty folder.

### 2. Sign
The repository contains `scripts/sign_app_macos.sh` and the entitlements file `scripts/entitlements.plist`. A PyInstaller
program unpacks and loads code at runtime, so the hardened runtime needs two entitlements
(`allow-unsigned-executable-memory`, `disable-library-validation`). Check on the first run whether both are required and
remove any that are not.

```bash
export NSVIZ_SIGN_IDENTITY="Developer ID Application: <organization> (<team ID>)"
ditto -x -k nsviz-macos-arm64-app.zip .          # unpacks nsviz.app
scripts/sign_app_macos.sh nsviz.app
```
The script signs every nested Mach-O file (deepest first)
```bash
codesign --force --timestamp --options runtime --sign "$NSVIZ_SIGN_IDENTITY" <file>
```
and then the bundle with the entitlements:
```bash
codesign --force --timestamp --options runtime \
         --entitlements scripts/entitlements.plist \
         --sign "$NSVIZ_SIGN_IDENTITY" nsviz.app
codesign --verify --deep --strict --verbose=2 nsviz.app
```
`codesign --deep` is not used for signing.

### 3. Store notarization credentials (once)
Notarization needs an Apple ID with an **app-specific password** or an **App Store Connect API key**. The credentials are
stored in the keychain under a profile name; later commands use only the profile name.

Option A, app-specific password (created at account.apple.com under *Sign-In and Security* → *App-Specific Passwords*):
```bash
xcrun notarytool store-credentials "nsviz-notary" \
      --apple-id "<Apple ID>" --team-id "<team ID>"
```
The command asks for the password interactively. Do not pass it on the command line.

Option B, API key (created in App Store Connect under *Users and Access* → *Integrations*; the `.p8` file is downloadable
only once):
```bash
xcrun notarytool store-credentials "nsviz-notary" \
      --key /path/to/AuthKey_<key ID>.p8 --key-id "<key ID>" --issuer "<issuer ID>"
```
Store the key file outside the repository.

### 4. Build and sign the DMG
```bash
mkdir dmg && ditto nsviz.app dmg/nsviz.app && ln -s /Applications dmg/Applications
hdiutil create -volname nsviz -srcfolder dmg -ov -format UDZO nsviz-macos-arm64.dmg
codesign --force --timestamp --sign "$NSVIZ_SIGN_IDENTITY" nsviz-macos-arm64.dmg
```
The script additionally copies the icon file of the bundle into the image as `.VolumeIcon.icns` and sets the
custom-icon flag (`SetFile -a C`) on the mounted volume before the final image is created.

### 5. Notarize and staple
`notarytool` accepts disk images, ZIP archives and installer packages, not a bare binary:
```bash
xcrun notarytool submit nsviz-macos-arm64.dmg --keychain-profile "nsviz-notary" --wait
```
On `Accepted`, staple the ticket, so that the app also opens offline:
```bash
xcrun stapler staple nsviz-macos-arm64.dmg
```
On `Invalid`, read the log:
```bash
xcrun notarytool log <submission ID> --keychain-profile "nsviz-notary"
```
Typical causes are a missing secure timestamp, a missing hardened runtime or an unsigned embedded file.

### 6. Verify
```bash
xcrun stapler validate nsviz-macos-arm64.dmg
spctl --assess --type open --context context:primary-signature --verbose nsviz-macos-arm64.dmg   # accepted, Notarized Developer ID
spctl --assess --type execute --verbose nsviz.app                                                  # accepted, Notarized Developer ID
```
Test on a second Mac that has not seen the file before, with the file downloaded through a browser, so that the quarantine
attribute is set: open the DMG, drag `nsviz` to *Applications*, start it; the GUI opens in the browser without a warning.
The command line: `/Applications/nsviz.app/Contents/MacOS/nsviz --version`.

### 7. Publish
Replace the unsigned macOS files in the draft release with the signed DMGs and state in the release notes that the macOS
files are signed and notarized.

The draft's `SHA256SUMS.txt` is generated by the release workflow and also contains the Windows file. The script's
`SHA256SUMS.txt` covers only the DMGs. Do not upload it as a replacement. Download the draft's file, keep the Windows line
unchanged, replace the two macOS lines with the lines of the DMGs from the release folder and upload the merged file.

### Signing in CI (optional)
Signing in GitHub Actions needs the certificate as a base64-encoded `.p12` secret, a temporary keychain on the runner and
the notarization credentials as secrets. This is optional and not part of the current workflow. If it is added, restrict
the secrets to the release environment, and never print them in logs.

## Notes
- The signing identity, team ID, Apple ID and keys are organization data and stay out of the repository.
- Re-sign and re-notarize every release; a notarization ticket is bound to the exact file content.
- Apple changes the tools and portal menus from time to time. If a command or menu differs, follow the current
  Apple documentation on "Notarizing macOS software before distribution".
