# Release signing

🇩🇪 [Deutsche Version](SIGNING.de.md)

This document describes how the release files are signed and what users see when a file is not signed.
It contains no secrets. Certificates, passwords and keys never belong in the repository, in logs or in the CI configuration
as plain text.

## Overview
| Platform | Status | Effect for users |
|---|---|---|
| Windows | Not code-signed | SmartScreen shows a warning on first start (see below). |
| macOS | App (DMG) and command-line binary (ZIP), signed with Developer ID Application and notarized, when the release notes say so | No warning. Without notarization Gatekeeper blocks the first start. |

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
macOS users get two downloads: the **app** `nsviz-macos-<arch>.dmg` (drag `nsviz` to *Applications*, double-click opens the
local GUI) and the **command-line binary** `nsviz-macos-<arch>-cli.zip` (file `nsviz`, for terminal and scripts).

```bash
export NSVIZ_SIGN_IDENTITY="Developer ID Application: <organization> (<team ID>)"
scripts/release_macos.sh --arch arm64 --app ~/Downloads/nsviz-macos-arm64-app.zip --binary ~/Downloads/nsviz-macos-arm64
scripts/release_macos.sh --arch x64   --app ~/Downloads/nsviz-macos-x64-app.zip   --binary ~/Downloads/nsviz-macos-x64
```
Per architecture the script
- signs the app bundle (every nested file first, then the bundle; hardened runtime, secure timestamp), builds the DMG with
  the app and an *Applications* link, signs the DMG, notarizes it, staples the ticket and validates;
- signs the command-line binary, packs it into a ZIP and notarizes the ZIP. A ZIP cannot be stapled, so Gatekeeper checks
  the ticket online for this file.

The script stops on the first error. `--dry-run` only prints the commands. `--app` and `--binary` can also be used
alone. Other options: `--out` (release folder, default `$NSVIZ_RELEASE_DIR` or `~/NetScaler-Visualizer-Release`; must be
outside the repository) and `--profile` (default `nsviz-notary`, created once, step 3).

Why an app bundle in a DMG: Gatekeeper could not assess the earlier DMG variant with a bare command-line binary inside
(`spctl` answered "invalid API object reference"). An app bundle is the form Gatekeeper expects for programs started by
double-click. Whether the bundle passes `spctl --assess --type execute` is to be confirmed by the first release run.

Where files end up:
- Final products, directly in the release folder: `nsviz-macos-arm64.dmg`, `nsviz-macos-x64.dmg`,
  `nsviz-macos-arm64-cli.zip`, `nsviz-macos-x64-cli.zip` and `SHA256SUMS.txt`.
- Intermediate files in `<release folder>/work/<arch>/`; deleted after success, kept on failure.
- Next: upload the DMGs and CLI ZIPs to the release draft, replacing the unsigned macOS files, and merge the checksums
  (step 7). Nothing from the release folder is ever committed.

The individual steps follow below. They describe the equivalent manual way, for example for troubleshooting.

## macOS (Developer ID Application and notarization)

### Prerequisites
- Membership in the Apple Developer Program (organization).
- A certificate of type **Developer ID Application** in the login keychain of the signing Mac. The Account Holder
  creates it at developer.apple.com under *Certificates, Identifiers & Profiles* → *Certificates* → *+* →
  *Developer ID Application*, using a certificate signing request created with Keychain Access.
- A *Developer ID Installer* certificate is not needed: nsviz is delivered as an app in a DMG and as a ZIP, not as a
  `.pkg` installer.
- Xcode command line tools (`xcode-select --install`) for `codesign` and `xcrun notarytool`.

Check the certificate:
```bash
security find-identity -v -p codesigning
```
The output lists an identity such as `Developer ID Application: <organization> (<team ID>)`.

### 1. Build the app and the binary
The release workflow produces, per architecture (arm64, x64), the single-file command-line binary `nsviz-macos-<arch>` and
the app bundle as `nsviz-macos-<arch>-app.zip` (PyInstaller; the bundle is built with `scripts/build_app.py --bundle` and
contains the `nsviz.app` folder). Download them from the workflow run or the draft release into an empty folder.

### 2. Sign
The repository contains `scripts/sign_macos.sh` (single file), `scripts/sign_app_macos.sh` (app bundle) and the
entitlements file `scripts/entitlements.plist`. A PyInstaller program unpacks and loads code at runtime, so the hardened
runtime needs two entitlements (`allow-unsigned-executable-memory`, `disable-library-validation`). Check on the first run
whether both are required and remove any that are not.

```bash
export NSVIZ_SIGN_IDENTITY="Developer ID Application: <organization> (<team ID>)"
ditto -x -k nsviz-macos-arm64-app.zip .          # unpacks nsviz.app
scripts/sign_app_macos.sh nsviz.app              # app bundle
scripts/sign_macos.sh nsviz-macos-arm64          # command-line binary
```
The binary is signed in essence like this:
```bash
codesign --force --timestamp --options runtime \
         --entitlements scripts/entitlements.plist \
         --sign "$NSVIZ_SIGN_IDENTITY" nsviz-macos-arm64
codesign --verify --strict --verbose=2 nsviz-macos-arm64
```
For the bundle, `sign_app_macos.sh` signs every nested Mach-O file the same way (without entitlements), deepest first, and
then the bundle with the entitlements. `codesign --deep` is not used. Finally it runs
`codesign --verify --deep --strict` on the bundle.

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
For the command-line binary, pack it into a ZIP (only the file `nsviz`):
```bash
ditto -c -k nsviz-macos-arm64 nsviz-macos-arm64-cli.zip     # name inside the ZIP: nsviz (rename the file first)
```

### 5. Notarize and staple
`notarytool` accepts `.dmg`, `.zip` and `.pkg`, not a bare binary:
```bash
xcrun notarytool submit nsviz-macos-arm64.dmg --keychain-profile "nsviz-notary" --wait
xcrun notarytool submit nsviz-macos-arm64-cli.zip --keychain-profile "nsviz-notary" --wait
```
On `Accepted` for the DMG, staple the ticket, so that the app also opens offline. A ZIP cannot be stapled:
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
For the ZIP, unpack it and run `./nsviz --version` in the terminal.

### 7. Publish
Replace the unsigned macOS files in the draft release with the signed DMGs and CLI ZIPs and state in the release notes that the macOS
files are signed and notarized.

The draft's `SHA256SUMS.txt` is generated by the release workflow and also contains the Windows file. The script's
`SHA256SUMS.txt` covers only the DMGs and ZIPs. Do not upload it as a replacement. Download the draft's file, keep the Windows line
unchanged, replace the two macOS lines with the lines of the DMGs and ZIPs from the release folder and upload the merged file.

### Signing in CI (optional)
Signing in GitHub Actions needs the certificate as a base64-encoded `.p12` secret, a temporary keychain on the runner and
the notarization credentials as secrets. This is optional and not part of the current workflow. If it is added, restrict
the secrets to the release environment, and never print them in logs.

## Notes
- The signing identity, team ID, Apple ID and keys are organization data and stay out of the repository.
- Re-sign and re-notarize every release; a notarization ticket is bound to the exact file content.
- Apple changes the tools and portal menus from time to time. If a command or menu differs, follow the current
  Apple documentation on "Notarizing macOS software before distribution".
