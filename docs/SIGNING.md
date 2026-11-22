# Release signing

🇩🇪 [Deutsche Version](SIGNING.de.md)

This document describes how the release files are signed and what users see when a file is not signed.
It contains no secrets. Certificates, passwords and keys never belong in the repository, in logs or in the CI configuration
as plain text.

## Overview
| Platform | Status | Effect for users |
|---|---|---|
| Windows | Not code-signed | SmartScreen shows a warning on first start (see below). |
| macOS | Signed with Developer ID Application and notarized, when the release notes say so | No warning. Without notarization Gatekeeper blocks the first start. |

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
```bash
export NSVIZ_SIGN_IDENTITY="Developer ID Application: <organization> (<team ID>)"
scripts/release_macos.sh --arch arm64 --binary ~/Downloads/nsviz-macos-arm64
scripts/release_macos.sh --arch x64   --binary ~/Downloads/nsviz-macos-x64
```
The script checks the binary, signs it, builds `nsviz-macos-<arch>.dmg`, signs the DMG, notarizes, staples and
validates, and stops on the first error. `--dry-run` only prints the commands. Options: `--out` (release folder, default
`$NSVIZ_RELEASE_DIR` or `~/NetScaler-Visualizer-Release`; must be outside the repository) and `--profile` (default
`nsviz-notary`, created once, step 3).

Where files end up:
- Final products, directly in the release folder: `nsviz-macos-arm64.dmg`, `nsviz-macos-x64.dmg` and `SHA256SUMS.txt`.
- Intermediate files in `<release folder>/work/<arch>/`; deleted after success, kept on failure.
- Next: upload the DMGs and `SHA256SUMS.txt` to the release draft, replacing the unsigned macOS files (step 7).
  Nothing from the release folder is ever committed.

The individual steps the script performs follow below.

## macOS (Developer ID Application and notarization)

### Prerequisites
- Membership in the Apple Developer Program (organization).
- A certificate of type **Developer ID Application** in the login keychain of the signing Mac. The Account Holder
  creates it at developer.apple.com under *Certificates, Identifiers & Profiles* → *Certificates* → *+* →
  *Developer ID Application*, using a certificate signing request created with Keychain Access.
  (A *Developer ID Installer* certificate is needed only for `.pkg` installers.)
- Xcode command line tools (`xcode-select --install`) for `codesign` and `xcrun notarytool`.

Check the certificate:
```bash
security find-identity -v -p codesigning
```
The output lists an identity such as `Developer ID Application: <organization> (<team ID>)`.

### 1. Build the binaries
The release workflow produces `nsviz-macos-arm64` and `nsviz-macos-x64` (PyInstaller, single file). Download them from the
workflow run or the draft release into an empty folder.

### 2. Sign
The repository contains `scripts/sign_macos.sh` and the entitlements file `scripts/entitlements.plist`. A single-file
PyInstaller binary unpacks and loads code at runtime, so the hardened runtime needs two entitlements
(`allow-unsigned-executable-memory`, `disable-library-validation`). Check on the first run whether both are required and
remove any that are not.

```bash
export NSVIZ_SIGN_IDENTITY="Developer ID Application: <organization> (<team ID>)"
scripts/sign_macos.sh nsviz-macos-arm64
```
The script runs, in essence:
```bash
codesign --force --timestamp --options runtime \
         --entitlements scripts/entitlements.plist \
         --sign "$NSVIZ_SIGN_IDENTITY" nsviz-macos-arm64
codesign --verify --strict --verbose=2 nsviz-macos-arm64
```

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

### 4. Notarize
`notarytool` accepts `.zip`, `.dmg` and `.pkg`, not a bare binary. Pack the signed file with `ditto`:
```bash
ditto -c -k --keepParent nsviz-macos-arm64 nsviz-macos-arm64.zip
xcrun notarytool submit nsviz-macos-arm64.zip --keychain-profile "nsviz-notary" --wait
```
On `Accepted` the process is complete. On `Invalid`, read the log:
```bash
xcrun notarytool log <submission ID> --keychain-profile "nsviz-notary"
```
Typical causes are a missing secure timestamp, a missing hardened runtime or an unsigned embedded binary.

### 5. Staple and distribute
A ticket can be stapled to `.app`, `.dmg` and `.pkg`, but not to a bare binary. A notarized bare binary still starts
without a warning, because Gatekeeper retrieves the notarization ticket online; offline machines show the warning.
For offline use, deliver a `.dmg` and staple it:
```bash
hdiutil create -volname nsviz -srcfolder <folder with the signed binary> -ov -format UDZO nsviz.dmg
codesign --force --timestamp --sign "$NSVIZ_SIGN_IDENTITY" nsviz.dmg
xcrun notarytool submit nsviz.dmg --keychain-profile "nsviz-notary" --wait
xcrun stapler staple nsviz.dmg
```

### 6. Verify
```bash
spctl --assess --type execute --verbose nsviz-macos-arm64     # "accepted, source=Notarized Developer ID"
xcrun stapler validate nsviz.dmg
```
Test on a second Mac that has not seen the file before, with the file downloaded through a browser, so that the quarantine
attribute is set.

### 7. Publish
Replace the unsigned files in the draft release with the signed ones, regenerate `SHA256SUMS.txt`
(`shasum -a 256 <files> > SHA256SUMS.txt`) and state in the release notes that the macOS files are signed and notarized.

### Signing in CI (optional)
Signing in GitHub Actions needs the certificate as a base64-encoded `.p12` secret, a temporary keychain on the runner and
the notarization credentials as secrets. This is optional and not part of the current workflow. If it is added, restrict
the secrets to the release environment, and never print them in logs.

## Notes
- The signing identity, team ID, Apple ID and keys are organization data and stay out of the repository.
- Re-sign and re-notarize every release; a notarization ticket is bound to the exact file content.
- Apple changes the tools and portal menus from time to time. If a command or menu differs, follow the current
  Apple documentation on "Notarizing macOS software before distribution".
