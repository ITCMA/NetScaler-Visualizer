#!/bin/sh
# Signs a macOS binary with a Developer ID Application certificate (hardened runtime, secure timestamp).
# Usage: NSVIZ_SIGN_IDENTITY="Developer ID Application: <organization> (<team ID>)" scripts/sign_macos.sh <file>...
# Notarization is a separate step, see docs/SIGNING.md. The script holds no credentials.
set -eu
if [ -z "${NSVIZ_SIGN_IDENTITY:-}" ] || [ "$#" -eq 0 ]; then
  echo "Usage: NSVIZ_SIGN_IDENTITY=\"Developer ID Application: ...\" $0 <file>..." >&2
  exit 2
fi
here=$(cd "$(dirname "$0")" && pwd)
for f in "$@"; do
  codesign --force --timestamp --options runtime \
           --entitlements "$here/entitlements.plist" \
           --sign "$NSVIZ_SIGN_IDENTITY" "$f"
  codesign --verify --strict --verbose=2 "$f"
done
