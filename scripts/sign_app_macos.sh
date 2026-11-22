#!/bin/sh
# Signs a macOS app bundle with a Developer ID Application certificate: every nested Mach-O file first (deepest
# first), then the bundle itself, with hardened runtime, secure timestamp and the entitlements of this repository.
# Usage: NSVIZ_SIGN_IDENTITY="Developer ID Application: <organization> (<team ID>)" scripts/sign_app_macos.sh <app>
# `codesign --deep` is deliberately not used: Apple advises against it for signing. The script holds no credentials.
set -eu
if [ -z "${NSVIZ_SIGN_IDENTITY:-}" ] || [ "$#" -ne 1 ] || [ ! -d "$1" ]; then
  echo "Usage: NSVIZ_SIGN_IDENTITY=\"Developer ID Application: ...\" $0 <path/to/nsviz.app>" >&2
  exit 2
fi
app=${1%/}
here=$(cd "$(dirname "$0")" && pwd)
main="$app/Contents/MacOS/nsviz"
[ -f "$main" ] || { echo "ERROR: main executable not found: $main" >&2; exit 1; }

# Regular files only (symlinks are skipped, their targets are signed in their own right). The main executable is
# signed together with the bundle at the end. Order: most path components first.
n=0
find "$app" -type f ! -path "$main" -print | while IFS= read -r f; do
  if file -b "$f" | grep -q 'Mach-O'; then
    printf '%s\n' "$f"
  fi
done | awk '{ c = gsub("/", "/"); printf "%d\t%s\n", c, $0 }' | sort -rn | cut -f2- > "${TMPDIR:-/tmp}/nsviz-sign-list.$$"
trap 'rm -f "${TMPDIR:-/tmp}/nsviz-sign-list.$$"' EXIT
while IFS= read -r f; do
  codesign --force --timestamp --options runtime --sign "$NSVIZ_SIGN_IDENTITY" "$f"
  n=$((n + 1))
done < "${TMPDIR:-/tmp}/nsviz-sign-list.$$"
echo "Signed $n nested file(s)."

codesign --force --timestamp --options runtime \
         --entitlements "$here/entitlements.plist" \
         --sign "$NSVIZ_SIGN_IDENTITY" "$app"
codesign --verify --deep --strict --verbose=2 "$app"
