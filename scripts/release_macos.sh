#!/usr/bin/env bash
# One-shot macOS release for a single architecture: sign the binary, build a DMG, sign the DMG,
# notarize, staple and validate. Runs on a Mac that holds the Developer ID Application certificate.
#
# Usage:
#   export NSVIZ_SIGN_IDENTITY="Developer ID Application: <organization> (<team ID>)"
#   scripts/release_macos.sh --arch arm64 --binary ~/Downloads/nsviz-macos-arm64
#   scripts/release_macos.sh --arch x64   --binary ~/Downloads/nsviz-macos-x64
# One run per architecture. Results land in the release folder (see --out), directly in its top level.
#
# Options:
#   --arch arm64|x64     Target architecture (required).
#   --binary PATH        Downloaded, still unsigned binary (required). It is copied, never modified.
#   --out DIR            Release folder. Default: $NSVIZ_RELEASE_DIR, else ~/NetScaler-Visualizer-Release.
#                        Must be outside the repository. Final products, directly in it:
#                          nsviz-macos-<arch>.dmg   signed, notarized, stapled
#                          SHA256SUMS.txt           regenerated over all nsviz-macos-*.dmg there
#                        Intermediate files go to <out>/work/<arch>/ and are deleted after success
#                        (kept on failure for inspection).
#   --profile NAME       notarytool keychain profile (default: nsviz-notary).
#   --dry-run            Print the commands without running them.
#   -h, --help           This help.
#
# The script holds no credentials. The signing identity comes from NSVIZ_SIGN_IDENTITY only; the notary
# credentials live in the keychain profile (see docs/SIGNING.md, step 3). Stops on the first error.
set -euo pipefail
# Keep the Bash 3.2 that ships with macOS in mind: no mapfile, no associative arrays.

here=$(cd "$(dirname "$0")" && pwd -P)
repo=$(cd "$here/.." && pwd -P)

arch="" binary="" out="" profile="nsviz-notary" dry=0

die()  { echo "ERROR: $*" >&2; exit 1; }
step() { printf '\n==> %s\n' "$*"; }
usage() { sed -n '2,/^set -euo/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//'; }

# Prints the command; runs it unless --dry-run.
run() {
  printf '+'; printf ' %q' "$@"; printf '\n'
  if [ "$dry" -eq 0 ]; then "$@"; fi
}

# Absolute, symlink-resolved path, also for a folder that does not exist yet.
abspath() {
  local p=$1 tail=""
  while [ ! -d "$p" ]; do
    tail="/$(basename "$p")$tail"
    p=$(dirname "$p")
  done
  printf '%s%s\n' "$(cd "$p" && pwd -P)" "$tail"
}

while [ $# -gt 0 ]; do
  case "$1" in
    --arch)    [ $# -ge 2 ] || die "--arch needs a value"; arch=$2; shift 2 ;;
    --binary)  [ $# -ge 2 ] || die "--binary needs a value"; binary=$2; shift 2 ;;
    --out)     [ $# -ge 2 ] || die "--out needs a value"; out=$2; shift 2 ;;
    --profile) [ $# -ge 2 ] || die "--profile needs a value"; profile=$2; shift 2 ;;
    --dry-run) dry=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; die "unknown argument: $1" ;;
  esac
done

# ---- input checks -------------------------------------------------------------------------------
[ -n "$arch" ]   || { usage >&2; die "--arch is required (arm64 or x64)"; }
[ -n "$binary" ] || { usage >&2; die "--binary is required"; }
[ -n "$out" ] || out="${NSVIZ_RELEASE_DIR:-$HOME/NetScaler-Visualizer-Release}"
case "$arch" in
  arm64) want_arch="arm64" ;;
  x64)   want_arch="x86_64" ;;
  *) die "--arch must be arm64 or x64, got: $arch" ;;
esac
[ -n "${NSVIZ_SIGN_IDENTITY:-}" ] || die "NSVIZ_SIGN_IDENTITY is empty. Set it in this shell first:
  export NSVIZ_SIGN_IDENTITY=\"Developer ID Application: <organization> (<team ID>)\"
  (list identities with: security find-identity -v -p codesigning)"
[ -f "$binary" ] || die "binary not found: $binary"

if [ "$dry" -eq 0 ] && [ "$(uname -s)" != "Darwin" ]; then
  die "this script needs macOS (codesign, hdiutil, notarytool). Use --dry-run to only print the commands."
fi

binary=$(cd "$(dirname "$binary")" && pwd -P)/$(basename "$binary")
out=$(abspath "$out")
case "$out/" in
  "$repo"/*) die "output folder is inside the repository ($repo). Choose a folder outside of it." ;;
esac

name="nsviz-macos-$arch"
work="$out/work/$arch"
staging="$work/staging"
dmg="$out/$name.dmg"
notary_log="$work/notary.log"

echo "Architecture : $arch ($want_arch)"
echo "Binary       : $binary"
echo "Output       : $out"
echo "Notary profile: $profile"
[ "$dry" -eq 1 ] && echo "Mode         : DRY RUN (nothing is executed)"

# ---- 1. check the binary --------------------------------------------------------------------------
step "1/7 Check binary"
magic=$(head -c 4 "$binary" | od -An -tx1 | tr -d ' \n')
case "$magic" in
  cffaedfe|cefaedfe|feedfacf|feedface|cafebabe|bebafeca) ;;  # Mach-O (thin, 32/64 bit) or fat
  *) die "not a Mach-O file (magic: $magic): $binary" ;;
esac
if command -v lipo >/dev/null 2>&1; then
  have_arch=$(lipo -archs "$binary" 2>/dev/null || true)
elif command -v file >/dev/null 2>&1; then
  have_arch=$(file -b "$binary" | grep -Eo 'arm64|x86_64' | sort -u | tr '\n' ' ' || true)
else
  have_arch=""
  [ "$dry" -eq 1 ] || die "neither lipo nor file available to check the architecture"
fi
have_arch=$(echo "$have_arch" | xargs)
if [ -n "$have_arch" ]; then
  [ "$have_arch" = "$want_arch" ] || die "architecture mismatch: file contains '$have_arch', expected '$want_arch' for --arch $arch"
  echo "OK: Mach-O, architecture $have_arch"
fi

# ---- 2. staging + sign binary -----------------------------------------------------------------------
step "2/7 Sign binary (hardened runtime, secure timestamp, entitlements)"
# Clean work folder for this architecture; staging contains only this binary. The folder is created by
# this script, so removing it is safe.
case "$work" in "$out"/work/arm64|"$out"/work/x64) ;; *) die "internal error: unexpected work path" ;; esac
run rm -rf "$work"
run mkdir -p "$staging"
run cp "$binary" "$staging/$name"
run chmod 755 "$staging/$name"
run "$here/sign_macos.sh" "$staging/$name"   # codesign --force --timestamp --options runtime --entitlements ...; --verify --strict

# ---- 3. verify binary signature ---------------------------------------------------------------------------
step "3/7 Verify binary signature"
run codesign --verify --strict --verbose=2 "$staging/$name"
if [ "$dry" -eq 0 ]; then
  info=$(codesign -dv --verbose=4 "$staging/$name" 2>&1)
  echo "$info" | grep -E '^(Identifier|Format|Authority|Timestamp|TeamIdentifier|CodeDirectory)' || true
  echo "$info" | grep -Eq '^CodeDirectory .*flags=0x[0-9a-f]+\([^)]*runtime' \
    || die "hardened runtime flag missing in the signature of $name"
  echo "$info" | grep -q '^Timestamp=' \
    || die "secure timestamp missing in the signature of $name"
  echo "$info" | grep -q '^Authority=Developer ID Application' \
    || die "signature is not a Developer ID Application signature (identity wrong?)"
  echo "OK: runtime flag, secure timestamp and Developer ID authority present"
fi

# ---- 4. DMG -----------------------------------------------------------------------------------------------
step "4/7 Build DMG"
run rm -f "$dmg"
run hdiutil create -volname nsviz -srcfolder "$staging" -ov -format UDZO "$dmg"

# ---- 5. sign DMG -------------------------------------------------------------------------------------------
step "5/7 Sign DMG"
run codesign --force --timestamp --sign "$NSVIZ_SIGN_IDENTITY" "$dmg"
run codesign --verify --strict --verbose=2 "$dmg"

# ---- 6. notarize ------------------------------------------------------------------------------------------
step "6/7 Notarize (waits for Apple, usually a few minutes)"
if [ "$dry" -eq 1 ]; then
  run xcrun notarytool submit "$dmg" --keychain-profile "$profile" --wait
  echo "(on status other than Accepted the script prints: xcrun notarytool log <id> --keychain-profile $profile)"
else
  # notarytool exits 0 even when the result is Invalid, so the status is read from its output.
  echo "+ xcrun notarytool submit $dmg --keychain-profile $profile --wait"
  xcrun notarytool submit "$dmg" --keychain-profile "$profile" --wait 2>&1 | tee "$notary_log"
  sub_id=$(sed -n 's/^ *id: *//p' "$notary_log" | head -n 1)
  status=$(sed -n 's/^ *status: *//p' "$notary_log" | tail -n 1)
  if [ "$status" != "Accepted" ]; then
    echo >&2
    echo "Notarization result: ${status:-unknown}. Notary log:" >&2
    if [ -n "$sub_id" ]; then
      xcrun notarytool log "$sub_id" --keychain-profile "$profile" >&2 || true
    fi
    die "notarization was not accepted (status: ${status:-unknown}, submission: ${sub_id:-n/a})"
  fi
  echo "OK: notarization accepted (submission $sub_id)"
fi

# ---- 7. staple + validate ----------------------------------------------------------------------------------------
step "7/7 Staple and validate"
run xcrun stapler staple "$dmg"
run xcrun stapler validate "$dmg"
if [ "$dry" -eq 0 ]; then
  # Informational Gatekeeper check; not fatal, because spctl output varies between macOS versions.
  spctl --assess --type open --context context:primary-signature --verbose "$dmg" 2>&1 \
    || echo "NOTE: spctl assessment did not accept the DMG. Verify manually on a second Mac." >&2
fi

step "Checksums and cleanup"
if [ "$dry" -eq 0 ]; then
  ( cd "$out" && shasum -a 256 nsviz-macos-*.dmg > SHA256SUMS.txt )
  echo "SHA256SUMS.txt:"; cat "$out/SHA256SUMS.txt"
  rm -rf "$work"
  rmdir "$out/work" 2>/dev/null || true
else
  echo "+ (cd $out && shasum -a 256 nsviz-macos-*.dmg > SHA256SUMS.txt)"
  echo "+ rm -rf $work"
fi

step "Done"
if [ "$dry" -eq 0 ]; then
  echo "Result : $dmg"
  echo "Sums   : $out/SHA256SUMS.txt"
  echo "Next steps:"
  echo "  1. Run this script for the other architecture if not done yet (one run per architecture)."
  echo "  2. Optional test on a second Mac: download the DMG via browser, open it, start nsviz."
  echo "  3. Upload $name.dmg (and SHA256SUMS.txt) to the GitHub release draft, replacing the unsigned"
  echo "     macOS files. Do not publish before checking the release notes."
  echo "  4. Keep the release folder as archive; it is outside the repository and is never committed."
else
  echo "Dry run finished, nothing was executed."
fi
