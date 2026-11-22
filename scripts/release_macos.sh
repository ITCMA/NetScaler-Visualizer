#!/usr/bin/env bash
# One-shot macOS release for a single architecture. Runs on a Mac that holds the Developer ID Application
# certificate. Two products, each optional per run:
#   App  (--app):    sign nsviz.app (nested files first, hardened runtime, secure timestamp), build a DMG with the
#                    app and an Applications link, sign the DMG, notarize, staple, validate.
#   CLI  (--binary): sign the command-line binary, pack it into a ZIP, notarize. A ZIP cannot be stapled.
#
# Usage:
#   export NSVIZ_SIGN_IDENTITY="Developer ID Application: <organization> (<team ID>)"
#   scripts/release_macos.sh --arch arm64 --app ~/Downloads/nsviz-macos-arm64-app.zip \
#                                         --binary ~/Downloads/nsviz-macos-arm64
#   scripts/release_macos.sh --arch x64   --app ~/Downloads/nsviz-macos-x64-app.zip \
#                                         --binary ~/Downloads/nsviz-macos-x64
# One run per architecture. Results land in the release folder (see --out), directly in its top level.
#
# Options:
#   --arch arm64|x64     Target architecture (required).
#   --app PATH           Unsigned app bundle from the release workflow: the ZIP (nsviz-macos-<arch>-app.zip) or an
#                        nsviz.app folder. It is copied, never modified.
#   --binary PATH        Unsigned command-line binary from the release workflow. It is copied, never modified.
#                        At least one of --app and --binary is required.
#   --out DIR            Release folder. Default: $NSVIZ_RELEASE_DIR, else ~/NetScaler-Visualizer-Release.
#                        Must be outside the repository. Final products, directly in it:
#                          nsviz-macos-<arch>.dmg       app, signed, notarized, stapled
#                          nsviz-macos-<arch>-cli.zip   CLI binary (file name nsviz), signed, notarized
#                          SHA256SUMS.txt               regenerated over all products of this kind there
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

arch="" app="" binary="" out="" profile="nsviz-notary" dry=0

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
  while [ ! -e "$p" ]; do
    tail="/$(basename "$p")$tail"
    p=$(dirname "$p")
  done
  if [ -d "$p" ]; then
    printf '%s%s\n' "$(cd "$p" && pwd -P)" "$tail"
  else
    printf '%s/%s%s\n' "$(cd "$(dirname "$p")" && pwd -P)" "$(basename "$p")" "$tail"
  fi
}

# Architecture of a Mach-O file: prints what lipo/file report (empty when neither tool is available).
arch_of() {
  if command -v lipo >/dev/null 2>&1; then
    lipo -archs "$1" 2>/dev/null || true
  elif command -v file >/dev/null 2>&1; then
    file -b "$1" | grep -Eo 'arm64|x86_64' | sort -u | tr '\n' ' ' || true
  fi
}

# Dies unless $1 is a Mach-O file of the wanted architecture.
check_macho() {
  local f=$1 magic have
  magic=$(head -c 4 "$f" | od -An -tx1 | tr -d ' \n')
  case "$magic" in
    cffaedfe|cefaedfe|feedfacf|feedface|cafebabe|bebafeca) ;;  # Mach-O (thin, 32/64 bit) or fat
    *) die "not a Mach-O file (magic: $magic): $f" ;;
  esac
  have=$(arch_of "$f" | xargs)
  if [ -n "$have" ]; then
    [ "$have" = "$want_arch" ] || die "architecture mismatch: file contains '$have', expected '$want_arch' for --arch $arch: $f"
    echo "OK: Mach-O, architecture $have"
  fi
}

# Dies unless the signature of $1 has hardened runtime, secure timestamp and a Developer ID Application authority.
check_signature() {
  local f=$1 info
  run codesign --verify --strict --verbose=2 "$f"
  if [ "$dry" -eq 0 ]; then
    info=$(codesign -dv --verbose=4 "$f" 2>&1)
    echo "$info" | grep -E '^(Identifier|Format|Authority|Timestamp|TeamIdentifier|CodeDirectory)' || true
    echo "$info" | grep -Eq '^CodeDirectory .*flags=0x[0-9a-f]+\([^)]*runtime' \
      || die "hardened runtime flag missing in the signature of $f"
    echo "$info" | grep -q '^Timestamp=' \
      || die "secure timestamp missing in the signature of $f"
    echo "$info" | grep -q '^Authority=Developer ID Application' \
      || die "signature is not a Developer ID Application signature (identity wrong?)"
    echo "OK: runtime flag, secure timestamp and Developer ID authority present"
  fi
}

# Submits $1 to the notary service and waits. Dies unless the status is Accepted.
notarize() {
  local f=$1 log=$2 sub_id status
  if [ "$dry" -eq 1 ]; then
    run xcrun notarytool submit "$f" --keychain-profile "$profile" --wait
    echo "(on status other than Accepted the script prints: xcrun notarytool log <id> --keychain-profile $profile)"
    return 0
  fi
  # notarytool exits 0 even when the result is Invalid, so the status is read from its output.
  echo "+ xcrun notarytool submit $f --keychain-profile $profile --wait"
  xcrun notarytool submit "$f" --keychain-profile "$profile" --wait 2>&1 | tee "$log"
  sub_id=$(sed -n 's/^ *id: *//p' "$log" | head -n 1)
  status=$(sed -n 's/^ *status: *//p' "$log" | tail -n 1)
  if [ "$status" != "Accepted" ]; then
    echo >&2
    echo "Notarization result: ${status:-unknown}. Notary log:" >&2
    if [ -n "$sub_id" ]; then
      xcrun notarytool log "$sub_id" --keychain-profile "$profile" >&2 || true
    fi
    die "notarization was not accepted (status: ${status:-unknown}, submission: ${sub_id:-n/a})"
  fi
  echo "OK: notarization accepted (submission $sub_id)"
}

while [ $# -gt 0 ]; do
  case "$1" in
    --arch)    [ $# -ge 2 ] || die "--arch needs a value"; arch=$2; shift 2 ;;
    --app)     [ $# -ge 2 ] || die "--app needs a value"; app=$2; shift 2 ;;
    --binary)  [ $# -ge 2 ] || die "--binary needs a value"; binary=$2; shift 2 ;;
    --out)     [ $# -ge 2 ] || die "--out needs a value"; out=$2; shift 2 ;;
    --profile) [ $# -ge 2 ] || die "--profile needs a value"; profile=$2; shift 2 ;;
    --dry-run) dry=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; die "unknown argument: $1" ;;
  esac
done

# ---- input checks -------------------------------------------------------------------------------
[ -n "$arch" ] || { usage >&2; die "--arch is required (arm64 or x64)"; }
[ -n "$app$binary" ] || { usage >&2; die "--app and/or --binary is required"; }
[ -n "$out" ] || out="${NSVIZ_RELEASE_DIR:-$HOME/NetScaler-Visualizer-Release}"
case "$arch" in
  arm64) want_arch="arm64" ;;
  x64)   want_arch="x86_64" ;;
  *) die "--arch must be arm64 or x64, got: $arch" ;;
esac
[ -n "${NSVIZ_SIGN_IDENTITY:-}" ] || die "NSVIZ_SIGN_IDENTITY is empty. Set it in this shell first:
  export NSVIZ_SIGN_IDENTITY=\"Developer ID Application: <organization> (<team ID>)\"
  (list identities with: security find-identity -v -p codesigning)"
[ -z "$app" ] || [ -e "$app" ] || die "app not found: $app"
[ -z "$binary" ] || [ -f "$binary" ] || die "binary not found: $binary"

if [ "$dry" -eq 0 ] && [ "$(uname -s)" != "Darwin" ]; then
  die "this script needs macOS (codesign, hdiutil, notarytool). Use --dry-run to only print the commands."
fi

[ -z "$app" ] || app=$(abspath "$app")
[ -z "$binary" ] || binary=$(abspath "$binary")
out=$(abspath "$out")
case "$out/" in
  "$repo"/*) die "output folder is inside the repository ($repo). Choose a folder outside of it." ;;
esac

name="nsviz-macos-$arch"
work="$out/work/$arch"
app_dir="$work/app"                 # holds nsviz.app
bundle="$app_dir/nsviz.app"
staging="$work/dmg"
cli_dir="$work/cli"                 # holds the binary, named nsviz
dmg="$out/$name.dmg"
clizip="$out/$name-cli.zip"

echo "Architecture : $arch ($want_arch)"
[ -z "$app" ]    || echo "App          : $app"
[ -z "$binary" ] || echo "CLI binary   : $binary"
echo "Output       : $out"
echo "Notary profile: $profile"
[ "$dry" -eq 1 ] && echo "Mode         : DRY RUN (nothing is executed)"

# The work folder is created by this script, so removing it is safe.
case "$work" in "$out"/work/arm64|"$out"/work/x64) ;; *) die "internal error: unexpected work path" ;; esac
step "Prepare work folder"
run rm -rf "$work"
run mkdir -p "$work"

# =================================================================================================
# App: nsviz.app -> signed -> DMG -> notarized -> stapled
# =================================================================================================
if [ -n "$app" ]; then
  step "App 1/6 Unpack and check the bundle"
  run mkdir -p "$app_dir"
  if [ -d "$app" ]; then
    run ditto "$app" "$bundle"
  else
    run ditto -x -k "$app" "$app_dir"
  fi
  if [ "$dry" -eq 0 ]; then
    [ -d "$bundle" ] || die "nsviz.app not found after unpacking (expected $bundle). Is --app the ZIP from the release workflow?"
    [ -f "$bundle/Contents/MacOS/nsviz" ] || die "main executable missing: $bundle/Contents/MacOS/nsviz"
    check_macho "$bundle/Contents/MacOS/nsviz"
  fi

  step "App 2/6 Sign bundle (nested files first, hardened runtime, secure timestamp, entitlements)"
  run "$here/sign_app_macos.sh" "$bundle"

  step "App 3/6 Verify bundle signature"
  check_signature "$bundle"

  step "App 4/6 Build and sign DMG"
  run mkdir -p "$staging"
  run ditto "$bundle" "$staging/nsviz.app"
  run ln -s /Applications "$staging/Applications"
  run rm -f "$dmg"
  run hdiutil create -volname nsviz -srcfolder "$staging" -ov -format UDZO "$dmg"
  run codesign --force --timestamp --sign "$NSVIZ_SIGN_IDENTITY" "$dmg"
  run codesign --verify --strict --verbose=2 "$dmg"

  step "App 5/6 Notarize DMG (waits for Apple, usually a few minutes)"
  notarize "$dmg" "$work/notary-app.log"

  step "App 6/6 Staple and validate DMG"
  run xcrun stapler staple "$dmg"
  run xcrun stapler validate "$dmg"
  if [ "$dry" -eq 0 ]; then
    # Informational Gatekeeper checks; not fatal, because spctl output varies between macOS versions.
    spctl --assess --type open --context context:primary-signature --verbose "$dmg" 2>&1 \
      || echo "NOTE: spctl assessment did not accept the DMG. Verify manually on a second Mac." >&2
    spctl --assess --type execute --verbose "$bundle" 2>&1 \
      || echo "NOTE: spctl assessment did not accept the app. Verify manually on a second Mac." >&2
  else
    echo "+ spctl --assess --type open --context context:primary-signature --verbose $dmg"
    echo "+ spctl --assess --type execute --verbose $bundle"
  fi
fi

# =================================================================================================
# CLI: binary -> signed -> ZIP -> notarized (no stapling possible for a ZIP)
# =================================================================================================
if [ -n "$binary" ]; then
  step "CLI 1/4 Check binary"
  if [ "$dry" -eq 0 ] || [ -f "$binary" ]; then check_macho "$binary"; fi

  step "CLI 2/4 Sign binary (hardened runtime, secure timestamp, entitlements)"
  run mkdir -p "$cli_dir"
  run cp "$binary" "$cli_dir/nsviz"
  run chmod 755 "$cli_dir/nsviz"
  run "$here/sign_macos.sh" "$cli_dir/nsviz"

  step "CLI 3/4 Verify signature and pack ZIP"
  check_signature "$cli_dir/nsviz"
  run rm -f "$clizip"
  # Only the binary in the ZIP (no parent folder); ditto keeps the executable bit.
  run ditto -c -k "$cli_dir/nsviz" "$clizip"

  step "CLI 4/4 Notarize ZIP (waits for Apple, usually a few minutes)"
  notarize "$clizip" "$work/notary-cli.log"
  echo "Note: a ZIP cannot be stapled. Gatekeeper checks the notarization ticket online for this file."
fi

# ---- checksums and cleanup ----------------------------------------------------------------------
step "Checksums and cleanup"
if [ "$dry" -eq 0 ]; then
  # find, not a glob: a pattern without a match (for example no CLI ZIP yet) must not abort the script.
  ( cd "$out" && find . -maxdepth 1 \( -name 'nsviz-macos-*.dmg' -o -name 'nsviz-macos-*-cli.zip' \) \
      | sed 's#^\./##' | sort | xargs shasum -a 256 > SHA256SUMS.txt )
  echo "SHA256SUMS.txt:"; cat "$out/SHA256SUMS.txt"
  rm -rf "$work"
  rmdir "$out/work" 2>/dev/null || true
else
  echo "+ (cd $out && shasum -a 256 <all nsviz-macos-*.dmg and nsviz-macos-*-cli.zip> > SHA256SUMS.txt)"
  echo "+ rm -rf $work"
fi

step "Done"
if [ "$dry" -eq 0 ]; then
  [ -z "$app" ]    || echo "App    : $dmg"
  [ -z "$binary" ] || echo "CLI    : $clizip"
  echo "Sums   : $out/SHA256SUMS.txt"
  echo "Next steps:"
  echo "  1. Run this script for the other architecture if not done yet (one run per architecture)."
  echo "  2. Optional test on a second Mac: download the DMG via browser, drag nsviz to Applications, start it."
  echo "  3. Upload the DMGs and CLI ZIPs to the GitHub release draft, replacing the unsigned macOS files, and"
  echo "     merge the checksums: keep the Windows line of the draft's SHA256SUMS.txt, replace the macOS lines"
  echo "     with the lines of this run. Do not publish before checking the release notes."
  echo "  4. Keep the release folder as archive; it is outside the repository and is never committed."
else
  echo "Dry run finished, nothing was executed."
fi
