#!/usr/bin/env bash
# One-shot macOS release for a single architecture. Runs on a Mac that holds the Developer ID Application
# certificate. Signs nsviz.app (nested files first, hardened runtime, secure timestamp), builds a DMG with the app and
# an Applications link, signs the DMG, notarizes, staples and validates. The command line is part of the app:
# nsviz.app/Contents/MacOS/nsviz (with arguments it behaves like `python -m nsviz`).
#
# Usage:
#   export NSVIZ_SIGN_IDENTITY="Developer ID Application: <organization> (<team ID>)"
#   scripts/release_macos.sh --arch arm64 --app ~/Downloads/nsviz-macos-arm64-app.zip
#   scripts/release_macos.sh --arch x64   --app ~/Downloads/nsviz-macos-x64-app.zip
# One run per architecture. Results land in the release folder (see --out), directly in its top level.
#
# Options:
#   --arch arm64|x64     Target architecture (required).
#   --app PATH           Unsigned app bundle from the release workflow (required): the ZIP
#                        (nsviz-macos-<arch>-app.zip, also as downloaded from GitHub, a ZIP inside a ZIP) or an
#                        nsviz.app folder. It is copied, never modified.
#   --out DIR            Release folder. Default: $NSVIZ_RELEASE_DIR, else ~/NetScaler-Visualizer-Release.
#                        Must be outside the repository. Final products, directly in it:
#                          nsviz-macos-<arch>.dmg       signed, notarized, stapled
#                          SHA256SUMS.txt               regenerated over all nsviz-macos-*.dmg there
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

arch="" app="" out="" profile="nsviz-notary" dry=0

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

# Detaches the volume mounted at $1; Finder or Spotlight may hold it for a moment, so retry before forcing.
detach_volume() {
  local i
  for i in 1 2 3 4 5; do
    if hdiutil detach "$1" >/dev/null 2>&1; then return 0; fi
    sleep 2
  done
  hdiutil detach "$1" -force
}

# Unpacks the ZIP $1 into the folder $2 (ditto on macOS; unzip where ditto is missing, e.g. a dry run elsewhere).
unzip_to() {
  mkdir -p "$2"
  if command -v ditto >/dev/null 2>&1; then ditto -x -k "$1" "$2"; else unzip -q -o "$1" -d "$2"; fi
}

# Puts nsviz.app into the folder $2 from $1: an nsviz.app folder, the ZIP made by the release workflow, or the
# ZIP that GitHub builds around a downloaded artifact (a ZIP inside a ZIP). Dies if there is no nsviz.app afterwards.
unpack_app() {
  local src=$1 dst=$2 inner n
  mkdir -p "$dst"
  if [ -d "$src" ]; then
    if command -v ditto >/dev/null 2>&1; then ditto "$src" "$dst/nsviz.app"; else cp -R "$src" "$dst/nsviz.app"; fi
  else
    unzip_to "$src" "$dst"
    if [ ! -d "$dst/nsviz.app" ]; then
      n=$(find "$dst" -maxdepth 1 -type f -name '*.zip' | wc -l | tr -d ' ')
      if [ "$n" = "1" ]; then
        inner=$(find "$dst" -maxdepth 1 -type f -name '*.zip')
        echo "NOTE: no nsviz.app in the ZIP, but an inner ZIP ($(basename "$inner")); unpacking that as well."
        unzip_to "$inner" "$dst"
      fi
    fi
  fi
  [ -d "$dst/nsviz.app" ] || die "nsviz.app not found after unpacking $src (found: $(ls "$dst" | tr '\n' ' '))"
  [ -f "$dst/nsviz.app/Contents/MacOS/nsviz" ] || die "main executable missing: $dst/nsviz.app/Contents/MacOS/nsviz"
}

while [ $# -gt 0 ]; do
  case "$1" in
    --arch)    [ $# -ge 2 ] || die "--arch needs a value"; arch=$2; shift 2 ;;
    --app)     [ $# -ge 2 ] || die "--app needs a value"; app=$2; shift 2 ;;
    --out)     [ $# -ge 2 ] || die "--out needs a value"; out=$2; shift 2 ;;
    --profile) [ $# -ge 2 ] || die "--profile needs a value"; profile=$2; shift 2 ;;
    --dry-run) dry=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; die "unknown argument: $1" ;;
  esac
done

# ---- input checks -------------------------------------------------------------------------------
[ -n "$arch" ] || { usage >&2; die "--arch is required (arm64 or x64)"; }
[ -n "$app" ] || { usage >&2; die "--app is required"; }
[ -n "$out" ] || out="${NSVIZ_RELEASE_DIR:-$HOME/NetScaler-Visualizer-Release}"
case "$arch" in
  arm64) want_arch="arm64" ;;
  x64)   want_arch="x86_64" ;;
  *) die "--arch must be arm64 or x64, got: $arch" ;;
esac
[ -n "${NSVIZ_SIGN_IDENTITY:-}" ] || die "NSVIZ_SIGN_IDENTITY is empty. Set it in this shell first:
  export NSVIZ_SIGN_IDENTITY=\"Developer ID Application: <organization> (<team ID>)\"
  (list identities with: security find-identity -v -p codesigning)"
[ -e "$app" ] || die "app not found: $app"

if [ "$dry" -eq 0 ] && [ "$(uname -s)" != "Darwin" ]; then
  die "this script needs macOS (codesign, hdiutil, notarytool). Use --dry-run to only print the commands."
fi

app=$(abspath "$app")
out=$(abspath "$out")
case "$out/" in
  "$repo"/*) die "output folder is inside the repository ($repo). Choose a folder outside of it." ;;
esac

name="nsviz-macos-$arch"
work="$out/work/$arch"
app_dir="$work/app"                 # holds nsviz.app
bundle="$app_dir/nsviz.app"
staging="$work/dmg"
dmg="$out/$name.dmg"

tmp_root=$(mktemp -d)
mnt="$work/mnt"                     # temporary mount point for the DMG volume icon
cleanup() {
  if [ "$dry" -eq 0 ] && mount | grep -q " on $mnt "; then hdiutil detach "$mnt" -force >/dev/null 2>&1 || true; fi
  rm -rf "$tmp_root"               # own temporary folder only
}
trap cleanup EXIT

echo "Architecture : $arch ($want_arch)"
echo "App          : $app"
echo "Output       : $out"
echo "Notary profile: $profile"
[ "$dry" -eq 1 ] && echo "Mode         : DRY RUN (nothing is executed)"

# The work folder is created by this script, so removing it is safe.
case "$work" in "$out"/work/arm64|"$out"/work/x64) ;; *) die "internal error: unexpected work path" ;; esac
step "Prepare work folder"
run rm -rf "$work"
run mkdir -p "$work"

# =================================================================================================
# nsviz.app -> signed -> DMG -> notarized -> stapled
# =================================================================================================
step "App 1/6 Unpack and check the bundle"
if [ "$dry" -eq 1 ]; then
  # Unpacking and checking the input is harmless, so a dry run does it too (in a temporary folder).
  echo "(dry run: the input is unpacked into a temporary folder only to check it)"
  unpack_app "$app" "$tmp_root/app"
  check_macho "$tmp_root/app/nsviz.app/Contents/MacOS/nsviz"
  echo "OK: nsviz.app found in $app"
  run mkdir -p "$app_dir"
  echo "+ (unpack $app into $app_dir)"
else
  unpack_app "$app" "$app_dir"
  check_macho "$bundle/Contents/MacOS/nsviz"
fi

step "App 2/6 Sign bundle (nested files first, hardened runtime, secure timestamp, entitlements)"
run "$here/sign_app_macos.sh" "$bundle"

step "App 3/6 Verify bundle signature"
check_signature "$bundle"

step "App 4/6 Build and sign DMG (with the app icon as volume icon)"
run mkdir -p "$staging"
run ditto "$bundle" "$staging/nsviz.app"
run ln -s /Applications "$staging/Applications"
# Volume icon: the icon file of the bundle (Info.plist: CFBundleIconFile) becomes .VolumeIcon.icns; the flag for a
# custom icon is set with SetFile -a C on the mounted volume. Cosmetic: without icon or SetFile the DMG is built plain.
have_icon=0
icon_src="$bundle/Contents/Resources/<CFBundleIconFile>.icns"
if [ "$dry" -eq 0 ]; then
  icon_name=$(/usr/libexec/PlistBuddy -c 'Print :CFBundleIconFile' "$bundle/Contents/Info.plist" 2>/dev/null || true)
  case "$icon_name" in ""|*.icns) ;; *) icon_name="$icon_name.icns" ;; esac
  icon_src="$bundle/Contents/Resources/$icon_name"
  if [ -z "$icon_name" ] || [ ! -f "$icon_src" ]; then
    echo "NOTE: no icon file found in the bundle (CFBundleIconFile='${icon_name:-}'); the DMG gets no volume icon." >&2
  elif ! command -v SetFile >/dev/null 2>&1; then
    echo "NOTE: SetFile not found (Xcode command line tools); the DMG gets no volume icon." >&2
  else
    have_icon=1
  fi
else
  have_icon=1
fi
run rm -f "$dmg"
if [ "$have_icon" -eq 1 ]; then
  rwdmg="$work/$name-rw.dmg"
  run cp "$icon_src" "$staging/.VolumeIcon.icns"
  run hdiutil create -volname nsviz -srcfolder "$staging" -fs HFS+ -format UDRW -ov "$rwdmg"
  run mkdir -p "$mnt"
  run hdiutil attach "$rwdmg" -mountpoint "$mnt" -nobrowse -noautoopen
  run SetFile -a C "$mnt"
  if [ "$dry" -eq 0 ]; then detach_volume "$mnt"; else echo "+ (hdiutil detach $mnt, with retries)"; fi
  run hdiutil convert "$rwdmg" -format UDZO -o "$dmg"
  # Check before signing and notarizing: the icon file is in the image and the custom-icon flag is set.
  if [ "$dry" -eq 0 ]; then
    hdiutil attach "$dmg" -readonly -mountpoint "$mnt" -nobrowse -noautoopen >/dev/null
    if [ -f "$mnt/.VolumeIcon.icns" ] && GetFileInfo -a "$mnt" | grep -q 'C'; then
      echo "OK: volume icon present and flagged in the DMG"
    else
      echo "NOTE: volume icon or its flag is missing in the DMG (cosmetic; the DMG works without it)." >&2
    fi
    detach_volume "$mnt"
  else
    echo "+ (check: hdiutil attach -readonly $dmg; .VolumeIcon.icns present; GetFileInfo -a shows flag C; detach)"
  fi
else
  run hdiutil create -volname nsviz -srcfolder "$staging" -ov -format UDZO "$dmg"
fi
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

# ---- checksums and cleanup ----------------------------------------------------------------------
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
  echo "  2. Optional test on a second Mac: download the DMG via browser, drag nsviz to Applications, start it."
  echo "  3. Upload the DMGs to the GitHub release draft, replacing the unsigned macOS files, and"
  echo "     merge the checksums: keep the Windows line of the draft's SHA256SUMS.txt, replace the macOS lines"
  echo "     with the lines of this run. Do not publish before checking the release notes."
  echo "  4. Keep the release folder as archive; it is outside the repository and is never committed."
else
  echo "Dry run finished, nothing was executed."
fi
