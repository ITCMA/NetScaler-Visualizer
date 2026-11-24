#!/usr/bin/env bash
# Fully automatic macOS release step: download the unsigned app bundles from the release DRAFT, sign, build the DMGs,
# notarize, staple, verify, and upload the signed DMGs and the merged SHA256SUMS.txt back to the same draft.
# Runs on the Mac that holds the Developer ID Application certificate. No parameters are needed.
#
# Usage:
#   scripts/publish_release.sh              # the one existing release draft is used
#   scripts/publish_release.sh v0.4.1       # a specific tag
#   scripts/publish_release.sh --dry-run    # checks and plan only: nothing is downloaded, signed or uploaded
#
# Options:
#   <tag>             Release tag (vX.Y.Z). Optional if exactly one draft release exists.
#   --dry-run         Run all read-only checks (tools, identity, notary profile, GitHub login, draft and its assets)
#                     and print what would happen. Changes nothing, not even locally.
#   --no-upload       Download, sign, notarize and verify, but do not touch the draft.
#   --out DIR         Release folder (default: $NSVIZ_RELEASE_DIR, else ~/NetScaler-Visualizer-Release). Per tag a
#                     subfolder <DIR>/<tag>/ is used; logs go to <DIR>/logs/. Must be outside the repository.
#   --repo OWNER/NAME GitHub repository (default: taken from the git remote of this checkout).
#   --profile NAME    notarytool keychain profile (default: nsviz-notary).
#   -h, --help        This help.
#
# Detected automatically:
#   signing identity  the only "Developer ID Application" identity in the keychain (security find-identity). With
#                     several, the script stops and lists them; choose one with NSVIZ_SIGN_IDENTITY.
#   notary profile    nsviz-notary, checked with notarytool before anything else.
#   GitHub access     the login of the GitHub CLI (gh auth login), nothing else.
#
# The release draft is NEVER published by this script. Unsigned macOS app ZIPs are removed from the draft only after
# both signed DMGs are uploaded and verified. The script holds no credentials and never prints any.
set -euo pipefail
# Keep the Bash 3.2 that ships with macOS in mind: no mapfile, no associative arrays, no ${var,,}.

here=$(cd "$(dirname "$0")" && pwd -P)
repo=$(cd "$here/.." && pwd -P)

tag="" out="" repo_slug="" profile="nsviz-notary" dry=0 no_upload=0
step_now="start"
logger_pid="" logfile="" T="" started=$(date +%s)
results=""

usage() { sed -n '2,/^set -euo/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//'; }
step()  { step_now=$*; printf '\n==> %s\n' "$*"; }
info()  { printf '%s\n' "$*"; }
ok()    { printf 'OK: %s\n' "$*"; }
warn()  { printf 'WARNING: %s\n' "$*" >&2; }
die()   { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
note_result() { results="$results$*
"; }

# retry <attempts> <delay seconds> command...   (the command must be a single simple command or function)
retry() {
  local n=$1 d=$2 i=1
  shift 2
  while :; do
    if "$@"; then return 0; fi
    if [ "$i" -ge "$n" ]; then return 1; fi
    warn "attempt $i/$n failed: $1 ...; next attempt in ${d}s"
    sleep "$d"
    i=$((i + 1))
  done
}

# ---- arguments ----------------------------------------------------------------------------------
while [ $# -gt 0 ]; do
  case "$1" in
    --dry-run)   dry=1; shift ;;
    --no-upload) no_upload=1; shift ;;
    --out)       [ $# -ge 2 ] || die "--out needs a value"; out=$2; shift 2 ;;
    --repo)      [ $# -ge 2 ] || die "--repo needs a value"; repo_slug=$2; shift 2 ;;
    --profile)   [ $# -ge 2 ] || die "--profile needs a value"; profile=$2; shift 2 ;;
    -h|--help)   usage; exit 0 ;;
    -*)          usage >&2; die "unknown option: $1" ;;
    *)           [ -z "$tag" ] || die "more than one tag given: $tag and $1"; tag=$1; shift ;;
  esac
done
if [ -n "$tag" ]; then
  printf '%s' "$tag" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z.]+)?$' \
    || die "tag '$tag' does not look like vX.Y.Z"
fi
[ -n "$out" ] || out="${NSVIZ_RELEASE_DIR:-$HOME/NetScaler-Visualizer-Release}"
on_mac=0; [ "$(uname -s)" = "Darwin" ] && on_mac=1
if [ "$on_mac" -eq 0 ] && [ "$dry" -eq 0 ]; then
  die "this script needs macOS (codesign, hdiutil, notarytool). --dry-run runs the checks that work elsewhere."
fi

# ---- release folder and logging -----------------------------------------------------------------
# Absolute, symlink-resolved path of a folder that may not exist yet.
abspath() {
  local p=$1 tail=""
  while [ ! -e "$p" ]; do tail="/$(basename "$p")$tail"; p=$(dirname "$p"); done
  printf '%s%s\n' "$(cd "$p" && pwd -P)" "$tail"
}
REL=$(abspath "$out")
case "$REL/" in "$repo"/*) die "release folder is inside the repository ($repo). Choose a folder outside of it." ;; esac

summary_and_close() {
  local rc=$1 secs=$(( $(date +%s) - started ))
  printf '\n'
  printf '=====================================================================\n'
  if [ "$rc" -eq 0 ]; then
    printf 'RESULT: SUCCESS%s (%dm%02ds)\n' "$([ "$dry" -eq 1 ] && printf ' (dry run, nothing changed)')" $((secs / 60)) $((secs % 60))
  else
    printf 'RESULT: FAILED in step "%s" (exit %s, %dm%02ds)\n' "$step_now" "$rc" $((secs / 60)) $((secs % 60))
    printf 'Nothing was published. The release draft is unchanged unless the log shows an upload step.\n'
    printf 'Fix the cause and run the same command again: every run starts clean and replaces earlier uploads.\n'
  fi
  [ -z "$results" ] || printf '%s' "$results"
  [ -z "$logfile" ] || printf 'Log: %s\n' "$logfile"
  printf '=====================================================================\n'
}

cleanup() {
  local rc=$? m
  trap - EXIT
  set +e
  # Volumes that a failed DMG step left mounted under our work folder.
  if [ "$on_mac" -eq 1 ] && [ -n "$T" ]; then
    mount | sed -n "s| on \($T/work/[^ ]*\) (.*|\1|p" | while IFS= read -r m; do
      info "Cleanup: detaching leftover volume $m"
      hdiutil detach "$m" -force >/dev/null 2>&1
    done
  fi
  summary_and_close "$rc"
  if [ -n "$logger_pid" ]; then
    exec >&- 2>&-
    wait "$logger_pid" 2>/dev/null
  fi
  exit "$rc"
}

if [ "$dry" -eq 0 ]; then
  mkdir -p "$REL/logs"
  logfile="$REL/logs/publish-$(date +%Y%m%d-%H%M%S).log"
  : > "$logfile"
  fifo="$REL/logs/.fifo.$$"
  mkfifo "$fifo"
  ( while IFS= read -r line; do printf '%s %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$line"; done < "$fifo" | tee -a "$logfile" ) &
  logger_pid=$!
  exec > "$fifo" 2>&1
  rm -f "$fifo"
fi
trap cleanup EXIT

info "publish_release.sh  started $(date '+%Y-%m-%d %H:%M:%S')  host $(hostname -s)  macOS $(sw_vers -productVersion 2>/dev/null || echo n/a)"
[ "$dry" -eq 1 ] && info "Mode: DRY RUN (read-only checks, nothing is downloaded, signed or uploaded)"
[ "$no_upload" -eq 1 ] && info "Mode: --no-upload (the release draft is not touched)"
info "Release folder: $REL"
if [ "$on_mac" -eq 1 ] && [ "$(id -u)" -ne 0 ]; then
  if command -v caffeinate >/dev/null 2>&1; then caffeinate -i -w $$ >/dev/null 2>&1 & fi   # no sleep during notarization
fi

# =================================================================================================
step "1/9 Check tools"
missing=""
for t in gh git curl shasum awk sed grep; do command -v "$t" >/dev/null 2>&1 || missing="$missing $t"; done
if [ "$on_mac" -eq 1 ]; then
  for t in codesign hdiutil xcrun security ditto spctl; do command -v "$t" >/dev/null 2>&1 || missing="$missing $t"; done
  if ! xcrun --find notarytool >/dev/null 2>&1; then missing="$missing notarytool(xcode-select --install)"; fi
  command -v SetFile >/dev/null 2>&1 || warn "SetFile not found (Xcode command line tools): the DMG gets no volume icon."
fi
if [ -n "$missing" ]; then
  if [ "$dry" -eq 1 ] && [ "$on_mac" -eq 0 ]; then warn "tools missing here (dry run, not macOS):$missing"
  else die "missing tools:$missing"; fi
else
  ok "all required tools found"
fi
for f in release_macos.sh sign_app_macos.sh entitlements.plist; do
  [ -f "$here/$f" ] || die "missing in the repository: scripts/$f"
done

# =================================================================================================
step "2/9 Check GitHub access"
command -v gh >/dev/null 2>&1 || die "GitHub CLI (gh) not installed. Install it: brew install gh"
if ! gh auth status >/dev/null 2>&1; then
  die "GitHub CLI is not logged in. Run once: gh auth login   (GitHub.com, HTTPS, browser; account with write access)"
fi
ok "gh is logged in"
if [ -z "$repo_slug" ]; then
  repo_slug=$(cd "$repo" && gh repo view --json nameWithOwner --jq .nameWithOwner 2>/dev/null) \
    || die "could not determine the GitHub repository from the git remote. Pass --repo OWNER/NAME."
fi
printf '%s' "$repo_slug" | grep -Eq '^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$' || die "invalid repository name: $repo_slug"
info "Repository: $repo_slug"
can_push=$(gh api "repos/$repo_slug" --jq '.permissions.push' 2>/dev/null || true)
[ "$can_push" = "true" ] || die "no write access to $repo_slug with the current gh login (permissions.push='$can_push')."
ok "write access to $repo_slug"

# =================================================================================================
step "3/9 Find the release draft"
releases_q() { gh api "repos/$repo_slug/releases?per_page=100" --jq "$1"; }
if [ -z "$tag" ]; then
  drafts=$(retry 3 5 releases_q '.[] | select(.draft) | .tag_name') || die "could not list releases"
  n=$(printf '%s\n' "$drafts" | grep -c . || true)
  if [ "$n" = "0" ]; then die "no release draft found in $repo_slug. Push a tag vX.Y.Z first; the workflow creates the draft."; fi
  if [ "$n" != "1" ]; then die "several release drafts exist; name one: scripts/publish_release.sh <tag>
$drafts"; fi
  tag=$(printf '%s' "$drafts" | head -n 1)
  printf '%s' "$tag" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z.]+)?$' || die "draft tag '$tag' does not look like vX.Y.Z"
  info "Exactly one draft exists: $tag"
fi
info "Tag: $tag"
jq_prog='.[] | select(.tag_name=="'"$tag"'") | "R\t\(.id)\t\(.draft)\t\(.html_url)", (.assets[] | "A\t\(.id)\t\(.name)\t\(.size)\t\(.state)\t\(.digest // "")")'
listing=$(retry 3 5 releases_q "$jq_prog") || die "could not read the release for $tag"
rel_lines=$(printf '%s\n' "$listing" | grep -c '^R' || true)
[ "$rel_lines" -ge 1 ] || die "no release found for tag $tag in $repo_slug (has the release workflow finished? gh run list --workflow release.yml)"
[ "$rel_lines" -eq 1 ] || die "$rel_lines releases carry the tag $tag; clean this up on GitHub first."
rel_id=$(printf '%s\n' "$listing" | awk -F'\t' '$1=="R"{print $2}')
rel_draft=$(printf '%s\n' "$listing" | awk -F'\t' '$1=="R"{print $3}')
rel_url=$(printf '%s\n' "$listing" | awk -F'\t' '$1=="R"{print $4}')
[ "$rel_draft" = "true" ] || die "release $tag is already PUBLISHED. This script only works on drafts and never changes a published release."
ok "draft release $tag (id $rel_id)"
info "Assets in the draft:"
printf '%s\n' "$listing" | awk -F'\t' '$1=="A"{printf "  %-34s %10s bytes  %s\n", $3, $4, $5}'
asset_id()   { printf '%s\n' "$listing" | awk -F'\t' -v n="$1" '$1=="A" && $3==n {print $2}'; }
asset_size() { printf '%s\n' "$listing" | awk -F'\t' -v n="$1" '$1=="A" && $3==n {print $4}'; }
for a in arm64 x64; do
  [ -n "$(asset_id "nsviz-macos-$a-app.zip")" ] || {
    if [ -n "$(asset_id "nsviz-macos-$a.dmg")" ]; then
      die "the draft has no unsigned nsviz-macos-$a-app.zip any more, but a nsviz-macos-$a.dmg. Looks like an earlier run already replaced it. To redo it, upload the unsigned ZIP to the draft again (copies of an earlier run: $REL/$tag/input/, or re-run the release workflow)."
    fi
    die "asset nsviz-macos-$a-app.zip is missing in the draft."
  }
done
ok "both unsigned app bundles are in the draft"

# =================================================================================================
step "4/9 Find signing identity and notary profile"
identity="${NSVIZ_SIGN_IDENTITY:-}"
if [ "$on_mac" -eq 1 ]; then
  if [ -n "$identity" ]; then
    info "Signing identity from NSVIZ_SIGN_IDENTITY: $identity"
  else
    idlist=$(security find-identity -v -p codesigning 2>/dev/null | sed -n 's/.*"\(Developer ID Application: [^"]*\)".*/\1/p' | sort -u)
    n=$(printf '%s\n' "$idlist" | grep -c . || true)
    if [ "$n" = "0" ]; then
      die "no 'Developer ID Application' identity (with private key) in the keychain. Check: security find-identity -v -p codesigning
(see docs/SIGNING.md, Prerequisites; the keychain may be locked or the private key missing)"
    fi
    if [ "$n" != "1" ]; then
      die "several Developer ID Application identities found; choose one with: export NSVIZ_SIGN_IDENTITY=\"<name>\"
$idlist"
    fi
    identity=$idlist
    info "Signing identity (automatic): $identity"
  fi
  security find-identity -v -p codesigning 2>/dev/null | grep -qF "$identity" \
    || die "identity '$identity' is not a valid codesigning identity in the keychain."
  ok "signing identity valid"
  notary_check() { xcrun notarytool history --keychain-profile "$profile" >/dev/null 2>&1; }
  if ! retry 3 10 notary_check; then
    die "notarytool cannot use the keychain profile '$profile' (profile missing, credentials revoked, or no network to Apple).
Create or renew it once (docs/SIGNING.md, step 3):
  xcrun notarytool store-credentials \"$profile\" --apple-id \"<Apple ID>\" --team-id \"<team ID>\""
  fi
  ok "notary profile '$profile' works"
else
  warn "not macOS: identity and notary profile are not checked (dry run)"
fi
mac_free_kb=$(df -Pk "$(dirname "$REL")" 2>/dev/null | awk 'NR==2{print $4}' || true)
if [ -n "${mac_free_kb:-}" ] && [ "$mac_free_kb" -lt 2097152 ]; then
  die "less than 2 GB free disk space in $(dirname "$REL")."
fi

# ---- dry run ends here --------------------------------------------------------------------------
T="$REL/$tag"
if [ "$dry" -eq 1 ]; then
  step "5/9 Plan (dry run)"
  cat <<EOF
Would do, in this order:
  - create/clean $T and $REL/logs, start the log file
  - download nsviz-macos-arm64-app.zip and nsviz-macos-x64-app.zip from draft $tag, check size and Mach-O architecture
  - per architecture: scripts/release_macos.sh --arch <arch> --app <zip> --out $T --profile $profile
    (sign nested files + bundle, build DMG with volume icon, sign, notarize with retries, staple, validate)
  - re-verify both DMGs (codesign, stapler, SHA-256) and write the merged SHA256SUMS.txt
    (keep the lines of the draft's file that are not nsviz-macos-*, add the lines of the two DMGs)
  - upload nsviz-macos-arm64.dmg, nsviz-macos-x64.dmg, SHA256SUMS.txt to the draft (replacing same-named assets),
    verify size/state/digest of each upload
  - remove nsviz-macos-arm64-app.zip and nsviz-macos-x64-app.zip from the draft
  - check that the release is still a draft; never publish
EOF
  ok "dry run finished: all checks passed, nothing was changed"
  exit 0
fi

# =================================================================================================
step "5/9 Prepare release folder"
case "$tag" in v[0-9]*) ;; *) die "internal error: unexpected tag" ;; esac
mkdir -p "$T"
T=$(cd "$T" && pwd -P)
case "$T" in "$REL"/v*) ;; *) die "internal error: unexpected release folder $T" ;; esac
# Only products of this script are removed, so a re-run starts clean.
rm -rf "$T/input" "$T/upload" "$T/work"
rm -f "$T"/nsviz-macos-*.dmg "$T/SHA256SUMS.txt"
mkdir -p "$T/input" "$T/upload"
ok "folder $T is clean"

# =================================================================================================
step "6/9 Download unsigned app bundles and checksums from the draft"
download_asset() {  # name  -> $T/input/name, size checked against the draft listing
  local name=$1 id want got dest="$T/input/$1"
  id=$(asset_id "$name"); want=$(asset_size "$name")
  rm -f "$dest" "$dest.part"
  if ! gh api -H "Accept: application/octet-stream" "repos/$repo_slug/releases/assets/$id" > "$dest.part" 2>/dev/null; then
    warn "API download of $name failed; trying gh release download"
    rm -f "$dest.part"
    gh release download "$tag" --repo "$repo_slug" --pattern "$name" --dir "$T/input" --clobber >/dev/null 2>&1 || return 1
  else
    mv "$dest.part" "$dest"
  fi
  got=$(wc -c < "$dest" | tr -d ' ')
  [ "$got" = "$want" ] || { warn "size mismatch for $name: got $got, expected $want"; rm -f "$dest"; return 1; }
}
for name in nsviz-macos-arm64-app.zip nsviz-macos-x64-app.zip; do
  retry 3 10 download_asset "$name" || die "download of $name failed (see warnings above)"
  ok "$name ($(wc -c < "$T/input/$name" | tr -d ' ') bytes)"
done
have_sums=0
if [ -n "$(asset_id SHA256SUMS.txt)" ]; then
  retry 3 10 download_asset SHA256SUMS.txt || die "download of SHA256SUMS.txt failed"
  have_sums=1
  ok "SHA256SUMS.txt of the draft (kept as backup in $T/input)"
else
  warn "the draft has no SHA256SUMS.txt; the new file will contain only the macOS lines."
fi

# =================================================================================================
step "7/9 Sign, build DMGs, notarize, staple (release_macos.sh, one run per architecture)"
for a in arm64 x64; do
  info "---- architecture $a ----"
  NSVIZ_SIGN_IDENTITY="$identity" "$here/release_macos.sh" --arch "$a" --app "$T/input/nsviz-macos-$a-app.zip" \
    --out "$T" --profile "$profile" || die "release_macos.sh failed for $a (intermediate files kept in $T/work/$a)"
  [ -f "$T/nsviz-macos-$a.dmg" ] || die "release_macos.sh finished without producing nsviz-macos-$a.dmg"
  note_result "  signed + notarized: nsviz-macos-$a.dmg"
done

# =================================================================================================
step "8/9 Re-verify DMGs and merge checksums"
for a in arm64 x64; do
  d="$T/nsviz-macos-$a.dmg"
  codesign --verify --strict --verbose=2 "$d" || die "signature check failed: $d"
  xcrun stapler validate "$d" || die "staple check failed: $d"
  ok "$(basename "$d"): signature and notarization ticket valid"
done
macos_lines=$(cd "$T" && shasum -a 256 nsviz-macos-arm64.dmg nsviz-macos-x64.dmg)
kept=""
if [ "$have_sums" -eq 1 ]; then
  kept=$(grep -v 'nsviz-macos-' "$T/input/SHA256SUMS.txt" || true)
  [ -n "$kept" ] || warn "the draft's SHA256SUMS.txt had no non-macOS line (no Windows entry?). Check the merged file."
fi
{ [ -z "$kept" ] || printf '%s\n' "$kept"; printf '%s\n' "$macos_lines"; } > "$T/upload/SHA256SUMS.txt"
info "Merged SHA256SUMS.txt:"
sed 's/^/  /' "$T/upload/SHA256SUMS.txt"
cp "$T/upload/SHA256SUMS.txt" "$T/SHA256SUMS.txt"
note_result "  merged SHA256SUMS.txt (kept $(printf '%s\n' "$kept" | grep -c . || true) non-macOS line(s))"

if [ "$no_upload" -eq 1 ]; then
  step "9/9 Upload skipped (--no-upload)"
  info "Signed files: $T"
  note_result "  upload skipped (--no-upload); files are in $T"
  exit 0
fi

# =================================================================================================
step "9/9 Upload to the draft, verify, remove unsigned ZIPs"
refresh_listing() { listing=$(releases_q "$jq_prog"); [ -n "$listing" ]; }
delete_asset() {  # name: delete all assets with that name (also half-uploaded ones)
  local id
  for id in $(asset_id "$1"); do
    info "Deleting asset $1 (id $id) from the draft"
    gh api -X DELETE "repos/$repo_slug/releases/assets/$id" >/dev/null
  done
}
upload_asset() {  # file name
  local file=$1 name=$2
  info "Uploading $name ($(wc -c < "$file" | tr -d ' ') bytes)"
  if gh api -X POST "https://uploads.github.com/repos/$repo_slug/releases/$rel_id/assets?name=$name" \
       -H "Content-Type: application/octet-stream" --input "$file" >/dev/null; then
    return 0
  fi
  warn "API upload of $name failed; trying gh release upload"
  # Clean a possibly half-uploaded asset, then use the CLI with the file under its final name.
  refresh_listing || true
  delete_asset "$name" || true
  ( cd "$(dirname "$file")" && [ "$(basename "$file")" = "$name" ] ) \
    || { cp "$file" "$T/upload/$name"; file="$T/upload/$name"; }
  gh release upload "$tag" "$file" --repo "$repo_slug" --clobber >/dev/null
}
upload_one() {  # file name: remove an old asset of the same name, upload, retry as a whole
  local file=$1 name=$2
  refresh_listing || return 1
  delete_asset "$name" || return 1
  upload_asset "$file" "$name"
}
for a in arm64 x64; do
  retry 3 15 upload_one "$T/nsviz-macos-$a.dmg" "nsviz-macos-$a.dmg" \
    || die "upload of nsviz-macos-$a.dmg failed. The signed file is in $T; run again."
done
retry 3 15 upload_one "$T/upload/SHA256SUMS.txt" "SHA256SUMS.txt" \
  || die "upload of SHA256SUMS.txt failed. The original is saved as $T/input/SHA256SUMS.txt; run again."

step_now="Verify upload"
retry 3 10 refresh_listing || die "could not re-read the draft after the upload"
verify_one() {  # file name
  local file=$1 name=$2 want got state dig wantsha
  want=$(wc -c < "$file" | tr -d ' ')
  got=$(asset_size "$name"); state=$(printf '%s\n' "$listing" | awk -F'\t' -v n="$name" '$1=="A" && $3==n {print $5}')
  dig=$(printf '%s\n' "$listing" | awk -F'\t' -v n="$name" '$1=="A" && $3==n {print $6}')
  [ "$state" = "uploaded" ] || die "$name in the draft has state '${state:-missing}' (expected uploaded)"
  [ "$got" = "$want" ] || die "$name in the draft has $got bytes, local file has $want"
  if [ -n "$dig" ]; then
    wantsha=$(shasum -a 256 "$file" | awk '{print $1}')
    [ "$dig" = "sha256:$wantsha" ] || die "$name in the draft has digest $dig, local file sha256:$wantsha"
  fi
  ok "$name uploaded and verified (size$([ -n "$dig" ] && printf ', sha256'))"
}
verify_one "$T/nsviz-macos-arm64.dmg" nsviz-macos-arm64.dmg
verify_one "$T/nsviz-macos-x64.dmg"   nsviz-macos-x64.dmg
verify_one "$T/upload/SHA256SUMS.txt" SHA256SUMS.txt
note_result "  uploaded + verified: nsviz-macos-arm64.dmg, nsviz-macos-x64.dmg, SHA256SUMS.txt"

step_now="Remove unsigned ZIPs from the draft"
for name in nsviz-macos-arm64-app.zip nsviz-macos-x64-app.zip; do
  retry 3 10 delete_asset "$name" || warn "could not delete $name from the draft; delete it by hand on GitHub."
done
note_result "  removed unsigned app ZIPs from the draft"

step_now="Final check"
retry 3 10 refresh_listing || die "could not re-read the draft"
still=$(printf '%s\n' "$listing" | awk -F'\t' '$1=="R"{print $3}')
[ "$still" = "true" ] || die "the release is not a draft any more. The script never publishes; check it on GitHub."
info "Assets in the draft now:"
printf '%s\n' "$listing" | awk -F'\t' '$1=="A"{printf "  %-34s %10s bytes  %s\n", $3, $4, $5}'
note_result "  release $tag is still a DRAFT: $rel_url"
info ""
info "Next (by hand): add the note that the macOS files are signed and notarized, review the release notes, then publish."
