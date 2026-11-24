#!/usr/bin/env bash
# Guided release: check, tag, wait for the build, sign (publish_release.sh), publish. Every step that changes
# something outside this folder asks for an explicit confirmation at the terminal, so nothing is tagged or published
# by accident. Run it on the signing Mac, inside the checkout, on the branch main.
#
# Usage:
#   scripts/release.sh               # version taken from nsviz/__init__.py, tag vX.Y.Z
#   scripts/release.sh --dry-run     # all checks and the release text, changes nothing
#
# Steps:
#   1 Checks   on main, clean tree, in sync with origin, CHANGELOG section for the version, CI green on this commit,
#              tag does not exist yet. Stops with a clear message otherwise.
#   2 Tag      after you type the tag name: annotated tag, pushed to origin (starts the release workflow).
#   3 Build    waits for the "Release builds" run of the tag and for the release draft.
#   4 Sign     runs scripts/publish_release.sh (signs, notarizes, uploads to the draft).
#   5 Publish  shows the release text and the files; after you type the tag name again the draft is published.
#   6 Verify   checks that the published release has the four expected files and that the checksums match.
# Re-running after an error continues sensibly: an existing tag is detected, an existing draft is reused.
# The script holds no credentials; it uses your git and gh logins.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd -P)
repo=$(cd "$here/.." && pwd -P)
cd "$repo"
dry=0
case "${1:-}" in
  --dry-run) dry=1 ;;
  "") ;;
  -h|--help) sed -n '2,/^set -euo/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//'; exit 0 ;;
  *) echo "unknown argument: $1" >&2; exit 2 ;;
esac

step() { printf '\n==> %s\n' "$*"; }
ok()   { printf 'OK: %s\n' "$*"; }
die()  { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
confirm() {  # confirm <what> <word to type>
  local answer
  if [ "$dry" -eq 1 ]; then echo "(dry run: would ask you to type '$2' to $1)"; return 0; fi
  printf '\n%s\nType "%s" to continue, anything else aborts: ' "$1" "$2"
  read -r answer || answer=""
  [ "$answer" = "$2" ] || die "aborted by you, nothing changed in this step."
}

step "1/6 Checks"
for t in git gh; do command -v "$t" >/dev/null 2>&1 || die "$t not found"; done
gh auth status >/dev/null 2>&1 || die "gh is not logged in (gh auth login)"
slug=$(gh repo view --json nameWithOwner --jq .nameWithOwner) || die "cannot determine the GitHub repository"
version=$(sed -n 's/^__version__ *= *"\([^"]*\)".*/\1/p' nsviz/__init__.py)
printf '%s' "$version" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$' || die "no version x.y.z in nsviz/__init__.py"
tag="v$version"
echo "Repository $slug, version $version, tag $tag"

[ "$(git branch --show-current)" = "main" ] || die "not on branch main (use: git switch main)"
[ -z "$(git status --porcelain)" ] || die "the working tree has uncommitted changes; commit or stash them first"
git fetch -q origin main --tags
[ "$(git rev-parse HEAD)" = "$(git rev-parse origin/main)" ] || die "main differs from origin/main (git pull --ff-only, or push first)"
ok "on main, clean, in sync with origin ($(git rev-parse --short HEAD))"

sec=$(awk -v v="$version" '$0 ~ "^## \\["v"\\]"{f=1;next} /^## \[/{f=0} f' CHANGELOG.md)
[ -n "$(printf '%s' "$sec" | tr -d '[:space:]')" ] || die "CHANGELOG.md has no filled section '## [$version]'"
ok "CHANGELOG section for $version found ($(printf '%s\n' "$sec" | grep -c .) lines)"

sha=$(git rev-parse HEAD)
ci=$(gh api "repos/$slug/commits/$sha/check-runs?per_page=100" --jq '[.check_runs[]|select(.name|startswith("test"))]|[length, (map(select(.conclusion=="success"))|length)]|@tsv')
total=${ci%%$'\t'*}; good=${ci##*$'\t'}
{ [ "$total" -gt 0 ] && [ "$total" = "$good" ]; } || die "CI is not green on $sha ($good of $total test jobs succeeded). Wait for CI or fix it."
ok "CI green on this commit ($good of $total test jobs)"

tag_local=0; git rev-parse -q --verify "refs/tags/$tag" >/dev/null && tag_local=1
tag_remote=$(git ls-remote --tags origin "refs/tags/$tag" | wc -l | tr -d ' ')
if [ "$tag_remote" != "0" ]; then
  tagsha=$(git rev-parse "$tag^{commit}" 2>/dev/null || true)
  [ "$tagsha" = "$sha" ] || die "tag $tag already exists on origin but not on this commit; bump the version instead"
  ok "tag $tag already exists on origin at this commit; step 2 is skipped"
elif [ "$tag_local" = "1" ]; then
  die "tag $tag exists locally but not on origin; check it (git tag -d $tag removes it) and run again"
fi
pub=$(gh api "repos/$slug/releases?per_page=100" --jq '.[]|select(.tag_name=="'"$tag"'")|.draft' | head -n 1)
[ "$pub" != "false" ] || die "release $tag is already published"

notes=$(mktemp); trap 'rm -f "$notes"' EXIT
{
  echo "## nsviz $version"
  echo
  printf '%s\n' "$sec" | sed '1{/^$/d;}'
  cat <<EOF

## Downloads
| File | For |
|---|---|
| \`nsviz-macos-arm64.dmg\` | macOS, Apple silicon (M1 or newer) |
| \`nsviz-macos-x64.dmg\` | macOS, Intel |
| \`nsviz-windows-x64.exe\` | Windows 64-bit (not code-signed) |
| \`SHA256SUMS.txt\` | SHA-256 checksums of the three files |

**macOS:** open the DMG, drag nsviz to Applications and start it. The app is signed and notarized; on the first start macOS asks once whether to open an app downloaded from the internet, confirm with *Open*. The command line is part of the app: \`/Applications/nsviz.app/Contents/MacOS/nsviz\`.

**Windows:** SmartScreen shows "Windows protected your PC" on the first start. Select *More info*, then *Run anyway*.

Compare the SHA-256 checksum with the downloaded file before you start it. Full history: [CHANGELOG.md](CHANGELOG.md).
EOF
} > "$notes"
echo "--- release text (from CHANGELOG) ---"; cat "$notes"; echo "--- end ---"

if [ "$dry" -eq 1 ]; then
  echo; echo "Dry run: next would be tag $tag (step 2), wait for the build (3), scripts/publish_release.sh (4), publish (5), verify (6)."
  exit 0
fi

step "2/6 Tag"
if [ "$tag_remote" = "0" ]; then
  confirm "Create the tag $tag on $(git rev-parse --short HEAD) and push it to origin. This starts the release build." "$tag"
  git tag -a "$tag" -m "$tag"
  git push origin "refs/tags/$tag"
  ok "tag $tag pushed"
fi

step "3/6 Wait for the release build (about 10 minutes)"
deadline=$(( $(date +%s) + 2400 ))
while :; do
  d=$(gh api "repos/$slug/releases?per_page=100" --jq '.[]|select(.tag_name=="'"$tag"'" and .draft)|.id' | head -n 1)
  [ -z "$d" ] || break
  run=$(gh api "repos/$slug/actions/runs?per_page=20&event=push" --jq '[.workflow_runs[]|select(.head_branch=="'"$tag"'")][0]|[.status,.conclusion]|@tsv' 2>/dev/null || true)
  case "$run" in *failure*|*cancelled*) die "the release workflow for $tag failed or was cancelled: gh run list --workflow release.yml" ;; esac
  [ "$(date +%s)" -lt "$deadline" ] || die "no release draft after 40 minutes; look at gh run list --workflow release.yml"
  printf '  waiting ... (%s)\n' "${run:-no run yet}"; sleep 30
done
ok "release draft exists"

step "4/6 Sign, notarize, upload (publish_release.sh)"
"$here/publish_release.sh" "$tag"

step "5/6 Publish"
gh api "repos/$slug/releases?per_page=100" --jq '.[]|select(.tag_name=="'"$tag"'")|.assets[]|"  \(.name)  \(.size) bytes"'
confirm "Publish release $tag with the text above. Published releases are public." "$tag"
rid=$(gh api "repos/$slug/releases?per_page=100" --jq '.[]|select(.tag_name=="'"$tag"'" and .draft)|.id' | head -n 1)
[ -n "$rid" ] || die "the draft for $tag is gone; check GitHub"
gh api -X PATCH "repos/$slug/releases/$rid" -F body=@"$notes" -F draft=false -f name="nsviz $version" -f make_latest=true --jq '.html_url'

step "6/6 Verify"
names=$(gh api "repos/$slug/releases/tags/$tag" --jq '[.assets[].name]|sort|join(" ")')
want="SHA256SUMS.txt nsviz-macos-arm64.dmg nsviz-macos-x64.dmg nsviz-windows-x64.exe"
[ "$names" = "$want" ] || die "published release has: $names (expected: $want)"
ok "published with the four expected files"
echo "Done. Release: https://github.com/$slug/releases/tag/$tag"
