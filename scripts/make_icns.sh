#!/bin/sh
# Creates a macOS icon (.icns) from the SVG source. Needs macOS (iconutil) and rsvg-convert (brew install librsvg).
# Usage: scripts/make_icns.sh [assets/nsviz-icon.svg] [output.icns]
# The .icns is a build product and is never committed; the release workflow creates it for the app bundle.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
svg=${1:-$here/../assets/nsviz-icon.svg}
out=${2:-nsviz.icns}
[ -f "$svg" ] || { echo "ERROR: SVG not found: $svg" >&2; exit 1; }
command -v rsvg-convert >/dev/null 2>&1 || { echo "ERROR: rsvg-convert not found (brew install librsvg)" >&2; exit 1; }
command -v iconutil >/dev/null 2>&1 || { echo "ERROR: iconutil not found (needs macOS)" >&2; exit 1; }
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
set_dir="$tmp/nsviz.iconset"
mkdir "$set_dir"
for s in 16 32 128 256 512; do
  d=$((s * 2))
  rsvg-convert -w "$s" -h "$s" "$svg" -o "$set_dir/icon_${s}x${s}.png"
  rsvg-convert -w "$d" -h "$d" "$svg" -o "$set_dir/icon_${s}x${s}@2x.png"
done
iconutil -c icns "$set_dir" -o "$out"
echo "Created $out"
