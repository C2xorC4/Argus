#!/usr/bin/env bash
# Tier-3 transform: produce a symbol-stripped variant of the
# stack-overflow / C Tier-1 cell.
set -euo pipefail

SOURCE="../../tier1-single/stack-overflow/c"
OUT="build"

make -C "$SOURCE"
mkdir -p "$OUT"

# pick the right artefact for the platform
if [ -f "$SOURCE/build/vuln.exe" ]; then
    cp "$SOURCE/build/vuln.exe" "$OUT/vuln.exe"
    target="$OUT/vuln.exe"
else
    cp "$SOURCE/build/vuln" "$OUT/vuln"
    target="$OUT/vuln"
fi

strip --strip-all "$target"      # remove symbol tables
objcopy --strip-debug "$target"  # remove DWARF, if any

echo "stripped: $target"
