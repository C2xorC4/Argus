#!/usr/bin/env bash
# Tier-3 transform: produce a symbol-stripped variant of the
# stack-overflow / C Tier-1 cell. The point is to verify the
# detector's structural recognition survives without function /
# symbol names.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SOURCE="$SCRIPT_DIR/../../tier1-single/stack-overflow/c"
OUT="$SCRIPT_DIR/build"
mkdir -p "$OUT"

if [ -f "$SOURCE/build/vuln.exe" ]; then
    # Windows PE: MSVC keeps symbols in a sibling .pdb file. Copy
    # the .exe but NOT the .pdb — Binja can no longer correlate
    # function names from PDB, simulating a stripped build.
    cp "$SOURCE/build/vuln.exe" "$OUT/vuln.exe"
    target="$OUT/vuln.exe"
    echo "stripped (PDB-omitted): $target"
elif [ -f "$SOURCE/build/vuln" ]; then
    # ELF: try GNU binutils. Fall back to bare copy if tools absent.
    cp "$SOURCE/build/vuln" "$OUT/vuln"
    target="$OUT/vuln"
    if command -v strip >/dev/null 2>&1; then
        strip --strip-all "$target"
    fi
    if command -v objcopy >/dev/null 2>&1; then
        objcopy --strip-debug "$target"
    fi
    echo "stripped: $target"
else
    echo "source binary not built at $SOURCE/build/vuln{.exe,}" >&2
    exit 1
fi
