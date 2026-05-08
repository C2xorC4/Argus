#!/bin/bash
# Test each candidate key against the encrypted PCK with gdre_tools
PCK="/tmp/gdre/Platformer2D.pck"
GDRE="/tmp/gdre/gdre_tools.x86_64"
OUT_BASE="/tmp/gdre_test"
CANDS="/mnt/d/Repos/Security/Argus/vulntest/validation/htb/challenges/reversing/GameLoader/cands.txt"

mkdir -p "$OUT_BASE"
i=0
grep -E "^[0-9a-f]{64}" "$CANDS" | awk '{print $1}' | sort -u | while read key; do
    i=$((i+1))
    out="$OUT_BASE/test_$i"
    rm -rf "$out"
    cd /tmp/gdre
    # Try as recover with --key. Suppress most output, check for success.
    result=$(timeout 10 "$GDRE" --headless --recover="$PCK" --output="$out" --key="$key" --quiet 2>&1 | tail -3)
    if echo "$result" | grep -qi "success\|extracted\|exported"; then
        echo "FOUND key=$key (test $i)"
        ls -la "$out" 2>/dev/null | head -10
        break
    fi
    if [ $((i % 20)) -eq 0 ]; then
        echo "  tried $i candidates so far..." >&2
    fi
done
