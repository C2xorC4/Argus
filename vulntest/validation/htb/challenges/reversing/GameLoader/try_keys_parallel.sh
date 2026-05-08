#!/bin/bash
PCK="/tmp/gdre/Platformer2D.pck"
GDRE="/tmp/gdre/gdre_tools.x86_64"
CANDS="/mnt/d/Repos/Security/Argus/vulntest/validation/htb/challenges/reversing/GameLoader/cands.txt"
RESULT_FILE="/tmp/gdre_found_key.txt"
rm -f "$RESULT_FILE"

test_key() {
    local key="$1"
    local idx="$2"
    local out="/tmp/gdre_test_$idx"
    [ -f "$RESULT_FILE" ] && return
    rm -rf "$out"
    cd /tmp/gdre
    out_log=$(timeout 8 "$GDRE" --headless --recover="$PCK" --output="$out" --key="$key" --quiet 2>&1)
    if ! echo "$out_log" | grep -qiE "wrong key|invalid|Cannot open encrypted|FATAL"; then
        # Maybe success
        echo "[CANDIDATE WIN] $key" | tee -a "$RESULT_FILE"
        echo "$out_log" | head -10 >> "$RESULT_FILE"
        ls "$out" 2>&1 | head -5 >> "$RESULT_FILE"
    fi
    rm -rf "$out"
}

export -f test_key
export PCK GDRE RESULT_FILE

idx=0
keys=$(grep -E "^[0-9a-f]{64}" "$CANDS" | awk '{print $1}' | sort -u)
total=$(echo "$keys" | wc -l)
echo "Testing $total unique candidates..." >&2

echo "$keys" | while read key; do
    idx=$((idx+1))
    if [ -f "$RESULT_FILE" ]; then
        echo "Found! breaking" >&2
        break
    fi
    if [ $((idx % 25)) -eq 0 ]; then
        echo "  $idx/$total tested" >&2
    fi
    test_key "$key" "$idx"
done

if [ -f "$RESULT_FILE" ]; then
    cat "$RESULT_FILE"
else
    echo "no key found in $total candidates"
fi
