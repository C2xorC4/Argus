#!/bin/bash
cd "$(dirname "$0")"
for year in 2020 2021 2025 2026 2019 2018 2027; do
  for len in 8 10 12 14 18 22 25 26 30 36 40 44; do
    for sym in 0 1; do
      for num in 0 1; do
        echo "=== year=$year len=$len sym=$sym num=$num ===" >&2
        out=$(./bruteforce "$year" "$len" "$sym" "$num" 2>/dev/null)
        if echo "$out" | grep -q "FOUND"; then
          echo "$out"
          exit 0
        fi
      done
    done
  done
done
echo "no match found"
