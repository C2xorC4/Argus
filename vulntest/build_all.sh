#!/usr/bin/env bash
# Build vuln + remediation binaries for VulnTest cells using MSVC.
#
# Bypasses the per-cell Makefiles (which target MinGW-w64) and invokes
# cl.exe through vcvars64 directly. Generates one batch file with all
# compile commands and runs it once so vcvars64 is sourced a single
# time.
#
# Flags: /Od /Zi /DUNICODE /D_UNICODE /MD, /SUBSYSTEM:CONSOLE.
# Always links advapi32 + user32 + kernel32 + ws2_32 (unreferenced
# libs are silently ignored by the linker, so this is safe across
# all tier1-single + tier2-chains cells).
#
# Usage:
#   build_all.sh                 # build all C/C++ cells
#   build_all.sh permissive-sddl # build cells whose path matches substring
#   build_all.sh --vuln-only     # skip remediation/ binaries

set -uo pipefail

ROOT=$(cd "$(dirname "$0")" && pwd)
VCVARS='C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat'

if [[ ! -f "/c/Program Files/Microsoft Visual Studio/2022/Community/VC/Auxiliary/Build/vcvars64.bat" ]]; then
    echo "vcvars64.bat not found at expected path; edit VCVARS in $0" >&2
    exit 2
fi

VULN_ONLY=0
FILTER=""
for arg in "$@"; do
    case "$arg" in
        --vuln-only) VULN_ONLY=1 ;;
        --help|-h) sed -n '2,17p' "$0"; exit 0 ;;
        *) FILTER="$arg" ;;
    esac
done

BATCH="$ROOT/.build_generated.bat"
trap 'rm -f "$BATCH"' EXIT

# Discover (src, out) pairs from tier1-single and tier2-chains.
PAIRS=()
while IFS= read -r src; do
    if [[ -n "$FILTER" && "$src" != *"$FILTER"* ]]; then
        continue
    fi
    case "$src" in
        */source/vuln.c|*/source/vuln.cpp)
            cell=$(dirname "$(dirname "$src")")
            out="$cell/build/vuln.exe"
            ;;
        */remediation/vuln.c|*/remediation/vuln.cpp)
            [[ "$VULN_ONLY" -eq 1 ]] && continue
            cell=$(dirname "$src")
            out="$cell/build/vuln.exe"
            ;;
        *) continue ;;
    esac
    mkdir -p "$(dirname "$out")"
    PAIRS+=("$src|$out")
done < <(find "$ROOT/tier1-single" "$ROOT/tier2-chains" \
              \( -name vuln.c -o -name vuln.cpp \) 2>/dev/null)

if [[ ${#PAIRS[@]} -eq 0 ]]; then
    echo "No source files matched (filter='$FILTER')."
    exit 1
fi

echo "Building ${#PAIRS[@]} target(s)..."

# Generate one batch script that calls vcvars64 once then compiles
# each pair. Any failures increment FAILED; final exit code = FAILED.
{
    echo '@echo off'
    echo 'setlocal enableextensions enabledelayedexpansion'
    echo "call \"$VCVARS\" >nul"
    echo 'if errorlevel 1 ( echo vcvars64 failed & exit /b 1 )'
    echo 'set FAILED=0'
    for pair in "${PAIRS[@]}"; do
        src="${pair%%|*}"
        out="${pair##*|}"
        win_src=$(cygpath -w "$src")
        win_out=$(cygpath -w "$out")
        win_outdir=$(cygpath -w "$(dirname "$out")")
        rel="${src#"$ROOT/"}"
        echo "echo [cl] $rel"
        echo "pushd \"$win_outdir\" >nul"
        echo "cl /nologo /Od /Zi /DUNICODE /D_UNICODE /MD /EHsc /Fe:\"$win_out\" \"$win_src\" advapi32.lib user32.lib kernel32.lib ws2_32.lib bcrypt.lib /link /SUBSYSTEM:CONSOLE > \"$win_out.log\" 2>&1"
        echo "if errorlevel 1 ( echo     FAILED ^(see $rel.log^) & set /a FAILED+=1 ) else ( del \"$win_out.log\" >nul 2>&1 )"
        echo "popd >nul"
    done
    echo 'echo.'
    echo 'if %FAILED% gtr 0 ( echo %FAILED% target^(s^) failed & exit /b %FAILED% )'
    echo 'echo all targets built'
    echo 'exit /b 0'
} > "$BATCH"

WIN_BATCH=$(cygpath -w "$BATCH")
cmd //c "$WIN_BATCH"
RC=$?
exit "$RC"
