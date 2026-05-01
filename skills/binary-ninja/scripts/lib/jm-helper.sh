#!/usr/bin/env bash
# Argus — `jm` integration helper for agent bash quick-reference blocks.
#
# Bash equivalent of scripts/lib/knowledge.py for use in agent prose
# pre-flight retrieval:
#
#   source $ARGUS_ROOT/skills/binary-ninja/scripts/lib/jm-helper.sh
#   argus_kb_retrieve "binary vulnerability identification" "taint,heap,injection" /tmp/kb.json
#
# Falls back to D:\Repos\LLM\LittleJohnnyMnemonic\agent\jm.exe if `jm`
# is not on PATH and ARGUS_JM_PATH is not set.

set -u

argus_jm_path() {
    if [[ -n "${ARGUS_JM_PATH:-}" ]]; then
        echo "$ARGUS_JM_PATH"
        return 0
    fi
    if command -v jm >/dev/null 2>&1; then
        command -v jm
        return 0
    fi
    if command -v jm.exe >/dev/null 2>&1; then
        command -v jm.exe
        return 0
    fi
    local default='/d/Repos/LLM/LittleJohnnyMnemonic/agent/jm.exe'
    if [[ -x "$default" ]]; then
        echo "$default"
        return 0
    fi
    echo "argus_jm_path: jm CLI not found" >&2
    return 1
}

# Pre-flight retrieval. Writes JSON output to $3 (or stdout if $3 empty).
#
#   argus_kb_retrieve "<intent>" "<comma-tags>" "[<output-path>]" "[<limit>]" "[--full]"
argus_kb_retrieve() {
    local intent="${1:-}"
    local tags="${2:-}"
    local out="${3:-}"
    local limit="${4:-10}"
    local extra="${5:-}"

    local jm
    jm="$(argus_jm_path)" || return 1

    local args=(retrieve --intent "$intent" --format json --limit "$limit")
    [[ -n "$tags" ]] && args+=(--tags "$tags")
    [[ "$extra" == "--full" ]] && args+=(--full)

    if [[ -n "$out" ]]; then
        "$jm" "${args[@]}" > "$out"
    else
        "$jm" "${args[@]}"
    fi
}

# Free-text association — for substrate-coherence checks against
# generated Findings.
#
#   argus_kb_associate "<query>" "[<output-path>]" "[<threshold>]" "[<limit>]"
argus_kb_associate() {
    local query="${1:-}"
    local out="${2:-}"
    local threshold="${3:-0.3}"
    local limit="${4:-10}"

    local jm
    jm="$(argus_jm_path)" || return 1

    local args=(associate --query "$query" --format json --threshold "$threshold" --limit "$limit")

    if [[ -n "$out" ]]; then
        "$jm" "${args[@]}" > "$out"
    else
        "$jm" "${args[@]}"
    fi
}
