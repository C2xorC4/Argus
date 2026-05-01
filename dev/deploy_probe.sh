#!/usr/bin/env bash
# Deploy a known-positive cell's probe artefacts to the lab target.
#
# Usage:
#   bash dev/deploy_probe.sh <cell-name>
#   bash dev/deploy_probe.sh CVE-2026-31431
#
# Reads `[lab_target].ssh_alias` and `[lab_target].default_workdir`
# from `config/argus.toml` (+ argus.local.toml). Cell artefacts under
# `vulntest/known-positive/<cell>/probe/` are rsync'd to
# <ssh_alias>:<workdir>/<cell-derived-subdir>/.
#
# Idempotent: re-running re-syncs and re-marks scripts executable.

set -euo pipefail

ARGUS_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CFG_LOCAL="${ARGUS_ROOT}/config/argus.local.toml"
CFG_DEFAULT="${ARGUS_ROOT}/config/argus.toml"

read_toml_key() {
    local file="$1" key="$2"
    [ -f "$file" ] || return 1
    awk -v key="$key" '
        /^\[lab_target\]/ {in_section=1; next}
        /^\[/ {in_section=0; next}
        in_section && $1 == key {
            sub(/^[^=]*=[ \t]*/, "")
            sub(/^"/, ""); sub(/"[ \t]*(#.*)?$/, "")
            sub(/[ \t]*(#.*)?$/, "")
            print
            exit
        }
    ' "$file"
}

ssh_alias=""
[ -f "$CFG_LOCAL" ]    && ssh_alias="$(read_toml_key "$CFG_LOCAL" ssh_alias || true)"
[ -z "$ssh_alias" ]    && ssh_alias="$(read_toml_key "$CFG_DEFAULT" ssh_alias || true)"
if [ -z "$ssh_alias" ]; then
    echo "[deploy_probe] no ssh_alias configured; set [lab_target].ssh_alias" >&2
    exit 2
fi

workdir=""
[ -f "$CFG_LOCAL" ]    && workdir="$(read_toml_key "$CFG_LOCAL" default_workdir || true)"
[ -z "$workdir" ]      && workdir="$(read_toml_key "$CFG_DEFAULT" default_workdir || true)"
[ -z "$workdir" ]      && workdir="~/argus"

# scp / rsync don't expand ~ — resolve it server-side once so the
# downstream paths are absolute. ssh expands ~ via the remote shell,
# so this is a single round-trip.
case "$workdir" in
    "~"*) workdir="$(ssh -o BatchMode=yes "$ssh_alias" "echo $workdir")" ;;
esac

cell="${1:-}"
if [ -z "$cell" ]; then
    echo "[deploy_probe] cell name required" >&2
    echo "Usage: $0 <cell-name>" >&2
    exit 1
fi

cell_dir="${ARGUS_ROOT}/vulntest/known-positive/${cell}"
probe_dir="${cell_dir}/probe"
if [ ! -d "$probe_dir" ]; then
    echo "[deploy_probe] no probe directory at $probe_dir" >&2
    exit 1
fi

# Subdir on the lab — drop the CVE prefix to keep paths short.
remote_subdir="$(echo "$cell" | tr '[:upper:]' '[:lower:]' | sed -E 's/^cve-?//')"
remote_path="${workdir}/${remote_subdir}"

echo "[deploy_probe] cell:       $cell"
echo "[deploy_probe] local:      $probe_dir"
echo "[deploy_probe] remote:     ${ssh_alias}:${remote_path}"

ssh -o BatchMode=yes "$ssh_alias" "mkdir -p \"$remote_path\""

# rsync if available; fall back to scp -r.
if command -v rsync >/dev/null 2>&1; then
    rsync -az --delete \
        --exclude '__pycache__' \
        -e "ssh -o BatchMode=yes" \
        "${probe_dir}/" "${ssh_alias}:${remote_path}/"
else
    scp -q -r -o BatchMode=yes "${probe_dir}/." "${ssh_alias}:${remote_path}/"
fi

ssh -o BatchMode=yes "$ssh_alias" "chmod +x \"${remote_path}\"/*.sh 2>/dev/null || true"
echo "[deploy_probe] done; trigger via: bash ${remote_path}/run_probe.sh"
