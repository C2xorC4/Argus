#!/usr/bin/env bash
# Run a command on the lab target via SSH, reading the host alias
# from `config/argus.local.toml`.
#
# Usage:
#   bash dev/lab_run.sh <command...>
#   bash dev/lab_run.sh apt-get update
#   bash dev/lab_run.sh "uname -a; lsmod | grep algif"
#
# Sudo commands work if the target user has NOPASSWD sudo configured;
# pass them as `sudo <cmd>` and the SSH session runs them directly.
#
# Destructive commands (modprobe, rmmod, mkfs, dd, rm -rf with
# absolute paths, etc.) prompt for operator confirmation by default
# unless the local config sets `require_confirm_destructive = false`
# or the env var ARGUS_LAB_NOCONFIRM=1 is set.

set -euo pipefail

ARGUS_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CFG_LOCAL="${ARGUS_ROOT}/config/argus.local.toml"
CFG_DEFAULT="${ARGUS_ROOT}/config/argus.toml"

# Naive TOML reader: extract a key under [lab_target].
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
    cat <<EOF >&2
[lab_run] no ssh_alias configured.

Set [lab_target].ssh_alias in config/argus.local.toml. Example:

    [lab_target]
    ssh_alias = "argus-lab"

The alias must match a Host entry in your ~/.ssh/config. See
dev/setup_ssh_target.md for the full setup walkthrough.
EOF
    exit 2
fi

if [ "$#" -eq 0 ]; then
    echo "[lab_run] no command given" >&2
    echo "Usage: bash dev/lab_run.sh <command...>" >&2
    exit 1
fi

# Destructive-pattern check
cmd_string="$*"
destructive=false
for pat in 'rmmod ' 'modprobe ' 'mkfs' 'dd if=' 'shred ' 'rm -rf /' \
           'sudo rm ' 'sudo dd ' '> /dev/sd' 'reboot' 'shutdown'; do
    case "$cmd_string" in
        *"$pat"*) destructive=true; break ;;
    esac
done

if [ "$destructive" = true ] && [ -z "${ARGUS_LAB_NOCONFIRM:-}" ]; then
    require_confirm="$(read_toml_key "$CFG_LOCAL" require_confirm_destructive || true)"
    [ -z "$require_confirm" ] && \
        require_confirm="$(read_toml_key "$CFG_DEFAULT" require_confirm_destructive || true)"
    if [ "$require_confirm" != "false" ]; then
        echo "[lab_run] destructive pattern matched; confirm to proceed." >&2
        echo "  target: ${ssh_alias}" >&2
        echo "  cmd:    ${cmd_string}" >&2
        printf "Confirm? [y/N] " >&2
        read -r reply
        case "$reply" in [yY]*) ;; *) echo "aborted." >&2; exit 1 ;; esac
    fi
fi

exec ssh -o BatchMode=yes "${ssh_alias}" "$@"
