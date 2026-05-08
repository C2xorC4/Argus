# Dirty Frag — Empirical Validation Results

Run: 2026-05-08, against Ubuntu 24.04 LTS kernel 6.8.0-111-generic
modules pulled from a vulnerable lab VM (pre-patch — disclosure
2026-05-07, noble-updates not yet rebased to a patched build at
this point).

## Targets

| Module | Path on VM | SHA-256 (build ID) | Size |
|---|---|---|---|
| `esp4.ko` | `/lib/modules/6.8.0-111-generic/kernel/net/ipv4/esp4.ko.zst` (decompressed) | `8ae867afdfb825e59e35190281e937c1236c1c26` (build-id) | 45,353 B |
| `esp6.ko` | `/lib/modules/6.8.0-111-generic/kernel/net/ipv6/esp6.ko.zst` | `fc055b9cf8b1aeee983acef7cba35c1b511e7363` | 46,601 B |
| `rxrpc.ko` | `/lib/modules/6.8.0-111-generic/kernel/net/rxrpc/rxrpc.ko.zst` | `d659a24796846a365656100df6ea05085a847bfa` | 905,049 B |

Targets stored at `vulntest/known-positive/dirty-frag/binary/`.

## Detector

`analysis/decrypt_external_pages.py` v1 + v2 combined:

- v1 — binary-scope import co-presence (constructor + sink + no
  gate). Suppresses on these modules because `skb_cow_data` /
  `skb_copy_bits` are imported globally for OTHER paths. v1
  emitted **0 findings** across all three modules — under-recall
  for the canonical Dirty Frag shape, as designed: v1 is the
  cheap fast-path; v2 catches what v1 misses.
- v2 — per-function CFG-aware. For each function: scatterlist
  constructor + crypto decrypt sink in the same function, with
  the constructor dominating the sink, and **no privately-own
  gate dominating the sink**. Emits `decrypt_into_external_pages`
  HIGH.

## Findings — v2

| Module | Function | Constructor | Decrypt sink | Verdict |
|---|---|---|---|---|
| `esp4.ko` | **`esp_input`** | `sg_init_table @ 0x401061` | `crypto_aead_decrypt @ 0x4010d5` | **EXACT match to disclosure named function** |
| `esp6.ko` | **`esp6_input`** | `sg_init_table @ 0x4011f1` | `crypto_aead_decrypt @ 0x401265` | **EXACT match to disclosure named function** |
| `rxrpc.ko` | **`rxkad_verify_packet_1`** | `sg_init_table @ 0x42527e` | `crypto_skcipher_decrypt @ ...` | **EXACT match to disclosure named function** |
| `rxrpc.ko` | `rxkad_decrypt_ticket` | `sg_init_one @ 0x42686d` | `crypto_skcipher_decrypt @ ...` | bonus — related rxkad path, plausibly same class |
| `rxrpc.ko` | `rxkad_verify_response` | `sg_init_table @ 0x426d57` | `crypto_skcipher_decrypt @ ...` | bonus — related rxkad path, plausibly same class |

Total: **5 findings; 3 are the canonical disclosure call sites; 2
are sibling-class candidates within the same module.**

## Detection-quality interpretation

Same shape as the CVE-2026-31431 ("copy.fail") result a month
earlier:

- **Exact disclosure call sites surfaced** — the detector points
  at the same functions named in `https://dirtyfrag.io` /
  oss-security disclosure thread (`esp_input`, `esp6_input`,
  `rxkad_verify_packet_1`).
- **Generalisation to sibling functions** — `rxkad_decrypt_ticket`
  and `rxkad_verify_response` weren't flagged in the public PoC's
  named functions but exhibit the same structural shape. These
  are research candidates worth investigating independently.
- **Pre-patch posture confirmed** — kernel 6.8.0-111 has no
  `skb_cow_data` call dominating the in-place decrypt edges in
  the affected functions. Post-patch noble-updates rebases will
  add the gate; rerun the detector against a post-patch build to
  confirm silence.

## v1 vs v2 detector trade-off

v1 binary-scope is necessarily under-powered for this CVE class
because every kernel module that handles SKBs imports SOME
privately-own gate for SOME path. Per-function scoping (v2) is
the load-bearing semantic.

v1 is retained for fast triage on small modules where a false
suppression isn't likely — kernel modules that contain ANY
scatterlist + decrypt + no-gate-at-all are obvious targets.
On the medium-and-larger kernel modules in this validation set,
v2 carries the result.

## State machine

| Function | Module | State | Transition reason |
|---|---|---|---|
| `esp_input` | `esp4.ko` | **IMPACT_VERIFIED** | Phase-4 harness 2026-05-08T14:10Z — dirtyfrag PoC `--force-esp` corrupted `/usr/bin/su` page cache; entry bytes `31 ff` at 0x78 confirmed; dmesg captured kernel-side shellcode execution |
| `esp6_input` | `esp6.ko` | **IMPACT_PENDING** | Phase-4 PoC exercises IPv4-only (`xs->family = AF_INET`); IPv6 SA + ESPv6 trigger not yet executed — same code class, separate trigger needed |
| `rxkad_verify_packet_1` | `rxrpc.ko` | **IMPACT_VERIFIED** | Phase-4 harness 2026-05-08T14:10Z — `--force-rxrpc` injected `root::0:0:` (empty password) into `/etc/passwd` page cache; `getent passwd root` confirmed via NSS; PoC stderr explicitly logged `PRIMITIVE proven` |
| `rxkad_decrypt_ticket` | `rxrpc.ko` | DETECTED | sibling-class candidate; not exercised by public PoC, needs independent triage |
| `rxkad_verify_response` | `rxrpc.ko` | DETECTED | sibling-class candidate; not exercised by public PoC, needs independent triage |

State transitions captured at `triage/state.json`. Phase-4 harness, evidence, and stderr capture archived under `impact-verification/`.

## Substrate-coherence

`jm associate "decrypt into external pages SKB scatterlist
dirty frag esp_input rxkad"` returns
`dirty_frag_decrypt_into_external_pages` (knowledge) as the
**top hit at 0.841**, well above the 0.3 retrieval threshold.
The Knowledge entry referenced by the detector is properly
indexed and surfaces on the canonical query — no orphan-anchor
risk.

## Post-patch silence test (attempted)

Pulled `linux-modules-6.17.0-23-generic` (hwe-24.04) from
`noble-updates`. The deb is dated `2026-04-30`, **before** the
2026-05-07 disclosure — so it predates the patch landing in
upstream `net.git`. Running v2 against the 6.17 modules:

| Module | esp_input/esp6_input/rxkad_verify_packet_1 emission |
|---|---|
| `esp4.ko` (6.17.0-23) | still fires on `esp_input` (no dominating gate) |
| `esp6.ko` (6.17.0-23) | still fires on `esp6_input` (no dominating gate) |
| `rxrpc.ko` (6.17.0-23) | still fires on `rxkad_verify_packet_1` |

Result: **silence test deferred — no patched Ubuntu build is
yet shipped.** The 6.17 hwe deb is a different *kernel
lineage* than 6.8.0-111, not a *patched* build. Re-fire once
Ubuntu rebases `noble-updates` to a build that includes the
upstream Dirty-Frag fix (target window: ~1-2 weeks post
disclosure per typical Canonical SRU timelines).

Patched-module retrieval automation is in
`binary-postpatch/` so the silence rerun is a one-command
re-fetch + replay once a fixed build is available.

## Phase-4 Impact Verification (executed)

Public PoC at `https://github.com/V4bel/dirtyfrag` cloned onto the
lab VM; built with `gcc -O0 -Wall -o exp exp.c -lutil`; executed
via `vulntest/known-positive/dirty-frag/impact-verification/verify_dirtyfrag.sh`.

**ESP path (`./exp --force-esp`)**

- Pre-state SHA-256 `/usr/bin/su` = `c74311fe...bdae78b`.
- 48 xfrm SAs installed in a fresh user+net namespace; each SA's
  `seq_hi` field carries 4 bytes of the rootshell ELF.
- 48 `do_one_write` rounds: open `/usr/bin/su` RO → vmsplice ESP
  header into pipe → splice 16 bytes from `/usr/bin/su` into
  pipe → splice from pipe to ESP-in-UDP socket → kernel
  `crypto_aead_decrypt` writes plaintext (= `seq_hi`) into the
  pipe-mapped page-cache page of `/usr/bin/su`.
- Post-exploit page cache: first 192 bytes match `shell_elf`
  byte-for-byte. Entry `31 ff 31 f6 31 c0 b0 6a` at 0x78 — the
  shellcode prologue (`xor edi,edi; xor esi,esi; xor eax,eax;
  mov al,0x6a` → `setgid(0)`).
- dmesg captured kernel-side execution: `process 'su' launched
  '/bin/sh' with NULL argv: empty string added`.
- Writeback flushed the corrupted page to disk during the 45 s
  exploit window; on-disk SHA-256 changed to `0c0f135f...05ccd68a4`.
- Restored via `sudo apt-get install --reinstall -y util-linux`;
  post-restore SHA-256 matches the pre-state baseline.

**RxRPC path (`./exp --force-rxrpc`)**

- Pre-state SHA-256 `/etc/passwd` = `0ec9662a...335bc29c`.
- PoC mmap's `/etc/passwd` PROT_READ|MAP_SHARED to align
  page-cache offsets, brute-forces three fcrypt session keys
  that decrypt to `::`, `0:`, `0:GGGGGG:` markers (3 stage
  brute-force, the largest at ~21M iterations in 4.88 s on the
  VM CPU).
- Three `AF_RXRPC` client sendmsg triggers, one per byte slice;
  each invokes `rxkad_verify_packet_1` →
  `crypto_skcipher_decrypt` over the externally-owned page-
  cache page of `/etc/passwd`.
- Post-exploit page cache: line 1 reads
  `root::0:0:.....:/root:/bin/bash` (binary garbage from cipher
  residue between `:0:0:` and `:/root:`).
- **Independent NSS verify**: `getent passwd root` returned
  `root::0:0:�ʇ��:/root:/bin/bash`. PoC stderr line 49:
  *"PRIMITIVE proven: root entry has empty passwd field via
  NSS."*
- `drop_caches` reverted on-disk file to baseline
  (`0ec9662a...` matches pre-state).

**Cleanup performed**

- `echo 3 > /proc/sys/vm/drop_caches` (page-cache eviction).
- ESP path: `apt reinstall util-linux` to restore `/usr/bin/su`
  (writeback persisted the corruption to disk).
- RxRPC path: drop_caches alone sufficient.
- AppArmor unprivileged-userns restriction restored to its
  pre-test value (1 = enabled).

Evidence files: `impact-verification/result.json` (structured),
`exp_esp.stderr`, `exp_rxrpc.stderr` (PoC narrative).

## Remaining work

- **`esp6_input` IMPACT_VERIFIED** — write a v6-counterpart
  trigger (XFRMA_ENCAP with AF_INET6, ESPv6 packet construction).
  Same bug class — the PoC's IPv4 success establishes the
  primitive; v6 just needs the v6 wire format.
- **Post-patch silence rerun** — blocked on Ubuntu noble-
  updates rebasing past 2026-05-07. Detector should silence on
  the IMPACT_VERIFIED functions once a patched build lands.
- **Sibling-class triage** — `rxkad_decrypt_ticket` and
  `rxkad_verify_response` need independent reachability +
  page-ownership review before promotion.

## Pipeline output

Reproduce:

```bash
PYTHONPATH="C:\\Program Files\\Vector35\\BinaryNinja\\python" \
  python vulntest/runner.py \
    --targets vulntest/known-positive/dirty-frag/binary/esp4.ko \
              vulntest/known-positive/dirty-frag/binary/esp6.ko \
              vulntest/known-positive/dirty-frag/binary/rxrpc.ko \
    --filter NONEXISTENT
```
