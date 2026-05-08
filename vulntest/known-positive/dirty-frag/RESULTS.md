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

The 5 findings are in DETECTED state. Triage to CONFIRMED
requires:

1. **Reachability validation** — confirm `esp_input` and
   `rxkad_verify_packet_1` are reachable from a userspace input
   path that allows arbitrary SKB pages (splice/sendfile/MSG_SPLICE_PAGES).
   The dirtyfrag.io disclosure already establishes this.
2. **Mitigation review** — confirm no XFRM-policy mitigation or
   PAM-config defense blocks the chain on this specific lab.

IMPACT_PENDING transition requires running the public dirtyfrag
PoC against the VM and capturing page-cache corruption evidence.
IMPACT_VERIFIED requires the launch chain (vmsplice → splice →
IPsec receive → page-cache page modified) end-to-end. Phase 4
work track.

## Remaining work

- **Post-patch confirmation** — rerun against the patched
  kernel build once Ubuntu rebases noble-updates. Detector
  should silence on the same functions.
- **Triage to CONFIRMED** — exercise the disclosed PoC on the
  lab VM under sanitizer instrumentation; transition state per
  Phase 4 protocol.
- **Substrate-coherence** — `jm associate "decrypt into external
  pages SKB scatterlist"` should surface the
  `dirty_frag_decrypt_into_external_pages` Knowledge entry as
  top match.

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
