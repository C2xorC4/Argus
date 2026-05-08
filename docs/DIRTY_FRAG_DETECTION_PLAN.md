# Dirty Frag (CVE-2026-43284 + CVE-2026-43500) — Detection Plan

**Disclosed:** 2026-05-07 (Hyunwoo Kim, oss-security).
**Status:** Public PoC (`https://dirtyfrag.io`).
**Affected:** Linux kernel `esp4`/`esp6` (IPsec ESP) and `rxrpc`/`rxkad`.

## 1. Bug shape

Decryption-into-externally-owned-pages. When an SKB carries paged
fragments that aren't kernel-owned (pipe pages attached via
`splice(2)` / `sendfile(2)` / `MSG_SPLICE_PAGES`), the receive
path's in-place AEAD or skcipher decrypt writes plaintext directly
onto those external pages. Because `vmsplice` can map pipe pages
back to the page cache, decrypt-in-place corrupts cached file
contents (e.g. `/usr/bin/su`, `/etc/passwd`) and yields root.

Named kernel functions:
- `esp_input` / `esp_input_done2` (IPsec ESP receive)
- `rxkad_verify_packet_1` / `rxrpc_recvmsg` / `verify_packet`
- `skb_to_sgvec` / `sg_set_buf` (scatterlist construction from SKB)
- crypto sinks: `crypto_aead_decrypt`, `crypto_skcipher_decrypt`

Patch shape (from the kernel-commit reference): the fix gates the
in-place decrypt path with a check that the SKB's pages are
privately owned (`skb_cow_data` / `skb_unclone` / `pskb_expand_head`
or equivalent) before passing the scatterlist to the cipher.

Kin: CVE-2026-31431 ("copy fail" — algif_aead page-cache OOB write).
The dirtyfrag.io disclosure refers to a secondary chain "Copy Fail
2: Electric Boogaloo" targeting the same code-path class. Argus
already detected CVE-2026-31431 on stripped `authencesn.ko` (per
`Memory/Project/argus`), so the kernel-mode taint pipeline has
priors here.

## 2. A-priori Argus capability (without seeing the modules)

### What is likely to fire

- **`analysis/taint.py` kernel-module seeder** (`_seed_kernel_module_taint`)
  — seeds taint on SysV ABI registers (rdi/rsi/rdx/rcx/r8/r9) in
  every defined function of a kernel `.ko`. For `esp_input(skb)`,
  rdi (the SKB pointer) becomes the tainted source.
- **Sink emissions on tainted_pointer_dereference (E4)** — if the
  decrypt code dereferences a tainted SSA var that itself came via
  a memory load, E4 fires. This is the same emission that produced
  6 TPs on `authencesn.ko` for CVE-2026-31431.

### What is likely to MISS

- The SPECIFIC structural property — "scatterlist points to
  externally-owned pages" — is invisible to the current detector
  set. The taint analyzer treats SKB pages as opaque; it doesn't
  reason about page ownership.
- No detector recognises `skb_to_sgvec(skb, sg, …)` →
  `crypto_*_decrypt(sg, …)` flow without intervening
  `skb_cow_data` as a structural anti-pattern.
- The chain composition in `heuristics/chains.py` has no template
  for "splice-from-pipe → IPsec-decrypt-corrupts-pagecache → root."

### Provisional assessment

The existing taint stack will likely emit *some* findings on
`esp_input` / `rxkad_verify_packet_1` (kernel-arg taint reaching
crypto sinks) — analogous to the 6 TPs on `authencesn.ko`. Those
findings would be approximately right: they identify the function
where the bug lives and the call sites where the corruption
happens. But they would NOT identify the bug as the specific
"decrypt-into-external-pages" class; they'd report it as generic
tainted-pointer-deref or kernel-arbitrary-rw.

Conclusion: **partial detection a-priori**. Class-precise detection
requires the new detector below.

## 3. New detection requirements

### Detector v1 — co-presence import filter

**Trigger:** function imports BOTH a scatterlist-from-skb constructor
AND a crypto-decrypt API, AND does NOT import a privately-own-pages
gate.

**Imports:**
- Scatterlist constructors: `skb_to_sgvec`, `skb_to_sgvec_nomark`,
  `sg_set_buf`, `sg_init_table`
- Crypto decrypt sinks: `crypto_aead_decrypt`, `crypto_skcipher_decrypt`,
  `crypto_aead_decrypt_done`, `aead_request_set_crypt`,
  `skcipher_request_set_crypt`
- Privately-own gates: `skb_cow_data`, `skb_unclone`,
  `pskb_expand_head`, `skb_share_check`, `skb_copy_expand`

**Emission:** `decrypt_into_external_pages_candidate` — INFO
severity, low-precision (catches the pattern at the binary level
without function-scope dominance).

### Detector v2 — CFG-aware structural detector

**Trigger:** within a single function:
1. There's a call to a scatterlist constructor (`skb_to_sgvec` or
   `sg_set_buf` taking an SKB-derived expression).
2. There's a downstream call to a crypto decrypt sink consuming
   that scatterlist.
3. There is NO call to a privately-own gate dominating the decrypt
   call site.

**Emission:** `decrypt_into_external_pages` — HIGH severity, with
evidence pointing to the unguarded sg-to-decrypt edge.

### Chain template

`heuristics/chains.py` gets a new entry:

```python
DIRTY_FRAG_CHAIN = ChainPattern(
    name="chains.dirty_frag_decrypt_into_external_pages",
    primitives=[
        "decrypt_into_external_pages",      # this CVE class
        "kernel_arbitrary_write_primitive", # downstream effect
    ],
    min_primitives=1,                       # v1 detector alone fires
    knowledge_refs=[
        "[[Memory/Knowledge/dirty_frag_decrypt_into_external_pages]]",
        "[[Memory/Knowledge/argus_kernel_module_taint_via_arg_registers]]",
    ],
)
```

### Knowledge entry

`Memory/Knowledge/dirty_frag_decrypt_into_external_pages.md` —
documents the pattern, the canonical functions, the privately-
own gate APIs, the splice-vmsplice-pagecache trigger sequence.
Cited by the v1 + v2 detectors and the chain template.

## 4. Tier-1 fixture cell

Build `vulntest/tier1-single/decrypt-external-pages/c/` that
synthesises the structural shape:

- `source/vuln.c` — function takes a fake SKB-like struct, builds
  scatterlist via fake `skb_to_sgvec`, calls fake `crypto_aead_decrypt`.
  No `skb_cow_data` call. v1 detector should fire on the import
  co-presence; v2 should fire on the CFG-unguarded edge.
- `remediation/vuln.c` — same shape but calls `skb_cow_data(skb,
  required_size)` first. v1 still fires (import is present in the
  binary either way); v2 should suppress (privately-own gate
  dominates the decrypt call).

Win-mode build via `build_all.sh` (cl.exe). Fixtures don't need
to actually run — they just need to compile so Binja can recover
the MLIL shape.

## 5. Module-level empirical validation

Pending acquisition of affected kernel modules:

- **Source A (preferred):** `kernel-modules-extra-${rev}.el${N}.x86_64.rpm`
  from AlmaLinux mirror. Contains `rxrpc.ko`. ESP modules likely
  in `kernel-modules`.
- **Source B:** AlmaLinux 9.6 ISO → extract via `rpm2cpio` (or
  7-Zip on Windows: `.rpm` is a custom container, but 7-Zip can
  walk into `.cpio`).
- **Source C:** Build vulnerable kernel from source — substantial
  effort.

Validation scoreboard:
- Run Argus full pipeline against `esp4.ko`, `esp6.ko`,
  `rxrpc.ko` from a vulnerable AlmaLinux release.
- For each: count v1 hits (binary-scope), v2 hits (CFG-scope),
  taint hits (existing kernel-arg seeder).
- Compare to the dirtyfrag.io PoC's named call sites.
- Document gaps + iterate on detector tightening.

## 6. Execution order (this session + follow-ons)

| Step | Effort | Status |
|---|---|---|
| 6.1 Knowledge entry `dirty_frag_decrypt_into_external_pages` | 1-2h | ✅ done 2026-05-08 |
| 6.2 v1 co-presence detector + chain template | 2-3h | ✅ done 2026-05-08 |
| 6.3 Tier-1 fixture cell (kernel module sources) | 2-3h | ✅ done 2026-05-08 (build deferred — needs Linux + kernel-devel) |
| 6.4 v2 CFG-aware detector | 0.5-1d | ✅ done 2026-05-08 — `find_decrypt_external_pages_per_function` checks per-function constructor→sink dominance + privately-own-gate absence |
| 6.5 Module acquisition + empirical validation | 0.5d | ✅ done 2026-05-08 — pulled `esp4.ko` / `esp6.ko` / `rxrpc.ko` from Ubuntu 24.04 / 6.8.0-111 lab VM. v2 fires on `esp_input`, `esp6_input`, `rxkad_verify_packet_1` (exact disclosure call sites) + 2 bonus rxkad sibling-class findings. Results in `vulntest/known-positive/dirty-frag/RESULTS.md`. |
| 6.6 Refine v2 based on real-module run | 1d | Detector landed clean — no refinement needed for the canonical disclosure case. Future tightening: surface the bonus rxkad findings to operator triage with a confidence tier. |
| 6.7 DETECTED → CONFIRMED for disclosure-named findings | 0.5h | ✅ done 2026-05-08 — `esp_input` / `esp6_input` / `rxkad_verify_packet_1` transitioned via public-PoC reachability attribution; sibling-class findings remain DETECTED pending independent triage. State capture in `triage/state.json`. |
| 6.8 Substrate-coherence verification | 0.5h | ✅ done 2026-05-08 — `jm associate` returns the Knowledge anchor as top-1 hit at score 0.841. |
| 6.9 Post-patch silence test | pending | ⏳ blocked on Ubuntu noble-updates rebase past 2026-05-07. Pre-patch `linux-modules-6.17.0-23-generic` (built 2026-04-30) was retrieved as a baseline; modules in `vulntest/known-positive/dirty-frag/binary-postpatch/`. Re-fetch + replay automation ready. |
| 6.10 Phase-4 IMPACT_VERIFIED execution | 1d | ✅ done 2026-05-08T14:10Z — `verify_dirtyfrag.sh` ran the public PoC from `github.com/V4bel/dirtyfrag` on the lab VM. ESP path corrupted `/usr/bin/su` page cache (shellcode landed at 0x78, dmesg captured kernel-side `su` → `/bin/sh` exec, writeback flushed to disk, restored via `apt reinstall util-linux`). RxRPC path corrupted `/etc/passwd` page cache (`getent passwd root` confirmed empty-password root entry via NSS, drop_caches reverted on-disk). Evidence in `impact-verification/`. State: `esp_input` + `rxkad_verify_packet_1` → IMPACT_VERIFIED; `esp6_input` → IMPACT_PENDING (PoC IPv4-only). |

**Validation summary:** v2 detector identifies the exact functions
named in the dirtyfrag.io disclosure (`esp_input`, `esp6_input`,
`rxkad_verify_packet_1`) plus 2 sibling-class candidates within
`rxrpc.ko`. Same detection-quality pattern as the CVE-2026-31431
result. Pre-patch posture confirmed; post-patch silence-test
pending Ubuntu noble-updates rebase.

Sprint goal for this session: 6.1–6.5. Empirically validated; v1
+ v2 detector in tree, fires on real-world CVE-2026-43284 +
CVE-2026-43500 targets.
