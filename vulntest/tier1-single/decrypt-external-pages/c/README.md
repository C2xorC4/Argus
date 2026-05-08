# Decrypt-into-externally-owned-pages — C / Linux kernel module

Synthesises the structural shape behind **Dirty Frag**
(CVE-2026-43284 esp4/esp6 + CVE-2026-43500 rxrpc/rxkad), disclosed
2026-05-07 by Hyunwoo Kim. The bug class:

- A network-receive-path function builds a scatterlist directly
  over an SKB's pages.
- Passes the scatterlist to `crypto_aead_decrypt` (or skcipher
  equivalent) for in-place decryption.
- Does NOT call `skb_cow_data` / `skb_unclone` /
  `pskb_expand_head` first to ensure the SKB's pages are
  privately owned by the kernel.

When the attacker splices pipe pages into the SKB (via
`splice(2)` + `vmsplice(2)` page-cache aliasing — the original
"Dirty Pipe" primitive surface), the in-place decrypt corrupts
attacker-readable backing memory. Concrete escalation: page-cache
overwrite of `/usr/bin/su` or `/etc/passwd` → root.

Knowledge: `[[Memory/Knowledge/dirty_frag_decrypt_into_external_pages]]`.

## Files

- `source/vuln.c` — vulnerable shape: scatterlist over SKB →
  decrypt with no `skb_cow_data` gate.
- `remediation/vuln.c` — fixed shape: `skb_cow_data` dominates the
  scatterlist-and-decrypt edge.

## Build

This cell is a Linux kernel module. Cross-compilation requires a
kernel build environment (kernel-devel package + kbuild). On the
Argus host (Windows/MSVC), `build_all.sh` skips this cell.

To build on a Linux host:

```bash
# Vulnerable variant
cd source
echo 'obj-m := vuln.o' > Makefile
make -C /lib/modules/$(uname -r)/build M=$(pwd) modules

# Remediation
cd ../remediation
echo 'obj-m := vuln.o' > Makefile
make -C /lib/modules/$(uname -r)/build M=$(pwd) modules
```

Resulting `.ko` files are the analysis targets.

## Detector targets

- **v1 (binary-scope, in tree 2026-05-08):**
  `analysis.decrypt_external_pages` — fires
  `decrypt_into_external_pages_candidate` when the binary's
  import set has scatterlist constructor(s) + crypto decrypt
  sink(s) but NO privately-own gate. INFO/MEDIUM severity.
- **v2 (per-function, pending):** CFG-aware. Confirms the
  scatterlist → decrypt edge is unguarded by `skb_cow_data` etc.
  on every reachable path. HIGH severity.

## Empirical real-module validation

Acquire affected modules from a vulnerable AlmaLinux build:

```bash
# AlmaLinux 9 — kernel-modules-extra has rxrpc.ko
wget https://rpmfind.net/linux/almalinux/9.6/baseos/x86_64/Packages/\
kernel-modules-extra-5.14.0-570.21.1.el9_6.x86_64.rpm
# Extract: rpm2cpio + cpio, or 7-Zip on Windows
```

Then point the runner / dev/validate.py at the extracted
`esp4.ko`, `esp6.ko`, `rxrpc.ko`. Compare emissions against the
named functions in the dirtyfrag.io disclosure (`esp_input`,
`esp_input_done2`, `rxkad_verify_packet_1`, `rxrpc_recvmsg`).

## Operator-validation checklist

- [ ] Kernel cross-compile produces `vuln.ko` + remediation
      `vuln.ko` on a Linux host.
- [ ] `analysis.decrypt_external_pages` fires
      `decrypt_into_external_pages_candidate` on `vuln.ko`,
      silent on remediation `vuln.ko`.
- [ ] Real-module sweep: detector fires on `esp4.ko` and / or
      `rxrpc.ko` from an AlmaLinux pre-patch build; silent on
      post-patch.
- [ ] Substrate-coherence: `jm associate "decrypt into external
      pages SKB scatterlist"` surfaces the
      `dirty_frag_decrypt_into_external_pages` Knowledge entry.
