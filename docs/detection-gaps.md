# Argus Detection Gaps — Binary Exploitation Patterns

Gaps surfaced through live exploit validation against real vulnerable binaries.
Each item names what was missed, why it matters, and the detection signal needed.

---

## 1. read()-into-execute via RWX mmap

**Pattern:** `mmap(NULL, size, PROT_RWX)` → `read(0, mmap_buf, N)` → `call mmap_buf`
**Gap:** vuln_scan does not flag read() as a taint sink when the destination is later called as a function pointer. The vulnerability is the `PROT_RWX` mmap + direct read-into-execute chain. Current corpus covers stack/heap overflow sinks; callable mmap regions are not modeled.
**Signal to add:** any mmap with PROT_EXEC|PROT_WRITE whose return value reaches a read() destination, followed by an indirect call.

---

## 2. seccomp BPF filter — constrains exploit path classification

**Pattern:** `prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &bpf_prog)` installed before untrusted code executes.
**Gap:** No detection for seccomp presence. Argus reports raw syscall surface but does not identify whether a BPF filter constrains it. A TP flag for "seccomp-filtered binary" changes the exploit path classification from "shellcode" to "ORW shellcode" or "blind memory scan" — affects both PoC generation and impact rating.
**Signal to add:** `prctl` call with PR_SET_SECCOMP + SECCOMP_MODE_FILTER constant; alternatively, `seccomp` syscall (x86: 354, x86-64: 317). Downstream: annotate taint paths with reachable syscall set.

---

## 3. PRNG-seeded hidden address (entropy as address-space primitive)

**Pattern:** `/dev/urandom` → `srand()` → `rand() << N` generates a random mmap address. Secret data is placed there; all direct pointers are zeroed before untrusted code runs. Exploitation requires a memory scan, not a pointer dereference.
**Gap:** prng-security-path detection targets PRNG output in cryptographic or authentication decisions. Using a PRNG to hide a memory address is a distinct pattern — "PRNG as ASLR surrogate." The tier1 corpus does not include this class.
**Signal to add:** PRNG output used as an mmap address argument (taint from rand()/urandom read → mmap addr parameter). Secondary signal: mmap result stored in a local then zeroed before an indirect call.

---

## 4. Format string + canary bypass via fgets truncation

**Pattern:** `fgets(buf, N+2, stdin)` on an N-byte buffer. Sending N printable bytes + `\n` overwrites `canary[0]` with `0x0a`. `__stack_chk_fail` is in GOT (partial RELRO) → overwriting that GOT entry via format string redirects canary failure to a controlled address, giving an unlimited loop-back.
**Gap:** Format-string detection correctly finds `printf(user_buf)`. It does not model the interaction where a *separate* bounded read (`fgets`) overflows the canary byte, and the canary-fail handler is itself a writable GOT entry. The combined pattern (format string leak + GOT overwrite of canary handler) is not in the tier1 corpus.
**Signal to add:** partial RELRO binaries where `__stack_chk_fail@GOT` is writable + a format string sink in the same or calling function scope. Flag the canary handler as a GOT overwrite target, not just an integrity check.

---

## 5. 3-byte partial GOT overwrite (printf → system)

**Pattern:** printf and system share the same libc page prefix; only the low 3 bytes differ. Three `%hhn` byte writes to `printf@GOT` redirect it to `system` without a full 8-byte overwrite. Requires only the low 3 bytes of the target address (obtainable from a partial libc leak).
**Gap:** Argus reports GOT write surface but does not classify partial-overwrite exploitability. A full 8-byte overwrite requires a known libc base; a 3-byte overwrite only needs the low 3 bytes — lower entropy, survives partial ASLR. Partial-overwrite feasibility is a distinct and lower-bar risk tier.
**Signal to add:** after any libc address leak, flag `printf@GOT` (and other libc-internal PLT stubs) as 3-byte partial-overwrite targets when the binary has writable GOT + a format string sink. Annotate as easier than full overwrite.

---

## Cross-cutting observation

Argus models individual vulnerability primitives well (format string, overflow, PRNG misuse) but does not chain interaction effects — PRNG→mmap→call, fgets→canary→GOT, format→GOT→canary-handler. Multi-primitive chaining is the general gap; the items above are concrete instantiations. Phase 4 verification integration is the long-term fix surface; items 1, 4, 5 are tractable as Phase 1 detection additions without it.
