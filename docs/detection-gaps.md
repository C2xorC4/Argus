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

## 3. Egg-hunting setup — PRNG-hidden data + shellcode execution primitive

**Pattern:** `/dev/urandom` → `srand()` → `rand() << N` places secret data at a random mmap address. All direct pointers are zeroed before untrusted shellcode runs. The binary separately provides a RWX mmap + read() → call chain. Together these form a classic **egg-hunting** setup: the attacker must scan memory for a known byte sequence (the "egg") because no pointer to it survives to exploit time.
**Gap (primary):** prng-security-path detection targets PRNG output in cryptographic or authentication decisions. The PRNG-as-hidden-address-sink is a different class, but even framing it that way misses the point — the correct classification is "egg-hunting setup." Argus sees the two halves (PRNG mmap and RWX shellcode exec) but does not recognize their combination as the canonical egg-hunting pattern.
**Gap (secondary):** The egg marker itself — a known constant prefix at the start of the hidden data (e.g., `"HTB{"` = `0x7b425448`) — is a direct probe target. Argus doesn't model "what constant would an attacker scan for?" from static analysis.
**Signal to add:** Combined detection: (1) PRNG output → mmap addr AND (2) separate mmap(RWX) → read() → indirect call, in the same binary. When both halves are present, classify as egg-hunting and note that the egg is the constant prefix of whatever data is strcpy'd to the PRNG-mmap'd region.

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

## 6. ret2win with argument guards (dead-code win function)

**Pattern:** A function never called in normal execution contains file I/O (`open("./flag.txt")` + read loop) but only reaches it if three arguments match specific magic constants (e.g., `0xdeadbeef`, `0xdeadbabe`, `0xdead1337`). The binary has a separate buffer overflow in main, making this a ret2win target.
**Gap:** Argus detects buffer overflow sinks but does not identify "latent win functions" — dead code containing sensitive I/O gated by constant comparisons. The combined pattern (unreachable function + magic guards + file read) is the canonical ret2win structure. Argus sees the overflow and can identify the function exists, but doesn't classify it as a reachable win target via ROP.
**Signal to add:** Functions with zero in-binary call sites that contain `open(path, 0)` + read loop AND whose entry path is blocked by N comparisons of argument registers against constants. Flag as "ret2win target with N argument constraints." The magic constants are the ROP values needed in rdi/rsi/rdx.

---

## 7. Stack alignment requirement for ret2win targets

**Pattern:** A ret2win target calls libc functions internally (printf, open, fputc). These functions use SSE instructions (`movaps xmm0, [rsp+...]`) that require 16-byte stack alignment. When RIP is overwritten via a stack overflow, the stack arrives at the win function misaligned by 8 bytes (post-overflow RSP has odd 16-byte alignment). Calling the win function directly crashes inside libc before reaching the sensitive I/O.
**Gap:** Argus does not annotate ret2win targets with alignment requirements. An exploit that overwrites RIP to jump directly to `fill_ammo` will silently SIGBUS/SIGSEGV inside `open()` with no visible output — indistinguishable from a wrong address. The fix is a single `ret` gadget before the target address to re-align. Without this annotation, exploit generation will produce a non-working payload.
**Signal to add:** Any ret2win target function containing a libc call should be flagged as "alignment-sensitive." Emit a `ret` gadget as the first element of the ROP suffix when the calculated pre-call RSP would be misaligned.

---

## 8. Defensive alarm timer — anti-scan timeout in binary

**Pattern:** `signal(SIGALRM, exit); alarm(N)` with small N (typically ≤ 30 seconds) kills the process after a fixed interval, preventing slow brute-force or scanning exploits from completing.
**Gap:** Argus does not flag defensive timer patterns. When a binary installs a SIGALRM handler pointing to exit/abort and calls alarm() with a small argument in the main execution path, the binary is scan-resistant. An exploit that scans memory (egg-hunting, format string oracle, etc.) must extend the timer before scanning — `alarm(0xFF)` resets the countdown. Missing this means a locally-working exploit fails remotely if latency pushes total runtime past the timer.
**Signal to add:** `signal(SIGALRM, ...)` + `alarm(N ≤ 30)` in the same function scope. Flag as "scan-resistant binary" and annotate: exploit must call alarm() with large argument before any iterative primitive (memory scan, oracle loop, etc.).

---

## Cross-cutting observation

Argus models individual vulnerability primitives well (format string, overflow, PRNG misuse) but does not chain interaction effects — PRNG→mmap→call, fgets→canary→GOT, format→GOT→canary-handler. Multi-primitive chaining is the general gap; the items above are concrete instantiations. Phase 4 verification integration is the long-term fix surface; items 1, 4, 5 are tractable as Phase 1 detection additions without it.
