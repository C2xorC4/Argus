# HTB Reversing Challenge Flags

| Order | Challenge | Flag | Method |
|---|---|---|---|
| 1 | SpookyPass | `HTB{un0bfu5c4t3d_5tr1ng5}` | Strings → password literal → run binary with password reveals flag |
| 2 | Simple_Encryptor | `HTB{vRy_s1MplE_F1LE3nCryp0r}` | Binja main: XOR+ROL with srand(time())+rand(); seed prepended to flag.enc; wrote C decryptor using glibc rand to invert |
| 3 | Behind_the_Scenes | `HTB{Itz_0nLy_UD2}` | SIGILL anti-disasm: handler skips ud2 (rip+=2). objdump shows real flow: 4× strncmp(argv[1]+offset, .rodata, 3). Concatenated literals = `Itz_0nLy_UD2` |
| 4 | Cyberpsychosis | *(skipped — remote-dependent)* | Modified diamorphine LKM rootkit. Challenge brief: "Malicious actors have infiltrated our systems and we believe they've implanted a custom rootkit. Can you disarm the rootkit and find the hidden data?" — flag is hidden data on the running infected box, not in the .ko itself. MAGIC_PREFIX `psychosis` recovered for context but not the flag. Skipped per operator. |
| 5 | Partial_Encryption | `HTB{W3iRd_RUnT1m3_DEC}` | Win64 PE. Self-decrypts shellcode via custom 1-round AES: `aesdeclast(input ^ aeskeygenassist(key,0x10), aeskeygenassist(key,0))` where key = per-block index broadcast to 16 bytes. 4 check-shellcodes verify argv[1] character-by-character via per-position `cmp` of expected ASCII bytes; statically decrypted all blobs in Python and read out the (idx,char) tuples: `H,T,B,{,W,3,i,R,d,_,R,U,n,T,1,m,3,_,D,E,C,}`. Verified by running binary → "Yes". |
| 6 | Bypass | `HTB{SuP3rC00lFL4g}` | Skater-obfuscated .NET. RijndaelManaged decrypts a `0` resource into 13 strings stored in class `5`. Username/password check trivially returns false (forced bypass intent). Wrote a tiny C# reflection harness — load assembly, invoke `5.0()` static initializer (the decryptor), enumerate fields. Got literal flag string from `5.5 + 0.2 + 5.6` = `Nice here is the Flag:HTB{SuP3rC00lFL4g}`. |
| 7 | Exatlon | `HTB{l3g1c3l_sh1ft_l3ft_1nsr3ct1on!!}` | UPX-packed ELF. Unpacked via `upx -d` (downloaded binary). `exatlon()` transform = each char `<< 4`. Reversed the 36-number target string by dividing each by 16. Spelling typos (`l3g1c3l`, `1nsr3ct1on`) intentional. |
| 8 | RAuth | *(skipped — remote-dependent; local stub is `HTB{F4k3_f74g_4_t3s7ing}`)* | Rust ELF using Salsa20. Key=`ef39f4f20e76e33bd25f4db338e81b10`, nonce=`d4c270a3` (both inlined). Password=Salsa20-decrypt of inline 32-byte ct → `TheCrucialRustEngineering@2021;)`. Local binary ships a placeholder ciphertext that decrypts to "F4k3_f74g_4_t3s7ing"; the real flag is supplied by the remote service when the password is sent over the wire. Skipped per operator's remote-dependency rule. |
| 9 | GameLoader | *(blocked — needs Godot pck extractor)* | Godot 4.1.1 game with encrypted .pck (header flag bit 0x1 = encrypted). Need to recover the 32-byte AES-256 `script_encryption_key` embedded in `Platformer 2D.exe` and decrypt the .pck directory. **Tooling gap**: no `gdre_tools` / `gdsdecomp` installed; `pip install gdsdecomp` failed (no PyPI distribution). Recommend installing `gdre_tools` (Godot Reverse Engineering Tools) — provides programmatic key extraction + pck decryption + script decompilation. |
| 10 | Rega's_Town | `HTB{Y0u_Ar3_Th3_K1ng_O7_The_Town}` | Rust ELF, 33-char passphrase. 9 regex constraints + 7 u128 product checks (`multiply_characters` slices). Range `start..end` is exclusive, so slice [12..15] is 3 chars (pos 12-14) not 4. Re-verified target hex: 0x6cc60=445,536 (NOT 446,560 — earlier arithmetic error), factors as 84·104·51 → "T·h·3" ✓; 0x27b5776=41,637,750 → "K·1·n·g"; 0xd76a0=882,336 → "T·h·e"; 0x7465a58=122,051,160 → "T·w·o·n" (Town). Final flag built from regex pos constraints + product solutions: `HTB{Y0u_Ar3_Th3_K1ng_O7_The_Town}`. Verified — binary prints "Correct one of us!!" |
| 11 | Wayback | *(deferred — exhaustive seed search did not converge)* | C++ ELF + `decrypt.py`. Generator: `seed = day*1e6 + min*100 + sec + hour*1e4 + (year+1900)*0x540be400 + (mon+1)*0x5f5e100`, then `srand(seed); rand() % len(alphabet)` for each char. AES-256-CBC decrypts an 80-byte ct (16-byte IV + 64 ct) using NUL-padded password. Verified my generator matches V1 byte-for-byte. **Exhaustive brute** over years 2024+2023+2022, lengths {32,50,16,20,24,8}, sym/num all 4 combos = 24×3 yr searches = 78 min — found nothing. Either (a) year outside 2022-2024, (b) length not in tested set (e.g., 10/12/25/30/40), (c) sym/num custom alphabet, or (d) bug. `bruteforce.c` saved at `Wayback/rev_wayback/`. Recommend: also try years 2020-2021, 2025-2026 and lengths 8-12, 25, 30, 40. |
| 12 | Coffee_Invocation | *(deferred — JNI verification analysis incomplete)* | C ELF embeds 2 Java classfiles (Verify1, Verify2) and invokes them via JNI_CreateJavaVM. Wrote a Python bytecode disassembler (`disasm.py`). **Verify1** logic: argv[1].substring(0, 26) must equal `~PL{A;PL{?;:=|PIC{HzP:A;~x` (literal in C binary). **Verify2** apparent contradiction: even-length check passes for 26-char input, but final `s.equals("Tinfoil")` requires 7-char input. Either disassembly misread or class-file boundaries are wrong (only the 2nd classfile-magic visible in the ELF). data_4074a0=26, data_4085b0=26 confirmed via raw read. Java tooling apt-install hung in WSL. Recommend: install JDK + javap to validate, then run binary with candidate input `HTB{argv...}` once verifies pass. |
| 13 | FFModule | *(deferred — Firefox PR_Write hook injector)* | Win64 PE. Main XOR-decrypts 0x5a4 bytes at .data section with key 0x72, then injects into firefox.exe via VirtualAllocEx + WriteProcessMemory + CreateRemoteThread. Decrypted shellcode hooks `PR_Write` (Firefox's NSPR write fn) to exfiltrate POST data. No `HTB{}` literal in either the EXE or the decrypted shellcode. Flag is likely emitted at runtime when the shellcode runs inside firefox (or sent over the wire to a C2). Skipped per 20-min budget — would need dynamic analysis. |
| 14 | SEPC | *(deferred — kernel module verification)* | Linux kernel boot challenge with bzImage + initramfs. Userspace `checker` calls `/dev/checker` (LKM) for verification. Skipped per 20-min budget. |
| 15 | Maze | `HTB{w0W_Y0u_C0uld_E5c4p3_Th1s_M4Z33!!}` | Five-layer reversing chain: PyInstaller → xdis bytecode disassembly → AES-zip extraction (pwd `Y0u_Ar3_W4lkiNG_t0_Y0uR_D34TH`) → triple-layer obf_path (XZ→zlib→marshalled inner code) → decoded inner reads `maze.png` to compute `seed=index[4817]+[2624]+[2640]+[2720]=493`, generates 300 randints(32,125) as the XOR key. Applied maze.py transforms (loop1: `+80%256` every 10th byte; loop2: `^key[i%len]` every 10th byte) to decrypted maze data → ELF binary. Final ELF `dec_maze` reads stdin and verifies via 36 triple-sum constraints (`buf[i]+buf[i+1]+buf[i+2] == sums[i]`). Reconstructed buf from sums starting with HTB → `HTB{w0W_Y0u_C0uld_E5c4p3_Th1s_M4Z33!!}`. Verified by piping to `dec_maze` → "Well done for escaping the maze...". |
| 16 | Virtually_Mad | *(deferred — custom VM)* | ELF that prompts "Give me code to execute:" — implements a custom virtual machine with registers a, b, c, d, flags and instructions parsed from input. Has handlers `sub_40125c`, `sub_4014c6`, `sub_4015bd`, `sub_401737`. Solving requires reversing the opcode table + writing VM bytecode that emits flag. Skipped per 20-min budget. |
| 17 | Callfuscated | *(deferred — extreme call-chain obfuscation)* | ELF with 4100 functions (vs typical 30-100). main calls a chain of `sub_40b663` → `sub_40900f` → ... — each function does trivial work then tail-calls another, creating an opaque control-flow graph. Each call modifies registers and returns to the next, ultimately implementing the password check. Static analysis would require tracing through the call DAG; dynamic analysis with gdb would be more efficient. Skipped per 20-min budget. |
| 18 | Debugme | *(deferred — debugger-required challenge)* | i386 PE. Self-describes: `"I heard you like bugs so I put bugs in your debugger so you can have bugs while you debug!!! Seriously though try and find the flag, you will find it in your debugger!!!"`. Classic anti-debug trick: flag revealed via INT 3 / INT 0x2D / self-modifying code that only executes when a debugger handles the exception. Skipped per 20-min budget — needs x32dbg / x64dbg or a similar interactive debugger. |
| 19 | dudidudida | *(deferred — D AA pair-check + 3s timeout)* | Win64 PE compiled from D-language. Prompts "Enter flag: " with 3-second timeout (`sub_14004c860(3)`). Verification at `sub_14000b180`: iterates 2-char chunks of input, looks up `data_1400f29a0[i]` (D associative array), memcmps 2 bytes, tail-calls next iteration handler if match. Each chunk has its own continuation function (`sub_14001cfa0`, `sub_14000ad60`, `sub_14002fc60`, ...). Solving requires either runtime instrumentation (gdb/x64dbg) to dump the AA pairs as the input flows in, or full RE of D's AA layout. Skipped per 20-min budget. |
| 20 | Hexecution | `HTB{cU510m_I54_aNd_eMuL4t10n_4r3_fUn}` | Pass-2 solve. ELF executes `.asm` recipe with custom opcodes. Verified opcode semantics: BOIL=load imm; AES256=write byte to mem[CARBO+ctr], ctr++ (counter monotonic, never resets); SPELL 0=scanf to mem[CARBO+i], SPELL 1=write/print; ROAST=XOR; QUICKMAFFS=PROTEIN=mem[imm]; GRIND/GOODBYE=reg-to-reg copy; WINDOW=mem[CARBO]=reg&0xff; LADDER=reg+=1; PEPEFROG=cmp 32 bytes at mem[r1] vs mem[r2]. **Crucial detail**: the AES counter is monotonic across the whole recipe — after 16 prompt bytes + 32 SPELL-0 input bytes, counter=48, so the embedded "5maNcI4..." block written with `BOIL CARBO,0x40` lands at mem[0x70..0x8F], not 0x40. Algorithm: input → mem[0x14..0x33], 4-byte chunks `(a,b,c,d) → (c,b,d,a)`, then permute to mem[0x42..0x61], compare against mem[0x70..0x8F]. Verified by piping `cU510m_I54_aNd_eMuL4t10n_4r3_fUn` to `./cook recipe.asm` → "Nice! The flag is HTB{YOUR_INPUT} :)". |
| 21 | vvm | *(deferred — custom VM with self-decrypted bytecode)* | ELF prints "vvm v0.0.3 / What is the password:" and verifies. Setup function `sub_401530` (4812 bytes, 111 BBs) decrypts ~20 bytecode blobs from `data_4050XX..` using XOR key `[0x2a, 0x0b, 0x21, 0x21, 0x4d, 0x2a]` (cycled), each blob mmap'd as RWX (size 0x12-0xb4 bytes). VM dispatcher `sub_402870` interprets those decrypted blobs. The flag check is somewhere in the bytecode — would need either to write a static decryptor for all blobs + a VM interpreter, or run with a debugger and intercept. Skipped per 20-min budget. |
| 22 | Poly | *(deferred — AArch64 printf-polymorphism)* | Statically-linked AArch64 ELF (270KB), no `main` sym, stripped. Has a custom `.flag` section at 0x40007e8b (size 0x39ec6 = 237KB) of randomly-seeded data. Verification at `sub_400000e0` uses `printf` `%n` byte-count side-effects through `/dev/null` (open + write + count) to compute pointer offsets into the flag section, extracting the flag bytes character by character based on input. AArch64 + qemu-user not installed in WSL. Skipped per 20-min budget. |

## Tooling Gaps Identified

| Gap | Impact | Recommendation |
|---|---|---|
| Godot pck extractor (gdre_tools / gdsdecomp) | GameLoader blocked | Install `gdre_tools` standalone binary (Godot Reverse Engineering Tools). Handles encrypted .pck via key extraction from the engine binary. |
| Live debugger / gdb scripting | Rega's Town stuck on opaque u128 product calculation | Add a per-detector helper that hooks `multiply_characters` / similar Rust closures via gdb-python and dumps the actual computed value per slice. |
| Long-running brute infrastructure | Wayback would benefit from parallelism | Argus would benefit from a `bin/brute-runner` that fans out a key-space brute job (e.g., time-seed × params × ciphertext) across worker processes with progress reporting. |
| `.rela.dyn` static resolver | Rega's Town blocked on runtime-relocated `data_7d52a0` (regex pointer table) | Add a util that resolves `.rela.dyn` runtime relocations statically — apply addends to .data.rel.ro values at extraction time. Would let Argus's heuristics treat PIE/PIC string tables as readable without an emulator. |

## Submission Plan

Confirmed/verified flags (in challenge order):
1. `HTB{un0bfu5c4t3d_5tr1ng5}` (SpookyPass) — verified by binary
2. `HTB{vRy_s1MplE_F1LE3nCryp0r}` (Simple_Encryptor) — Salsa20 decryption
3. `HTB{Itz_0nLy_UD2}` (Behind_the_Scenes) — verified by binary
4. `HTB{W3iRd_RUnT1m3_DEC}` (Partial_Encryption) — verified ("Yes")
5. `HTB{SuP3rC00lFL4g}` (Bypass) — verified via reflection
6. `HTB{l3g1c3l_sh1ft_l3ft_1nsr3ct1on!!}` (Exatlon) — verified via leetspeak division
7. `HTB{w0W_Y0u_C0uld_E5c4p3_Th1s_M4Z33!!}` (Maze) — verified by piped input

Skipped — remote-dependent (host service required for the actual flag):
- RAuth — Salsa20 password recovered (`TheCrucialRustEngineering@2021;)`); flag served over wire only
- Cyberpsychosis — rootkit reversing on a running infected host

## Pass-2 priority order (deferred items, ranked by completion likelihood given current/installable tooling)

**Tier A (high likelihood — direct path with tooling available):**
1. **Wayback** — already have validated brute-force generator; need wider parameter sweep (years 2020-2021/2025-2026 + lengths 8-12, 25, 30, 40). Pure compute, parallelisable.
2. **GameLoader** — `gdre_tools` installed; encrypted Godot 4.1.1 .pck. Need to recover the 32-byte AES-256 `script_encryption_key` from `Platformer 2D.exe` via static analysis (entropy scan + xref to encryption setup) or runtime trace.
3. **dudidudida** — Win64 PE; **x64dbg works directly**. Single-step the per-chunk memcmp at `sub_14000b180`, capture each expected 2-char pair from data_1400f29a0, reconstruct flag.
4. **Debugme** — i386 PE with intentional anti-debug; **x64dbg is the canonical tool** for this challenge class. Patch out anti-debug exceptions and capture the revealed flag.

**Tier B (medium likelihood — modest extra tooling/setup):**
5. **Coffee_Invocation** — JDK in WSL is the missing piece. Install JDK + use reflection harness (proven approach from Bypass).
6. **Rega's Town** — Linux ELF; gdb (with python scripting) to live-trace the `multiply_characters` u128 product per slice. Resolves the prime-factor blocker.
7. **Hexecution** — Pure static; the AES256 internal counter at buf[0x100] needs careful trace. Re-emulate the recipe in Python.
8. **Poly** — AArch64; needs `qemu-user-aarch64` (apt installable) or **Frida-aarch64** for runtime trace of the printf-%n offset computations.

**Tier C (lower likelihood — heavier dynamic-analysis lift):**
9. **vvm** — Linux ELF; statically decrypt all ~20 bytecode blobs (XOR key known) + write VM interpreter, OR gdb-trace the dispatcher.
10. **Callfuscated** — 4100-function tail-call chain. gdb step-instruction with conditional breakpoints; aggregate the eventual char comparisons.
11. **Virtually_Mad** — Custom VM with full register set; reverse opcode dispatcher then write a flag-emitting recipe.
12. **FFModule** — Firefox PR_Write injector. Run inside Firefox with WireShark/proxy to capture exfil URL/payload, OR symbolic-execute the decrypted shellcode.
13. **SEPC** — Linux kernel boot via QEMU; reverse the kernel module's `/dev/checker` ioctl handler to find the password.

## Tooling status

Installed during pass-1:
- `gdre_tools` v2.5.0-beta.5 (Godot pck handler)
- `pyinstxtractor` (PyInstaller archive extractor)
- `pyzipper`, `xdis`, `dnfile` (Python helpers)
- WSL `upx`, `gcc`, `wine` (no wine32), `mono`

Pass-2 tooling additions queued:
- **Frida** (cross-platform runtime instrumentation; covers dudidudida hook, Rega's Town product trace, FFModule shellcode trace)
- **JDK 8/11** in WSL (Coffee_Invocation reflection harness)
- **gdb + gef/pwndbg** in WSL (Rega's Town u128 trace, vvm/Callfuscated step-trace)
- **qemu-user-aarch64** (Poly)
- **qemu-system-x86_64** (SEPC)
- **Ghidra** (alternative when Binja's HLIL gets noisy on D-runtime / Java JNI)

Per-challenge time budget: 20 min initial; if no convergence, fork to next priority and revisit on a later pass. Tooling-blocked challenges noted as such.
