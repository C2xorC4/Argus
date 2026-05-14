# Argus — Manual Analysis Playbook

## Purpose

This document is the operator reference for any binary analysis session
conducted under the Argus framework. It prescribes a stage-sequenced
workflow that ensures:

- Every deterministic action is manually replicable 1:1
- Every non-deterministic action (LLM-assisted interpretation, decompiler
  output reading) follows the same question-answer-validate structure and
  produces the same conclusion given the same binary
- Confidence is tracked explicitly; output is gated to confirmed findings

This is not HTB-specific. It applies to any workload where the operator
is doing hands-on binary analysis: CTF reversing challenges, vulnerability
research triage, malware analysis, or tool-assisted research sessions under
the full automated pipeline.

---

## Relationship to PIPELINE.md

The automated Argus pipeline (`docs/PIPELINE.md`) is agent-driven and covers
the full research lifecycle from acquisition to reporting. This playbook covers
the **operator's manual workflow** — what the human does, in what order, with
what tools — and maps to pipeline stages where they overlap.

| Playbook stage | Pipeline stage |
|---|---|
| S0: Pre-Flight | (pre-pipeline) |
| S1: Triage | 1. Acquisition + 2. Recon |
| S2: Preprocessing | (pipeline assumes clean artifact) |
| S3: Static Analysis | 4. Identification |
| S4: Dynamic Analysis | 7. Verification (partial) |
| S5: Solution Derivation | 5. Triage → 6. Exploitation |
| S6: Result Confirmation | 7. Verification + Reporting |
| S7: Post-Mortem | (cross-cutting) |

---

## Stage 0 — Pre-Flight

### Environment verification

Before touching the binary, verify the toolchain is functional:

```sh
# Verify core tools
file --version
readelf --version
strings --version
ghidra --version 2>/dev/null || echo "Ghidra: check PATH"
python3 --version

# Verify 32-bit support (ELF32 targets)
dpkg -l libc6:i386 2>/dev/null || ls /tmp/l32/usr/lib32/libc.so.6 2>/dev/null || \
  echo "WARNING: no 32-bit libc — dynamic analysis blocked for ELF32"

# Verify LJM retrieval is live (if running under LJM context)
jm retrieve --tag reversing --limit 5
```

### Working directory

Create a dedicated analysis directory before starting:

```sh
BINARY_NAME="<target>"
mkdir -p analysis/${BINARY_NAME}/{artifacts,scripts,findings}
cd analysis/${BINARY_NAME}
cp /path/to/binary artifacts/${BINARY_NAME}.orig
```

All derived artifacts (patched binaries, scripts, findings) go under `artifacts/`.
The original binary is never modified in-place — always work on a copy.

---

## Stage 1 — Triage

**Goal:** produce a complete binary profile before touching any analysis tool.
Reading the profile determines what preprocessing is needed and what the
analysis priority order is.

All commands in this stage are deterministic. Output should be recorded.

### 1a. Basic identification

```sh
TARGET="artifacts/${BINARY_NAME}.orig"

file "${TARGET}"
sha256sum "${TARGET}"
wc -c "${TARGET}"
```

Record: architecture, bitness, format (ELF/PE/Mach-O), linkage (static/dynamic),
interpreter path, presence/absence of section headers, BuildID.

### 1b. Segments and sections

```sh
readelf -a "${TARGET}" 2>/dev/null | head -200
# Focus on: program headers (PT_LOAD, PT_DYNAMIC, PT_GNU_STACK),
#            dynamic section (DT_NEEDED, DT_REL, DT_JMPREL, DT_INIT, DT_FINI),
#            section headers (if present)
```

Record: load addresses, permissions (RWX segments are anomalous), whether
section headers are present or stripped.

### 1c. Exports and imports — read these first

```sh
nm -D "${TARGET}" 2>/dev/null | sort
readelf --syms "${TARGET}" 2>/dev/null | grep -E "GLOBAL|WEAK"
```

**This is the highest-signal triage step.** Unusual exports are the challenge
author's breadcrumbs (or the malware author's tells). Read the export list
before looking at any code.

Flag as priority:
- Custom implementations of stdlib functions (strncmp, strcmp, malloc, free)
- Unexpectedly named exports in stripped binaries
- Constructor/destructor entries (_DT_INIT_, _DT_FINI_, .init_array entries)
- Anything that shouldn't be exported for the stated purpose of the binary

### 1d. Relocations

```sh
readelf -r "${TARGET}" 2>/dev/null
```

Record: DT_REL entries, DT_JMPREL entries, relocation types. Unusual relocation
types (R_386_PC32 in .text) or offsets pointing into code sections indicate
relocation-based obfuscation.

### 1e. Strings

```sh
strings -n 8 "${TARGET}" | sort -u
strings -n 8 -e l "${TARGET}" 2>/dev/null | sort -u  # UTF-16LE (PE targets)
```

Record: printable strings that suggest purpose, flag format, XOR-encoded strings
(high byte density, non-printable ratio), version/build strings.

### 1f. Entropy scan

```sh
python3 -c "
import sys
data = open('${TARGET}','rb').read()
from collections import Counter
def entropy(b):
    import math
    c = Counter(b)
    t = len(b)
    return -sum((v/t)*math.log2(v/t) for v in c.values())
chunk = 256
print(f'File size: {len(data)} bytes')
print(f'Full file entropy: {entropy(data):.2f} bits/byte')
for i in range(0, min(len(data), 4096), chunk):
    e = entropy(data[i:i+chunk])
    if e > 7.0:
        print(f'  High entropy region: offset 0x{i:x}-0x{i+chunk:x} ({e:.2f})')
"
```

High-entropy regions (>7.0 bits/byte) in otherwise low-entropy binaries indicate
packed/encrypted blobs. Note file offsets for preprocessing.

### 1g. Anti-analysis inventory

Before proceeding, enumerate all anti-analysis mechanisms. Do not deep-dive
into any of them yet — just list them.

Common patterns to note:
- `ptrace()` in imports or constructor → anti-debug
- `E8 FC FF FF FF` call pattern + R_386_PC32 relocations → relocation obfuscation
- High-entropy RW segments → encrypted blob(s)
- Custom export of stdlib function → hooking/backdoor
- Non-standard DT_INIT/DT_FINI → constructor/destructor chains
- RWX segments → self-modifying code or shellcode staging

Record each mechanism and whether it is **blocking** (prevents analysis) or
**non-blocking** (annotatable and passable). Only blocking mechanisms warrant
deep investigation before proceeding.

### Triage output

Before leaving S1, produce a one-paragraph triage summary:

```
Binary: <name>, <arch>/<bits>, <format>, <linkage>
Interesting exports: <list or "none">
Preprocessing needed: <yes/no — what>
Anti-analysis: <list and blocking/non-blocking status>
Analysis priority: <what to look at first, based on exports>
```

---

## Stage 2 — Preprocessing

**Goal:** produce a single clean analysis artifact that reflects runtime state.
All analysis in S3 and beyond operates on this artifact, not the original.

### 2a. Decision gate

Preprocessing is required when any of the following are true:
- XOR-encrypted blob detected (high entropy RW segment, decrypt loop in main)
- Packed binary (UPX, custom packer, LZMA/zlib segment)
- Self-decrypting shellcode staged at runtime

If none of these apply, skip to S3 and use the original binary.

### 2b. Blob extraction and decryption

For XOR-encrypted blobs (common pattern: decrypt loop in main, blob in RW segment):

```python
#!/usr/bin/env python3
# artifacts/scripts/decrypt_blob.py
# Adapt to the specific binary.

BIN_PATH  = "artifacts/<binary>.orig"
PATCH_OUT = "artifacts/<binary>.patched"
BLOB_FOFF = 0x????      # file offset of encrypted blob
BLOB_SIZE = 0x????      # size in bytes
XOR_KEY   = b"\x??"    # single-byte or multi-byte key

data = bytearray(open(BIN_PATH, "rb").read())
blob = data[BLOB_FOFF:BLOB_FOFF + BLOB_SIZE]
key  = XOR_KEY * (BLOB_SIZE // len(XOR_KEY) + 1)
for i in range(BLOB_SIZE):
    data[BLOB_FOFF + i] = blob[i] ^ key[i]

open(PATCH_OUT, "wb").write(bytes(data))
print(f"Patched binary written: {PATCH_OUT}")
print(f"Blob @ 0x{BLOB_FOFF:x}, {BLOB_SIZE} bytes, key {XOR_KEY.hex()}")
```

Verify the decryption is correct before proceeding:

```sh
# Verify: first 16 bytes of decrypted region should look like valid code or data
python3 -c "
data = open('artifacts/<binary>.patched','rb').read()
print(data[0x????:0x????+16].hex())  # should not be high-entropy garbage
"
```

### 2c. Artifact naming convention

```
artifacts/<binary>.orig          — original, never modified
artifacts/<binary>.patched       — preprocessing output, primary analysis target
artifacts/scripts/decrypt_blob.py — preprocessing script (committed, reproducible)
```

The preprocessing script is the reproducibility record. Anyone running it against
`.orig` should produce the same `.patched` output bit-for-bit.

---

## Stage 3 — Static Analysis

**Goal:** reconstruct program logic to identify the comparison point, key material,
and answer derivation path. This is the primary analysis stage.

### 3a. Tool selection

| Situation | Primary tool | Secondary |
|---|---|---|
| ELF (any arch), PE (any arch), Mach-O — general analysis | Ghidra or IDA | Capstone (targeted) |
| Binja session loaded (Argus pipeline) | Binary Ninja HLIL | Ghidra |
| ARM/MIPS/custom arch | Ghidra (with processor plugin) | objdump |
| Raw shellcode region | Capstone (targeted) | defuse.ca online assembler |
| Verification of specific bytes | Capstone or `xxd` | — |

**Capstone is a secondary/verification tool, not a primary.** It shows
on-disk bytes without relocation patching. Use it to verify specific byte
sequences after the decompiler has established context, never as the first
lens on the binary.

### 3b. Ghidra initial setup (ELF targets)

```
1. Import the PATCHED binary (artifacts/<binary>.patched)
2. Options → Perform Symbol Relocations: UNCHECK if decompilation is broken by
   incorrect relocation application. Leave checked by default.
3. Auto-analyze with defaults. Wait for completion.
4. Open Symbol Tree → Exports pane. Read it. Note anything unusual.
5. Open the Defined Data section. Note any cross-references to unusual symbols.
```

### 3c. Analysis sequence — always follow this order

**Step 1: Read exports pane before looking at code.**
The export list defines the analysis priority order. Unusual exports are
intentional signals.

**Step 2: Identify main control flow branches.**
Find `main` (or entry if stripped). Identify all major branches:
- argc/argv checks
- Anti-debug conditions (ptrace, timing, IsDebuggerPresent)
- Decryption/staging loops
- The "real" path vs. dead-end paths

Map all branches before going deep on any one of them.

**Step 3: Follow the interesting path to the comparison.**
In reversing challenges: the comparison is the target — find it.
In vulnerability research: the interesting path is the one that reaches
untrusted input handling.

**Step 4: Inspect all unusual exports before any other deep analysis.**
If the export list flagged a custom strncmp, malloc, etc. — analyze those
functions completely before continuing with the main path analysis.

**Step 5: Extract all key material.**
Once the comparison and any encoding/decryption is understood, extract:
- XOR keys (byte values, as hex)
- Comparison targets (byte arrays, as hex)
- Encoding sequence (what key applies to what, in what order)

### 3d. Non-deterministic step framework

Non-deterministic steps are those where the analysis involves interpretation:
reading decompiler output, inferring intent from assembly, identifying which
of several code paths is the "real" one.

For every non-deterministic step, follow this structure:

**1. State the question explicitly.**
> "What is the XOR key used to decode the string at [ebp-0x6d]?"
> "Which argument to strncmp is the stored password vs. user input?"
> "Does the ptrace check in the constructor affect the comparison path?"

Questions must be specific enough that two analysts reading the same code
would produce the same answer. If the question is too broad, break it down.

**2. State what the expected output format is.**
> "A single hex byte or multi-byte sequence."
> "The argument number (1 or 2) and the corresponding variable name."
> "Yes/No with the condition that determines branching."

**3. Read the decompiler output against the question. Derive the answer.**

**4. State the answer and how it was derived.**
> "XOR key is 0x0A. Derived from: `xor eax, 0xa` at shellcode offset 0x6e,
>  applied to each byte of [ebp-0x6d] through [ebp-0x6d+strlen(buf)]."

**5. Validate the answer by an independent method.**

Every non-deterministic conclusion must be validated by at least one
independent method. The validation is deterministic — it either confirms
or refutes.

| Conclusion type | Primary derivation | Acceptable validation |
|---|---|---|
| XOR key | Decompiler instruction read | Apply key to ciphertext; verify output is printable/valid |
| String encoding | Decompiler byte sequence | Python decode; verify output matches expected context |
| Comparison argument order | Decompiler variable trace | Trace register state from call site; or dynamic confirmation |
| Code path reachability | Decompiler control flow | Verify no unconditional branch exits before the path; or dynamic |
| Custom function semantics | Decompiler + ASM | Cross-reference with known stdlib semantics; verify behavior on edge case |

**6. Record the question, answer, derivation, and validation method.**
This is what makes the analysis replicable — the path to the conclusion,
not just the conclusion.

### 3e. Static analysis output

Before leaving S3, record:

```
Key material:
  <component>: <value> (hex), derived from: <source + method>, validated by: <method>

Comparison:
  Function: <name or address>
  Arg1: <description> (stored/expected)
  Arg2: <description> (user input / candidate)
  Comparison length: <value or expression>

Candidate answer: <decoded value>
Confidence: <high / medium / low>
Confidence rationale: <why>
```

---

## Stage 4 — Dynamic Analysis

**Goal:** secondary confirmation when static analysis leaves ambiguity. This
stage is conditional — run only when S3 confidence is medium or lower, or when
static analysis cannot resolve a specific question.

Dynamic analysis is **not** the primary path. Static + validation in S3 should
produce high confidence in most cases.

### 4a. Decision gate

Trigger S4 when any of the following are true:
- Multiple code paths could plausibly be the "real" path and static analysis
  cannot distinguish
- Relocation-dependent behavior cannot be traced statically (dynamic linker
  resolves at runtime in a way that's hard to follow)
- A custom memory allocation/dispatch scheme makes argument tracing unreliable
- S3 confidence is explicitly medium or lower

### 4b. Environment setup for ELF32

```sh
# Verify 32-bit libs
ls /tmp/l32/usr/lib32/libc.so.6 2>/dev/null && \
  echo "32-bit libs available" || echo "WARNING: 32-bit libs not found"

# Run with expected arguments
echo "<candidate_answer>" | \
  LD_LIBRARY_PATH=/tmp/l32/usr/lib32 \
  /tmp/l32/usr/lib32/ld-linux.so.2 \
  ./artifacts/<binary>.patched <args>
```

### 4c. What to record

- Exact command used (copy-pasteable)
- Exit code
- stdout/stderr verbatim
- Whether output matches static prediction

If dynamic output contradicts static prediction, the contradiction is the
finding — do not discard the static analysis, resolve the discrepancy.

---

## Stage 5 — Solution Derivation

**Goal:** produce the final answer from confirmed key material.

### 5a. Derivation script

Every derivation must be expressed as a Python script in `artifacts/scripts/`:

```python
#!/usr/bin/env python3
# artifacts/scripts/solution.py

# Stored/encoded bytes — source: [reference to binary address or decompiler output]
stored = bytes([...])

# Decoding — key and operation — source: [reference to custom function or instruction]
key    = 0x??
answer = bytes(b ^ key for b in stored)

print(f"Decoded: {answer}")
print(f"Flag:    HTB{{{answer.decode('ascii')}}}")  # adjust format per challenge

# Verification: answer XOR'd back with key should equal stored
assert bytes(b ^ key for b in answer) == stored, "Round-trip check failed"
```

The script must include:
- The source of the stored bytes (binary address or decompiler output)
- The source of the key (instruction address or function analysis)
- A round-trip assertion where applicable
- The complete derivation, not just the result

### 5b. Confidence gate for submission

Submit when confidence is **high** — do not wait for certainty.

| Confidence | Definition | Action |
|---|---|---|
| High | Key material derived, validation passed, derivation script round-trips | Submit. Continue analysis in parallel if time permits. |
| Medium | Key material derived but validation method was not independent | Submit. Flag as provisional. Identify what would make it high. |
| Low | Key material uncertain, multiple candidates | Do not submit. Identify the specific ambiguity. Return to S3. |

**Never hold a high-confidence answer pending further analysis.** The platform's
accept/reject is immediate feedback. Submit and continue.

---

## Stage 6 — Result Confirmation

### 6a. Success path

```
Answer submitted → accepted → record in findings/<challenge>/flag.txt
```

Record format for flag.txt:
```
## <ChallengeName>
<flag>
[Source: <brief description of key material and derivation>]
```

### 6b. Rejection path

When a high-confidence answer is rejected:

**Step 1: Verify the submission format.**
- Check case sensitivity
- Check wrapping (HTB{} vs. raw vs. FLAG{})
- Check for leading/trailing whitespace

**Step 2: Verify the derivation script output directly.**
Run `python3 artifacts/scripts/solution.py` and copy the output verbatim.
Do not type the flag manually.

**Step 3: Re-examine confidence level.**
Did any assumption in the derivation go unvalidated? Specifically:
- Was the comparison argument order confirmed (not assumed)?
- Was the full comparison length confirmed (not truncated at `n`)?
- Was the key applied to the right bytes (not a subset)?

**Step 4: Check platform state.**
If steps 1-3 produce no error, the analysis is correct and the platform is wrong.
Check: challenge age, retirement status, HTB forum for the specific challenge,
recent writeups dated within the last 12 months. Do not continue technical
analysis — the problem is no longer technical.

### 6c. Platform issue confirmation

If platform state is the problem:
1. Record the confirmed-correct answer in `findings/<challenge>/flag.txt` with a note
2. File a report with the platform (HTB support or forum post)
3. Move on — do not re-derive

---

## Stage 7 — Post-Mortem

Every completed analysis (success or failure) produces a post-mortem entry.
Record in the LJM buffer (`D:\Repos\LLM\LittleJohnnyMnemonic\Buffer\`).

The buffer entry must answer:

1. **What worked as expected?** (methods that produced correct results quickly)
2. **What took longer than it should have?** (detours, rabbit holes, wrong assumptions)
3. **What would have saved the most time?** (tool choice, sequencing, early submission)
4. **Any mechanism that was novel or surprising?** (high-surprise observations → high buffer score)
5. **Methodology update needed?** (if the answer to #3 identifies a recurring pattern,
   this playbook should be updated)

If a methodology update is needed, make the change to this document in the same commit
as the post-mortem buffer entry. The two are linked.

---

## Tooling Reference

### By task

| Task | Tool | Command pattern |
|---|---|---|
| Binary identification | `file` | `file <binary>` |
| Segment/section layout | `readelf` | `readelf -a <binary>` |
| Exports/imports | `nm` | `nm -D <binary>` |
| Relocations | `readelf` | `readelf -r <binary>` |
| String extraction | `strings` | `strings -n 8 <binary>` |
| Entropy scan | Python | See S1f template |
| XOR decryption | Python | `bytes(b ^ key for b in blob)` |
| Binary patching | Python | Write bytes at file offset (see S2b template) |
| Decompilation | Ghidra / IDA / Binja | Load patched binary |
| Targeted disassembly | Capstone | `Cs(CS_ARCH_X86, CS_MODE_32/64)` |
| Online disassembly | defuse.ca | Paste hex, verify |
| XOR decode verification | CyberChef / Python | Apply key, verify output |
| Dynamic execution (ELF32) | ld-linux.so.2 | See S4b template |
| Dynamic execution (ELF64) | direct | `./<binary> <args>` |

### Tool preference order (analysis)

```
1. Ghidra (or IDA) — decompiler view, primary
2. Binary Ninja HLIL — when Argus pipeline session is loaded
3. objdump — when Ghidra fails or for quick targeted reads
4. Capstone — secondary/verification only
5. defuse.ca — shellcode/isolated region verification
```

---

## Recurring Anti-Analysis Patterns

Patterns encountered in Argus workloads. When identified in S1, note the mechanism
and confirm it's handled by the primary tool before deep-diving.

| Pattern | Signature | Primary tool handles? | Fallback if not |
|---|---|---|---|
| R_386_PC32 call obfuscation | `E8 FC FF FF FF` + DT_REL entries at addr+1 | Ghidra (auto relocation) | Read DT_REL directly; calculate `S + A - P` |
| Custom stdlib export | Unusual symbol in `nm -D` exports | n/a — always inspect | Analyze the custom function before main |
| Anti-debug via ptrace | ptrace() in DT_INIT or constructor | Patch or ignore in Ghidra | Note flag variable; trace through main conditionals |
| XOR blob in RW segment | High entropy, decrypt loop in main | Patch before loading (S2) | Capstone + manual decode |
| XOR-encoded strings | Non-printable bytes, XOR loop before puts/printf | Decompiler loop analysis | Byte-by-byte XOR with candidate key |
| RTLD_NEXT dlsym | `push -1; call dlsym` | Ghidra (shows 0xffffffff) | RTLD_NEXT = (void*)-1; finds next symbol after caller |
| argc-gated paths | Multiple argc branches in main | Decompiler control flow | Test all argc values dynamically |

---

## Non-Deterministic Step Checklist

Quick reference for S3 analysis steps where interpretation is involved.
Check each before recording the answer as confirmed.

```
[ ] Question stated explicitly and specifically
[ ] Expected output format defined
[ ] Answer derived from decompiler/ASM output
[ ] Derivation recorded (not just the answer)
[ ] Validated by at least one independent method
[ ] Validation method recorded
[ ] Round-trip check performed (where applicable)
[ ] Argument ordering confirmed (not assumed)
[ ] Comparison length confirmed (not assumed equal to n)
[ ] Key application scope confirmed (full buffer, not first n bytes)
```

---

---

## Windows Service Binary Supplement

Applies when the analysis target is a Windows service or system binary
(SYSTEM/LocalService/NetworkService privilege, exposes RPC/COM/ALPC
interface, or is part of a multi-DLL service cluster). Supersedes the
general S1–S3 order for these targets — the IPC surface is the analysis
entry point, not the export list.

### Cluster scoping (do before any single-binary analysis)

Map the full service cluster before touching any individual binary.
A cluster is the set of binaries that cooperate to implement the service's
attack surface. Single-binary taint analysis misses inter-process primitives.

Minimum cluster inventory:

```
Service host:   the .exe that registers the service (e.g. MsMpEng.exe)
IPC proxy DLL:  the .dll that exposes the RPC/COM interface (e.g. MpSvc.dll)
Client DLL:     the .dll callers link against (e.g. MpClient.dll)
Comms DLL:      any .dll that handles channel plumbing (e.g. MpCommu.dll)
```

To discover the cluster: `sc qc <service>` (binary path), ProcMon trace
of service startup (DLLs loaded), or static import walk from the service
host executable.

### Analysis order for Windows service binaries

Mandatory first pass — run before any single-function taint:

```
1. rpc_interface.py   → which methods take path / string arguments?
                         (UUID, dispatch table, NDR format-string walk)
2. sddl.py            → which interface entries are reachable by
                         low-privilege callers?
                         (NULL DACL, Everyone/AU execute-or-broader)
3. composition.py     → do any (SDDL-permissive entry, TOCTOU-containing
                         function) pairs exist within call-graph reach?
                         → rpc_callable_path_toctou (HIGH)
                         → does any path-taking method co-locate with
                           Cloud Files registration?
                         → rpc_callable_cloud_stall (MEDIUM)
```

These three passes define the exploitable surface perimeter. All
downstream taint/heap/crypto analysis is filtered against this perimeter —
a taint finding that is not reachable from a permissive RPC entry is a
lower-priority research candidate, not an actionable finding.

### Cloud Files primitive check

Run `cloud_files.py` against every Windows service binary in the cluster.
The Cloud Files API (`CfRegisterSyncRoot`, `CfConnectSyncRoot`, `CfExecute`,
`CfHydratePlaceholder`) is a timing primitive: a BLOCKING_CALLBACK on
the sync-root freezes the file operation until the callback returns,
holding open any TOCTOU window.

Emit triggers:

| Signal | Condition | Severity |
|---|---|---|
| `cloud_files_import` | Any CF import present | INFO |
| `cloud_files_write_proxy` | CF import + co-located TOCTOU or permissive SDDL | HIGH |

A `cloud_files_write_proxy` finding adjacent to an `rpc_callable_path_toctou`
finding is the full RedSun-class shape (RPC entry → TOCTOU race → SYSTEM
write routed through attacker-controlled junction).

### Cross-binary reachability caveat (composition.py v1 limitation)

`composition.py` v1 operates within a single binary's call graph.
For clusters where the SDDL-protected RPC entry lives in one DLL and
the path-taking function lives in another (e.g., entry in `MpSvc.dll`,
TOCTOU in `MpCommu.dll`), the same-binary pass will miss the composition.

Workaround: run the three passes against each DLL in the cluster
independently, then manually check whether any HIGH/MEDIUM findings
in different DLLs are connected via the cluster's known dispatch path.
`composition.py` v2 (Tier 1.7, cross-binary reachability) will automate
this. Until it lands, document the manual composition step in the
findings if the signals span module boundaries.

### Triage output supplement (Windows service)

Extend the S1 triage summary with:

```
Cluster members: <list of DLLs + EXE in the service cluster>
RPC interface: <UUID if found, else "not found">
Path-taking methods: <list from rpc_interface.py output, or "none">
SDDL permissiveness: <permissive / restrictive / not found>
Cloud Files: <imports present / absent>
Composition result: <rpc_callable_path_toctou / rpc_callable_cloud_stall / none>
Cross-binary gap: <yes/no — which signals span module boundaries>
```

---

## Revision Log

| Date | Change | Trigger |
|---|---|---|
| 2026-05-10 | Initial document | BombsLanded post-mortem: Capstone-as-primary, no preprocessing step, exports not read at triage, no early submission discipline |
| 2026-05-13 | Windows Service Binary Supplement | NightmareEclipse post-mortem: single-binary analysis order misses IPC surface for service cluster targets; RPC→SDDL→Composition must precede taint for Windows service binaries |
