# Binary Ninja Python API — cookbook reference

Build-time reference for Argus binary-analysis skills. Mirrors
the canonical Binary Ninja cookbook
(<https://docs.binary.ninja/dev/cookbook.html>) with API surface
keyed to Argus's needs (taint, heap, surface, chains, obfuscation
detection).

When a skill module needs an API call it can't recall, search this
file first; fall back to the upstream cookbook only when the entry
isn't here.

> **Source.** Ingested 2026-04-30 from the upstream cookbook. The
> upstream is the source of truth for API drift; this file is a
> snapshot. Re-fetch + diff at minor-version bumps of Binary Ninja.

---

## 1. Loading binaries

### Basic file loading

```python
from binaryninja import load

# Context manager (recommended — auto-close)
with load('/bin/ls') as bv:
    if bv is not None:
        print(f"{bv.arch.name}: {hex(bv.entry_point)}")

# Manual management
bv = load('/bin/ls')
if bv is not None:
    print(f"Loaded {bv.file.filename}")
    bv.file.close()                       # Prevents memory leaks
```

**Argus pattern.** All `analysis/*.py` modules use the context-
manager form via `scripts/lib/binja.py:open_binary()`. Direct
`load()` calls in skill modules are an anti-pattern — they leak
file handles on exception paths.

**Key APIs:**
- `load(path, options=None, update_analysis=True)` — primary entry
- `bv.arch.name` — architecture identifier
- `bv.entry_point` — binary entry address
- `bv.file.filename` — source file path
- `bv.file.close()` — release resources

### Loading with analysis options

```python
bv = load('/bin/ls', options={
    'loader.imageBase': 0xfffffff0000,
    'loader.macho.processFunctionStarts': False,
    'analysis.mode': 'basic'
})
```

Common options:
- `loader.imageBase` — set base address
- `loader.macho.processFunctionStarts` — macOS-specific parsing
- `analysis.mode` — `basic` / `intermediate` / `full`

### Loading databases

`.bndb` files load via the same API:

```python
bv = load('/path/to/analysis.bndb')
```

### Controlling analysis

```python
bv = load('/bin/ls', update_analysis=False)
if bv is not None:
    bv.update_analysis_and_wait()       # synchronous
    bv.file.close()
```

**Argus pattern.** For batch / pipeline runs, prefer
`update_analysis=False` + explicit
`bv.update_analysis_and_wait()`. Lets the caller log progress and
catch analysis hangs / OOMs deterministically.

---

## 2. Working with functions

### Enumeration

```python
for func in bv.functions:
    print(func.name)
    print(func.start)
    print(func.parameter_vars)
    print(func.return_type)
```

**Key APIs:**
- `bv.functions` — iterator
- `func.name`, `func.start`, `func.parameter_vars`, `func.return_type`
- `func.total_bytes` — size in bytes

### Lookup

```python
# By name (may have multiple matches — symbol clashes across modules)
func = bv.get_functions_by_name(name)[0]

# At specific address
func = bv.get_function_at(address)

# Containing address (single)
func = bv.get_function_containing(address)

# Containing address (all overlapping — share-tail / chained-prologue cases)
funcs = bv.get_functions_containing(address)
```

**Argus pattern.** Use `get_functions_containing` (plural)
defensively — share-tail optimisation produces overlapping
function regions in real binaries. Single-result lookup misses
the overlap.

### Selection helpers

```python
largest = max(bv.functions, key=lambda x: x.total_bytes)
connected = max(bv.functions, key=lambda x: len(x.callers + x.callees))
```

---

## 3. Cross-references and call graphs

### Caller analysis

```python
current_function.callers                # Function objects calling this one

for site in current_function.caller_sites:
    addr = site.address                 # Call site address
    inst = site.hlil                    # HLIL instruction at site
```

### Callee analysis

```python
for site in current_function.call_sites:
    addr = site.address                 # Address of call instruction
    inst = site.hlil                    # HLIL call expression
```

**Argus pattern — chain detection.** Chains compose via callgraph
walks: identify primitive site, walk `caller_sites` to find the
calling stage, repeat. `analysis/chains.py` builds chain
matchers as ordered call-graph traversals.

**Key APIs:**
- `func.callers` — list of Function objects
- `func.caller_sites` — list of ReferenceSource (address + HLIL)
- `func.callees` — list of called Function objects
- `func.call_sites` — list of ReferenceSource
- `site.address`, `site.hlil`

### Code- and data-refs at an address

```python
# Cross-references to an address
for ref in bv.get_code_refs(addr):
    print(ref.address, ref.function)

for ref in bv.get_data_refs(addr):
    print(hex(ref))                     # data-ref returns address only
```

These are not in the cookbook explicitly but are the canonical
xref entry points. Skills use them to find call sites for
imported APIs (taint sinks, surface signals).

---

## 4. IL representations

### All IL forms of a function

```python
for func in bv.functions:
    low_level_il        = func.llil
    low_level_il_ssa    = func.llil.ssa_form
    medium_level_il     = func.mlil
    medium_level_il_ssa = func.mlil.ssa_form
    high_level_il       = func.hlil
    high_level_il_ssa   = func.hlil.ssa_form
    base_function       = func.hlil.source_function
```

**Argus pattern — choosing IL.**
- **HLIL** for human-readable display, manual-workflow
  reproduction, report rendering.
- **MLIL SSA** for taint analysis (clean def-use chains, register
  / memory unified, unambiguous variable identity).
- **LLIL** when an analysis must reason about exact assembly —
  e.g., direct-syscall stub recognition (need the raw `syscall`
  + register pre-loads).

### Iterating decompiled instructions

```python
# Direct instruction iteration
for inst in func.hlil.instructions:
    print(f"{inst.address} : {inst}")

# Basic-block iteration
for bb in func.hlil:
    for inst in bb:
        print(f"{inst.address} : {inst}")

# All HLIL in binary (whole-program scan)
for inst in bv.hlil_instructions:
    print(f"{inst.address} : {inst}")
```

### Cross-IL mapping

```python
func = bv.get_functions_containing(address)[0]
llil_inst = func.get_llil_at(address)

# Approximate mappings (single-instruction, may be lossy)
hlil_inst = llil_inst.hlil
mlil_inst = hlil_inst.mlil
llil_inst = hlil_inst.llil

# Many-to-one mappings (accurate, all contributors)
mlils = hlil_inst.mlils
llils = hlil_inst.llils
```

**Argus pattern.** When tracing a finding from HLIL (where the
report renders) down to the actual machine bytes (where the PoC
needs to land its payload offset), use the plural-form mappings
(`hlil_inst.llils`) — singular `hlil_inst.llil` returns only the
first contributor and silently loses information.

---

## 5. Variables and SSA def-use

### Variable enumeration

```python
all_vars          = func.vars               # All variables
hlil_vars         = func.hlil.vars          # HLIL-visible
hlil_aliased_vars = func.hlil.aliased_vars  # Including memory aliases
parameter_vars    = func.parameter_vars     # Parameters
```

### Storage and type

```python
var = hlil_vars[0]
if var.source_type == StackVariableSourceType:
    print(var.storage)                  # Stack offset
print(abs(var.storage))                 # Max variable size
print(abs(var.type.width))              # Type-annotated size
```

### SSA def-use chains — taint primitive

```python
hlil_ssa = func.hlil.ssa_form
ssa_vars = hlil_ssa.ssa_vars

def_inst = hlil_ssa.get_ssa_var_definition(ssa_var)
use_insts = hlil_ssa.get_ssa_var_uses(ssa_var)
```

**Argus pattern — taint propagation.** `analysis/taint.py`'s core
loop:

```python
worklist = initial_sources(...)
seen = set()
while worklist:
    var = worklist.pop()
    if var in seen: continue
    seen.add(var)
    for use in hlil_ssa.get_ssa_var_uses(var):
        if is_sink(use):
            yield Finding(...)
        # propagate through use's defined SSA vars
        for new_var in defined_ssa_vars(use):
            worklist.append(new_var)
```

The MLIL SSA form is preferred over HLIL SSA for unambiguous
register / memory unification.

### SSA variable identity

```python
inst = current_il_instruction          # MediumLevelILVarSsa or similar
ssa_form = inst.ssa_form                # SSAVariable wrapper
def_inst = func.hlil.ssa_form.get_ssa_var_definition(ssa_form.src)
```

**Type distinction.**
- `MediumLevelILVarSsa` / `HighLevelILVarSsa` — *instruction* that
  reads / writes an SSA variable.
- `SSAVariable` — the variable itself (`.src` accessor on the
  instruction).

### Querying parameter values (range analysis)

```python
for ref in current_function.caller_sites:
    if isinstance(ref.hlil, Call) and len(ref.hlil.params) >= 3:
        param = ref.hlil.params[2]
        print(param.possible_values)    # range / constant analysis
```

**Argus pattern.** `possible_values` is the entry point for
constant-propagation: confirms an integer is constant, in a small
range, or a stack pointer. Useful for filtering false positives
in heuristics where the sink argument is a known-safe constant
literal at every call site.

---

## 6. Searching and pattern matching

### Byte / text search

```python
bv.find_next_data(start_addr, b"\x90" * 10)    # NOP-slide
bv.find_next_text(addr, "/etc/passwd")         # disassembly text
```

**Argus pattern.** `heuristics/syscalls.py` uses
`find_next_data` to locate NTDLL syscall-stub prologue sequences
(`mov r10, rcx; mov eax, imm32; syscall`) outside the NTDLL
image, marking direct-syscall-stub candidates.

---

## 7. Sections, segments, memory map

(Not heavily covered in cookbook; key APIs gleaned from upstream
docs:)

- `bv.sections` — dict of named sections (`.text`, `.rodata`, ...)
- `bv.segments` — list of segments with permissions
- `bv.read(addr, length)` — raw byte read
- `bv.write(addr, bytes)` — raw byte write (rare in analysis)

---

## 8. Strings

- `bv.strings` — iterator of detected strings
- `string.value`, `string.start`, `string.length`, `string.type`

**Argus pattern — obfuscation detection.** When `bv.strings`
returns sparse / low-entropy output relative to binary size, the
binary likely uses runtime decryption (LCG-XOR / String-cipher
class). `analysis/obfuscation.py` cross-checks high-entropy
`.rodata` regions against the missing-strings signal.

---

## 9. Annotations and tags

```python
# Address tag
bv.add_tag(address, "Crashes", "Description")

# Function tag
current_function.add_tag("Important", "Look at this later!")

# Function tag at specific offset
current_function.add_tag("Bug", "Possible overflow?", address)
```

**Argus pattern.** `analysis/*.py` modules tag findings inline so
that a human running the same binary in Binja UI sees the
toolchain's marks. Tag categories: `Argus.DETECTED`,
`Argus.CONFIRMED`, `Argus.PROVEN`, `Argus.RESEARCH_CANDIDATE`.

---

## 10. Type management

```python
current_function.type = Type.function(Type.void(), [])

Type.function(return_type, param_types)
Type.void()
Type.int(width, signed=True)
```

**Argus pattern.** Source-guided analysis (Phase 2) imports
ground-truth types from the source build and applies via
`func.type =` to improve downstream analysis precision.

---

## 11. Plugin development

The plugin/UI APIs are not heavily used by Argus's
**headless** pipeline but are relevant for the manual-workflow
companion docs (operator running interactively).

### UIAction with hotkey

```python
from binaryninja import log_info, mainthread
from binaryninjaui import UIAction, UIActionHandler, Menu
from PySide6.QtGui import QKeySequence

def range_action(ctx):
    bv = ctx.binaryView
    start = ctx.address
    length = ctx.length
    log_info(f"{bv} {start} {length}")

UIAction.registerAction("Trigger Range", QKeySequence("F3"))
UIActionHandler.globalActions().bindAction("Trigger Range",
                                           UIAction(range_action))
Menu.mainMenu("Plugins").addAction("Trigger Range", "Plugins")
```

### PluginCommand (simpler)

```python
from binaryninja import PluginCommand

def action(bv, start, length):
    log_info(f"{bv} {start} {length}")

PluginCommand.register_for_range("Action", "Description", action)
```

### Magic console variables

```python
from binaryninja import PythonScriptingProvider

def get_my_foo(instance):
    return instance.interpreter.active_addr & 0xffffff

PythonScriptingProvider.register_magic_variable("my_foo", get_my_foo)
```

### UI context (open new tab)

```python
from binaryninja.binaryview import BinaryView
from binaryninjaui import FileContext, UIContext

data = BinaryView.new(b'\x00\x00\x01')
context = FileContext(data.file, data, '')
execute_on_main_thread(
    lambda: UIContext.activeContext().openFileContext(context)
)
```

---

## 12. Version checking

```python
from binaryninja import core_version_info, CoreVersionInfo

if core_version_info() >= CoreVersionInfo(5, 1, 8104):
    print("New API available")

if core_version_info() >= CoreVersionInfo("4.2.0"):
    print("Version 4.2.0+")

version = core_version_info()
print(f"{version.major}.{version.minor}.{version.build}-{version.channel}")
```

**Argus pattern.** Skill modules that depend on a specific Binja
version (e.g., a new IL feature) check at module-import time and
fall back gracefully if older.

---

## 13. Logging

```python
from binaryninja import log

log.log_debug("Hidden by default")
log.log_info("Console display")
log.log_warn("Yellow text")
log.log_error("Red text")
log.log_alert("Dialog popup")

# Custom log group
log.log_error("Message", "My Log Group")
```

**Argus pattern.** All skill modules log under group `Argus.<module>`
(e.g., `Argus.taint`, `Argus.heap`). Allows operator to filter the
Binja log pane to a single module.

---

## 14. Magic variables in UI / Run-Script context

When using the Binary Ninja UI console or `File → Run Script`:
- `bv` — pre-bound BinaryView for the open binary
- `here` — current cursor address

Headless scripts must construct `bv` explicitly via `load()`.

---

## Argus integration — module-by-module API map

| Argus module | Primary cookbook APIs |
|---|---|
| `analysis/surface.py` | `bv.sections`, `bv.segments`, `bv.strings`, `bv.functions`, hardening flags via PE/ELF header parsing |
| `analysis/taint.py` | `func.mlil.ssa_form`, `get_ssa_var_uses`, `get_ssa_var_definition`, `bv.get_code_refs` |
| `analysis/heap.py` | `func.hlil.instructions`, `func.callers` / `callees` for free-then-use detection |
| `analysis/crypto.py` | `bv.find_next_data` for known PRNG constants, `bv.strings` for hardcoded keys, `func.hlil` for security-tagged sink classification |
| `analysis/mitigations.py` | PE/ELF header parsing, `bv.sections` permissions, segment flags |
| `analysis/obfuscation.py` | `bv.strings` (entropy), `bv.find_next_data` (LCG constants), `func.llil` (CFF dispatch loops) |
| `analysis/chains.py` | `func.caller_sites` / `func.call_sites` for chain composition, multi-function callgraph walks |
| `differ/*` | Two BinaryViews, `func.hlil` edit-distance, `bv.symbols` diff |
| `exploit/gadgets.py` | `bv.read(addr, length)` for raw bytes + capstone for gadget search |
| `verify/debugger.py` | Headless launch + harness; Binja used for offset computation |

---

## Argus quick-reference index

| Task | Primary API |
|------|-------------|
| Load file | `load(path, options={})` |
| All functions | `bv.functions` |
| Lookup function | `bv.get_function_at(addr)` |
| Function containing addr | `bv.get_functions_containing(addr)` |
| HLIL code | `func.hlil.instructions` |
| MLIL SSA | `func.mlil.ssa_form` |
| Function calls (out) | `func.call_sites` |
| Called by (in) | `func.caller_sites` |
| Variables | `func.hlil.vars` |
| SSA def | `il.ssa_form.get_ssa_var_definition(ssa_var)` |
| SSA uses | `il.ssa_form.get_ssa_var_uses(ssa_var)` |
| Pattern search | `bv.find_next_data(addr, pattern)` |
| Code xrefs | `bv.get_code_refs(addr)` |
| Tags | `bv.add_tag(addr, name, note)` |
| Logging | `log.log_info(message, "Argus.<module>")` |
| Version check | `core_version_info() >= CoreVersionInfo(5, 1, 8104)` |
