"""RPC interface enumeration — find dispatch tables, list methods.

For a Windows binary that hosts a native RPC server (registers an
interface via `RpcServerRegisterIf*`), this module locates the
interface's `RPC_SERVER_INTERFACE` structure from a known UUID
anchor, walks its dispatch table, and emits findings naming each
method handler. When combined with a known-vulnerable helper
(e.g., the `MpIsPathSymlink` TOCTOU in Defender's MpSvc.dll), it
identifies WHICH method procnums reach the vulnerable code path —
producing the missing piece for chain-PoC construction.

v1 scope:
  - Input: a UUID (binary GUID bytes or canonical string) + an
           optional "vulnerable-function-name" anchor
  - Search the loaded BV for the binary UUID
  - From each match, identify the `RPC_SERVER_INTERFACE` struct
    (UUID lives at offset +4 of the struct on x64 PE)
  - Read the DispatchTable pointer, then DispatchTableCount and
    the dispatch entries (count at +0, fn-pointer-array pointer
    at +8)
  - For each dispatch entry: emit a dispatch finding listing
    method index + handler function address. Optionally walk
    forward callgraph to an anchor function.
  - Cheap string-hint signal: scan each handler for path-related
    string literals.

Output:
  - One `rpc_interface_dispatch` finding per (interface, method)
    pair, listing method index + handler function address
  - One `remote_callable_vuln_method` finding per method that
    reaches the anchor — the method procnum a PoC should call

Honest limitations of v1
------------------------

Static callgraph reachability from a dispatch handler to a
helper is brittle on MIDL-generated RPC code: the handlers are
NDR-marshal stubs that call the real implementation via an
indirect call. Binja's callees relation doesn't model the
indirect call without dataflow resolution.

Empirically on MpSvc.dll: the walker enumerates all 237
IMpService methods cleanly, but the callgraph link from any
dispatch entry to `MpIsPathSymlink` is invisible to Binja —
the helper has only one direct caller (a CommonUtil function)
and the dispatch handlers reach it through ≥6 layers of
indirect calls.

The string-hint signal (path-touching tokens in handler-
referenced strings) doesn't fire at the dispatch-entry level
either, because handlers reference no user-visible strings —
the strings live in the real implementation behind the
indirect call.

This means **v1 surfaces the interface scaffolding (UUID,
method count, dispatch addresses) but not the per-method
intent.** Identifying which specific procnum to call for a
BlueHammer-class attack requires either:
  (a) A real NDR format-string parser that recovers argument
      types (path methods take `wchar_t *` — methods to call
      take string args; that's a strong static signal)
  (b) Indirect-call resolution via dataflow (MLIL constant
      propagation across the marshal stub)
  (c) Operator inspection of the decompiled dispatch handlers

(a) is the v2 work and is the "right" answer. ~300+ LOC of
NDR format-string walking. v1 ships the skeleton; v2 fills in
per-method semantics.

v2 scanner confirmed gap (2026-05-13, MpSvc.dll 4.18.26030.3011-0):
  The FC_WSTRING (0x25) / FC_C_WSTRING (0x26) direct byte scan in
  _ndr_proc_has_wstring_param MISSES PWSTR parameters encoded as
  Oif-format TypeFormatString offsets. MIDL Oif mode stores parameter
  type descriptors as 2-byte offsets into the TypeFormatString blob;
  the FC_WSTRING / FC_RP bytes appear only in TypeFormatString, not in
  the proc format string.

  Consequence: `ServerMpUpdateEngineSignature` (proc_idx=42, the
  BlueHammer chain target) was NOT found by the v2 scan. The 5
  hits found (37, 38, 125, 141, 208) are real wchar_t* methods but
  are quarantine/sample/DLP handlers. PROC_IDX=42 was confirmed
  via Binja dispatch-table walk + decompile of callees.

  v3 partial fix: scan proc format string for FC_RP/FC_UP inline
  descriptors (pre-Oif encoding or rare explicit pointer params).
  Does not catch proc_idx=42.

  v3b fix (2026-05-14): scan 2-byte aligned WORDs in the proc format
  string as candidate TypeFormatString offsets. For each offset that
  lands in the binary, call _tf_is_wstring_pointer to follow the type
  chain. Catches proc_idx=42: its Oif param descriptor contains WORD
  0x05ce, and TypeFormatString[0x05ce] = FC_WSTRING (0x25) directly.
  TypeFormatString offsets point to FC_RP / FC_UP / FC_FP chains OR
  to FC_WSTRING/FC_C_WSTRING directly; _tf_is_wstring_pointer handles
  both cases.

This is `compose`-class output: it composes a `permissive_sddl`
signal, a `toctou` signal, and the dispatch enumeration into
a single PoC-anchor finding. It's the foundation for the
Phase 3 v2 chain-PoC generator.

Reference structures (NDR / NDR64):

  RPC_SERVER_INTERFACE {
      ULONG  Length;                     // 0x0
      RPC_SYNTAX_IDENTIFIER InterfaceId; // 0x4: GUID + 2x u16 version
      RPC_SYNTAX_IDENTIFIER TransferSyntax; // 0x18
      PRPC_DISPATCH_TABLE DispatchTable; // 0x2c (x86) / 0x30 (x64 aligned)
      ULONG  RpcProtseqEndpointCount;
      ...
  }

  RPC_DISPATCH_TABLE {
      ULONG DispatchTableCount;
      RPC_DISPATCH_FUNCTION DispatchTable[]; // array of fnptrs
      LONG_PTR Reserved;
  }

x64 PE layout (which Defender platform uses): UUID at offset 4,
TransferSyntax at offset 24, DispatchTable pointer at offset 56.
Confirmed empirically; varies between MIDL output flavours so the
walker is defensive.

Knowledge anchor:
- `[[Memory/Knowledge/windows_defender_attack_surface]]` — once
  buffered. The IMpService interface UUID, the MpIsPathSymlink
  TOCTOU shape, and the cross-module replication are documented
  there.
"""
from __future__ import annotations

import struct
from collections import deque
from typing import Optional

from ..output.finding import Evidence, Finding, Severity


CATEGORY_META = {
    "rpc_interface_dispatch": {
        "severity": Severity.INFO,
        "cwe": [],
        "mitre": [],
        "knowledge_refs": [
            "[[Memory/Knowledge/argus_detector_design_principles]]",
        ],
    },
    "remote_callable_path_method": {
        "severity": Severity.MEDIUM,
        "cwe": ["CWE-367"],
        "mitre": ["T1068"],
        "knowledge_refs": [
            "[[Memory/Knowledge/argus_detector_design_principles]]",
            "[[Memory/Knowledge/windows_defender_attack_surface]]",
        ],
    },
    "remote_callable_vuln_method": {
        "severity": Severity.HIGH,
        "cwe": ["CWE-367"],
        "mitre": ["T1068"],
        "knowledge_refs": [
            "[[Memory/Knowledge/argus_detector_design_principles]]",
        ],
    },
}

# Transfer syntax GUIDs in Windows binary (mixed-endian) form.
# NDR32: 8a885d04-1ceb-11c9-9fe8-08002b104860
# NDR64: 71710533-beba-4937-8319-b5dbef9ccc36
_NDR32_TRANSFER_SYNTAX = bytes.fromhex("045d888aeb1cc9119fe808002b104860")
_NDR64_TRANSFER_SYNTAX = bytes.fromhex("33057171babe37498319b5dbef9ccc36")

# NDR format-string FC codes for wide-string path parameters.
# Both codes appear in NDR32 and NDR64 type format strings —
# the byte scan is grammar-agnostic.
_FC_WSTRING   = 0x25  # [string] wchar_t* — null-terminated
_FC_C_WSTRING = 0x26  # conformant (sized) wchar_t*

# FmtStringOffset sentinel for methods with no format string.
_NDR_NO_FORMAT = 0xFFFF


def _uuid_str_to_binary(uuid_str: str) -> bytes:
    """Convert canonical GUID string to Windows binary form
    (Data1 LE u32, Data2 LE u16, Data3 LE u16, Data4 8 bytes BE).
    """
    parts = uuid_str.replace("{", "").replace("}", "").split("-")
    if len(parts) != 5:
        raise ValueError(f"bad uuid: {uuid_str!r}")
    d1 = bytes.fromhex(parts[0])[::-1]
    d2 = bytes.fromhex(parts[1])[::-1]
    d3 = bytes.fromhex(parts[2])[::-1]
    d4 = bytes.fromhex(parts[3]) + bytes.fromhex(parts[4])
    return d1 + d2 + d3 + d4


def _find_binary_occurrences(bv, needle: bytes) -> list[int]:
    """Return all addresses where `needle` appears in bv's data.
    Uses Binja's `find_next_data` walker.
    """
    out = []
    if bv is None or not needle:
        return out
    start = bv.start
    end = bv.end
    # Cap iterations defensively
    max_hits = 64
    cur = start
    while cur < end and len(out) < max_hits:
        try:
            hit = bv.find_next_data(cur, needle)
        except Exception:
            break
        if hit is None:
            break
        if isinstance(hit, tuple):
            hit_addr = hit[0]
        else:
            hit_addr = hit
        if hit_addr is None or hit_addr < cur:
            break
        out.append(int(hit_addr))
        cur = hit_addr + 1
    return out


def _read_qword(bv, addr: int) -> Optional[int]:
    try:
        b = bv.read(addr, 8)
        if len(b) != 8:
            return None
        return struct.unpack("<Q", b)[0]
    except Exception:
        return None


def _read_dword(bv, addr: int) -> Optional[int]:
    try:
        b = bv.read(addr, 4)
        if len(b) != 4:
            return None
        return struct.unpack("<I", b)[0]
    except Exception:
        return None


# Candidate offsets where the DispatchTable pointer sits in the
# RPC_SERVER_INTERFACE structure on x64 PE. Probed in order;
# whichever points to a plausible dispatch-table candidate wins.
_DISPATCH_PTR_CANDIDATE_OFFSETS = (0x30, 0x38, 0x28, 0x40, 0x48)


def _read_dispatch_table(bv, dispatch_ptr: int) -> list[int]:
    """Given a candidate RPC_DISPATCH_TABLE pointer, return the
    list of dispatch-function pointers if it's plausibly a
    dispatch table, else empty list.

    Layout (x64 RPC_DISPATCH_TABLE):
      +0x00  DispatchTableCount    UINT
      +0x04  (padding)
      +0x08  DispatchTable         PRPC_DISPATCH_FUNCTION
                                   (pointer to fn-pointer array)
      +0x10  Reserved              LONG_PTR
    """
    if dispatch_ptr is None or dispatch_ptr <= 0:
        return []
    count = _read_dword(bv, dispatch_ptr)
    if count is None or count < 1 or count > 1024:
        # Plausible range: 1-1024 RPC methods per interface
        # (Defender's IMpService has 237; some big interfaces go higher)
        return []
    # The fn-pointer array is at *(dispatch_ptr + 8), NOT at
    # dispatch_ptr + 8. It's a pointer to a separately allocated array.
    fn_array_ptr = _read_qword(bv, dispatch_ptr + 8)
    if fn_array_ptr is None or fn_array_ptr == 0:
        return []
    if fn_array_ptr < bv.start or fn_array_ptr >= bv.end:
        return []
    entries: list[int] = []
    for i in range(count):
        ptr = _read_qword(bv, fn_array_ptr + i * 8)
        if ptr is None or ptr == 0:
            entries.append(0)
            continue
        # Sanity check: pointer should be inside the binary
        if ptr < bv.start or ptr >= bv.end:
            return []
        entries.append(ptr)
    # Confirm at least half the entries are non-null AND resolve
    # to functions (handler addresses must land in code).
    nonzero = [p for p in entries if p != 0]
    if len(nonzero) < max(1, count // 2):
        return []
    fn_resolved = sum(
        1 for p in nonzero
        if any(bv.get_functions_containing(p) or [])
    )
    if fn_resolved < max(1, len(nonzero) // 2):
        return []
    return entries


def _function_containing(bv, addr: int):
    if bv is None or addr is None:
        return None
    try:
        fs = list(bv.get_functions_containing(int(addr)) or [])
    except Exception:
        return None
    return fs[0] if fs else None


def _reaches(start_fn, target_fn, *, max_depth: int = 16) -> int:
    """BFS forward callgraph reachability. Returns hops if target
    reachable from start, else -1."""
    if start_fn is None or target_fn is None:
        return -1
    target_start = int(getattr(target_fn, "start", 0) or 0)
    if int(getattr(start_fn, "start", 0) or 0) == target_start:
        return 0
    seen = {int(getattr(start_fn, "start", 0) or 0)}
    frontier = deque([(start_fn, 0)])
    while frontier:
        fn, depth = frontier.popleft()
        if depth >= max_depth:
            continue
        try:
            callees = list(getattr(fn, "callees", None) or [])
        except Exception:
            continue
        for c in callees:
            c_addr = int(getattr(c, "start", 0) or 0)
            if c_addr in seen:
                continue
            seen.add(c_addr)
            if c_addr == target_start:
                return depth + 1
            frontier.append((c, depth + 1))
    return -1


def _find_function_by_name_substring(bv, needle: str):
    """Return the first Function whose name contains `needle`."""
    for fn in (bv.functions or []):
        name = getattr(fn, "name", "") or ""
        if needle in name:
            return fn
    return None


# ── NDR v2 helpers ────────────────────────────────────────────────────────────

def _binary_to_uuid_str(b: bytes) -> str:
    """Convert Windows binary GUID (mixed-endian) to canonical string."""
    if len(b) < 16:
        return ""
    d1 = struct.unpack("<I", b[0:4])[0]
    d2 = struct.unpack("<H", b[4:6])[0]
    d3 = struct.unpack("<H", b[6:8])[0]
    return (f"{d1:08x}-{d2:04x}-{d3:04x}-"
            f"{b[8:10].hex()}-{b[10:16].hex()}")


def _read_transfer_syntax(bv, struct_base: int) -> str:
    """Read and classify the RPC_SERVER_INTERFACE TransferSyntax field
    at struct_base + 0x18. Returns 'NDR32', 'NDR64', or
    'unknown:<uuid>' so callers can gate grammar-specific logic.

    NDR32 and NDR64 use different ProcString grammars — a walker that
    conflates them will produce confident wrong type maps. This
    function gates the classification so the NDR walk can annotate
    findings with which dialect was observed, even when the byte-scan
    approach used here is grammar-agnostic.
    """
    try:
        b = bv.read(struct_base + 0x18, 16)
    except Exception:
        return "unknown"
    if not b or len(b) != 16:
        return "unknown"
    if b == _NDR32_TRANSFER_SYNTAX:
        return "NDR32"
    if b == _NDR64_TRANSFER_SYNTAX:
        return "NDR64"
    return f"unknown:{_binary_to_uuid_str(b)}"


def _find_midl_server_info(
        bv, struct_base: int,
) -> tuple[Optional[int], Optional[int]]:
    """Locate MIDL_SERVER_INFO via RPC_SERVER_INTERFACE.InterpreterInfo
    at struct_base + 0x50 (x64 PE layout).

    Returns (proc_string_ptr, fmt_offset_ptr) where:
      proc_string_ptr — base of the NDR format string blob
      fmt_offset_ptr  — base of the u16[] FmtStringOffset table
                        (indexed by procnum → offset into ProcString)

    Returns (None, None) on any navigation or sanity failure.

    MIDL_SERVER_INFO layout (x64):
      +0x00  pStubDesc        PMIDL_STUB_DESC
      +0x08  DispatchTable    const SERVER_ROUTINE*
      +0x10  ProcString       PFORMAT_STRING  ← format string base
      +0x18  FmtStringOffset  const unsigned short*  ← per-method offsets
      +0x20  ThunkTable       const STUB_THUNK*
      +0x28  pTransferSyntax  PRPC_SYNTAX_IDENTIFIER
      +0x30  nCount           ULONG_PTR
      +0x38  pSyntaxInfo      PMIDL_SYNTAX_INFO
    """
    interp_ptr = _read_qword(bv, struct_base + 0x50)
    if not interp_ptr or interp_ptr < bv.start or interp_ptr >= bv.end:
        return None, None, None

    proc_string_ptr = _read_qword(bv, interp_ptr + 0x10)
    fmt_offset_ptr  = _read_qword(bv, interp_ptr + 0x18)

    if (not proc_string_ptr or proc_string_ptr < bv.start
            or proc_string_ptr >= bv.end):
        return None, None, None
    if (not fmt_offset_ptr or fmt_offset_ptr < bv.start
            or fmt_offset_ptr >= bv.end):
        return None, None, None

    # v3: also return the TypeFormatString base (MIDL_STUB_DESC.pFormatTypes
    # at pStubDesc + 0x40) so _ndr_proc_has_wstring_param can follow
    # FC_RP/FC_UP pointer chains into the TYPE format string.
    pstub_desc = _read_qword(bv, interp_ptr + 0x00)
    type_format_ptr: Optional[int] = None
    if pstub_desc and bv.start <= pstub_desc < bv.end:
        tfp = _read_qword(bv, pstub_desc + 0x40)
        if tfp and bv.start <= tfp < bv.end:
            type_format_ptr = tfp

    return proc_string_ptr, fmt_offset_ptr, type_format_ptr


_FC_RP = 0x11  # reference pointer
_FC_UP = 0x12  # unique pointer
_FC_OP = 0x13  # OLE pointer
_FC_FP = 0x14  # full pointer
_FC_SIMPLE_POINTER = 0x08  # flags bit: type descriptor is inline (2 bytes)

_POINTER_FC_CODES = (_FC_RP, _FC_UP, _FC_OP, _FC_FP)


def _tf_is_wstring_pointer(bv, addr: int, depth: int = 0) -> bool:
    """Follow a pointer descriptor chain starting at `addr` in the
    TypeFormatString and return True if it eventually reaches
    FC_WSTRING (0x25) or FC_C_WSTRING (0x26).

    TypeFormatString pointer descriptor layout:
      byte 0: FC_RP / FC_UP / FC_OP / FC_FP
      byte 1: flags (FC_SIMPLE_POINTER = 0x08 → inline type at byte 2)
      bytes 2-3: if not FC_SIMPLE_POINTER:
                   signed 16-bit offset from &byte[2] to the pointee type

    Follows chains up to depth 6 to handle multi-level pointers.
    """
    if depth > 6:
        return False
    try:
        tb = bv.read(addr, 4)
    except Exception:
        return False
    if not tb or len(tb) < 2:
        return False
    fc = tb[0]
    if fc in (_FC_WSTRING, _FC_C_WSTRING):
        return True
    if fc not in _POINTER_FC_CODES:
        return False
    if len(tb) < 4:
        return False
    flags = tb[1]
    if flags & _FC_SIMPLE_POINTER:
        return len(tb) > 2 and tb[2] in (_FC_WSTRING, _FC_C_WSTRING)
    signed_off = struct.unpack_from("<h", tb, 2)[0]
    return _tf_is_wstring_pointer(bv, addr + 2 + signed_off, depth + 1)


def _ndr_proc_has_wstring_param(
        bv,
        proc_string_ptr: int,
        fmt_offset_ptr: int,
        proc_idx: int,
        method_count: int,
        type_format_ptr: Optional[int] = None,
) -> bool:
    """Check whether NDR format string for proc_idx contains a
    wchar_t* path-type parameter.

    v2: direct byte scan for FC_WSTRING (0x25) / FC_C_WSTRING (0x26)
        in the proc format string chunk. Catches [string] wchar_t* params
        encoded inline.

    v3: follow FC_RP (0x11) / FC_UP (0x12) pointer descriptors that appear
        directly in the proc format string into the TypeFormatString and
        check for FC_C_WSTRING there. Handles the encoding where the
        ProcFormatString directly contains an FC_RP byte.

        FC_RP/FC_UP layout in proc format string:
          byte 0: FC_RP or FC_UP
          byte 1: flags (FC_SIMPLE_POINTER = 0x08 → type inline at byte 2)
          bytes 2-3: if FC_SIMPLE_POINTER: inline type code + pad
                     else: signed 16-bit offset from &offset_field into
                           TypeFormatString (computed as:
                           proc_string_ptr + proc_offset + i + 2 + signed_off)

    v3b (Oif format): in Oif-style proc format strings, parameter type
        descriptors do NOT contain inline FC_RP bytes. Instead each 6-byte
        parameter descriptor ends with a 2-byte TypeFormatString offset
        (absolute from type_format_ptr). The FC_RP lives only in the
        TypeFormatString. This path scans every 2-byte aligned WORD in the
        proc chunk as a candidate TypeFormatString offset, then calls
        _tf_is_wstring_pointer to check if it chains to WSTRING.

        Requires type_format_ptr (from MIDL_STUB_DESC.pFormatTypes).

    Scan is bounded by the next method's offset (or 256 bytes). Returns
    False on any read failure or when the method has no format string.
    """
    offset_b = bv.read(fmt_offset_ptr + proc_idx * 2, 2)
    if not offset_b or len(offset_b) != 2:
        return False
    proc_offset = struct.unpack("<H", offset_b)[0]
    if proc_offset == _NDR_NO_FORMAT:
        return False

    scan_len = 256
    if proc_idx + 1 < method_count:
        next_b = bv.read(fmt_offset_ptr + (proc_idx + 1) * 2, 2)
        if next_b and len(next_b) == 2:
            next_offset = struct.unpack("<H", next_b)[0]
            if (next_offset != _NDR_NO_FORMAT
                    and next_offset > proc_offset):
                scan_len = min(next_offset - proc_offset, 256)

    try:
        chunk = bv.read(proc_string_ptr + proc_offset, scan_len)
    except Exception:
        return False
    if not chunk:
        return False

    # v2: fast path — FC_WSTRING / FC_C_WSTRING directly in proc format string.
    if _FC_WSTRING in chunk or _FC_C_WSTRING in chunk:
        return True

    # v3: follow FC_RP / FC_UP pointer descriptors that appear inline in the
    # proc format string (pre-Oif encoding or explicit pointer params).
    for i in range(len(chunk) - 3):
        b = chunk[i]
        if b not in (_FC_RP, _FC_UP):
            continue
        flags = chunk[i + 1]
        if flags & _FC_SIMPLE_POINTER:
            if chunk[i + 2] in (_FC_WSTRING, _FC_C_WSTRING):
                return True
        else:
            signed_off = struct.unpack_from("<h", chunk, i + 2)[0]
            offset_field_va = proc_string_ptr + proc_offset + i + 2
            target_va = offset_field_va + signed_off
            if not (bv.start <= target_va < bv.end):
                continue
            try:
                tb = bv.read(target_va, 1)
            except Exception:
                continue
            if tb and tb[0] in (_FC_WSTRING, _FC_C_WSTRING):
                return True

    # v3b: Oif-format param descriptor scan.
    # In Oif proc format strings the 6-byte parameter descriptor ends with a
    # 2-byte TypeFormatString offset (absolute from type_format_ptr). There is
    # no inline FC_RP in the proc format string — the pointer type lives only in
    # the TypeFormatString. Scan every 2-byte aligned WORD in the proc chunk as
    # a candidate TF offset and follow it through _tf_is_wstring_pointer.
    if type_format_ptr is not None:
        seen: set[int] = set()
        for i in range(0, len(chunk) - 1, 2):
            tf_off = struct.unpack_from("<H", chunk, i)[0]
            # Skip zero and values we've already checked; skip if the TF
            # address falls outside the binary's mapped range.
            if tf_off < 4 or tf_off in seen:
                continue
            seen.add(tf_off)
            tf_addr = type_format_ptr + tf_off
            if not (bv.start <= tf_addr < bv.end):
                continue
            if _tf_is_wstring_pointer(bv, tf_addr):
                return True

    return False


# ─────────────────────────────────────────────────────────────────────────────

# Substrings whose presence in a dispatch handler's referenced
# strings suggests the method touches filesystem paths — i.e. is a
# candidate BlueHammer-class attack-surface entry.
_PATH_TOUCHING_HINTS = (
    "path", "file", "definition", "update", "import", "scan",
    "manifest", "signature", "cab", "vdm", "lkg", "shadow",
    "VolumeShadow", "Reparse", "Symlink", "junction", "open",
)


def _string_refs_in_function(bv, fn) -> list[str]:
    """Return the literal strings referenced by `fn` (via code
    refs from any string in the binary). Filter to printable
    ASCII / UTF-16 of length ≥ 4."""
    out: list[str] = []
    if bv is None or fn is None:
        return out
    fn_start = int(getattr(fn, "start", 0) or 0)
    try:
        # Walk the function's basic blocks; for each instruction,
        # check its data refs (constants pointing into a string
        # section).
        for bb in (getattr(fn, "basic_blocks", []) or []):
            for inst_addr in range(int(bb.start), int(bb.end)):
                try:
                    refs = list(
                        bv.get_data_refs_from(inst_addr) or []
                    )
                except Exception:
                    continue
                for r in refs:
                    try:
                        sv = bv.get_ascii_string_at(int(r), min_length=4)
                    except Exception:
                        sv = None
                    if sv is None:
                        continue
                    val = getattr(sv, "value", None)
                    if val:
                        out.append(val)
    except Exception:
        pass
    return list(set(out))


def find_rpc_interface_methods(
        bv, *,
        interface_uuid: str,
        binary: str,
        arch: str,
        platform: str,
        anchor_function_substring: Optional[str] = None,
        detector: str = "analysis.rpc_interface",
) -> list[Finding]:
    """Locate the RPC interface table for `interface_uuid` and
    enumerate its dispatch methods. If `anchor_function_substring`
    is provided, also emit `remote_callable_vuln_method` findings
    for any method that reaches the anchor in the forward callgraph.
    """
    findings: list[Finding] = []
    if bv is None:
        return findings

    try:
        needle = _uuid_str_to_binary(interface_uuid)
    except ValueError:
        return findings

    occurrences = _find_binary_occurrences(bv, needle)
    if not occurrences:
        return findings

    # For each UUID occurrence, try the candidate dispatch-pointer
    # offsets. The first that yields a plausible dispatch table is
    # the winner. Empirically, the UUID lives at offset +4 of an
    # `RPC_SERVER_INTERFACE` struct (Length field is +0), so the
    # struct base is `occurrence - 4`. The DispatchTable pointer is
    # at struct_base + 0x30 (x64 aligned typical layout).
    discovered: dict[int, list[int]] = {}  # interface_base -> [dispatch entries]
    for occ in occurrences:
        struct_base = occ - 4
        for off in _DISPATCH_PTR_CANDIDATE_OFFSETS:
            disp_ptr = _read_qword(bv, struct_base + off)
            if disp_ptr is None or disp_ptr == 0:
                continue
            entries = _read_dispatch_table(bv, disp_ptr)
            if entries:
                discovered[struct_base] = entries
                break

    if not discovered:
        return findings

    # Resolve anchor function (the vulnerable helper) if requested.
    anchor_fn = None
    if anchor_function_substring:
        anchor_fn = _find_function_by_name_substring(
            bv, anchor_function_substring
        )

    # Emit per-method dispatch findings, plus reachability composites.
    meta_disp = CATEGORY_META["rpc_interface_dispatch"]
    meta_vuln = CATEGORY_META["remote_callable_vuln_method"]
    for interface_base, entries in discovered.items():
        for proc_idx, dispatch_addr in enumerate(entries):
            if dispatch_addr == 0:
                continue
            handler_fn = _function_containing(bv, dispatch_addr)
            handler_name = (
                getattr(handler_fn, "name", "") or f"sub_{dispatch_addr:x}"
            )
            # String-reference signals: cheap hint that the
            # dispatch handler touches filesystem paths (BlueHammer-
            # class candidate).
            handler_strings = _string_refs_in_function(bv, handler_fn) if handler_fn else []
            path_hints = []
            for s in handler_strings:
                sl = s.lower()
                for h in _PATH_TOUCHING_HINTS:
                    if h.lower() in sl:
                        path_hints.append((h, s[:80]))
                        break  # one hit per string is enough
            path_touching = bool(path_hints)
            findings.append(Finding(
                id="",
                category="rpc_interface_dispatch",
                severity=meta_disp["severity"],
                address=int(dispatch_addr),
                function=handler_name,
                binary=binary, arch=arch, platform=platform,
                detector=detector,
                knowledge_refs=list(meta_disp["knowledge_refs"]),
                cwe=list(meta_disp["cwe"]),
                mitre_attack=list(meta_disp["mitre"]),
                confidence=0.9 if not path_touching else 0.7,
                description=(
                    f"RPC interface {interface_uuid} method idx "
                    f"{proc_idx}: dispatch handler {handler_name} at "
                    f"0x{dispatch_addr:x} (interface table at "
                    f"0x{interface_base:x})"
                    + (f"; path-touching string hints: "
                       f"{', '.join(h for h, _ in path_hints[:5])}"
                       if path_touching else "")
                ),
                evidence=[Evidence(
                    kind="rpc_dispatch_entry",
                    source=detector,
                    payload=(f"interface_uuid={interface_uuid} "
                             f"proc_idx={proc_idx} "
                             f"handler=0x{dispatch_addr:x} "
                             f"interface_base=0x{interface_base:x}"),
                    address=int(dispatch_addr),
                    function=handler_name,
                )],
                details={
                    "interface_uuid": interface_uuid,
                    "proc_idx": proc_idx,
                    "handler_addr": hex(int(dispatch_addr)),
                    "interface_table_addr": hex(int(interface_base)),
                    "path_touching_hints": [
                        {"hint": h, "string": s}
                        for h, s in path_hints[:8]
                    ],
                    "path_touching": path_touching,
                },
            ))

            if anchor_fn is None or handler_fn is None:
                continue
            hops = _reaches(handler_fn, anchor_fn, max_depth=16)
            if hops < 0:
                continue
            anchor_name = getattr(anchor_fn, "name", "<anchor>")
            findings.append(Finding(
                id="",
                category="remote_callable_vuln_method",
                severity=meta_vuln["severity"],
                address=int(dispatch_addr),
                function=handler_name,
                binary=binary, arch=arch, platform=platform,
                detector=detector,
                knowledge_refs=list(meta_vuln["knowledge_refs"]),
                cwe=list(meta_vuln["cwe"]),
                mitre_attack=list(meta_vuln["mitre"]),
                confidence=0.85,
                description=(
                    f"RPC method idx {proc_idx} of {interface_uuid} "
                    f"({handler_name}) reaches the anchor "
                    f"`{anchor_name}` in {hops} callee-hop(s). This "
                    f"is the structural property a PoC can exploit: "
                    f"invoking method procnum {proc_idx} via RPC "
                    f"reaches the vulnerable code path."
                ),
                evidence=[Evidence(
                    kind="rpc_method_to_anchor_reachability",
                    source=detector,
                    payload=(f"interface_uuid={interface_uuid} "
                             f"proc_idx={proc_idx} "
                             f"handler={handler_name} "
                             f"anchor={anchor_name} "
                             f"reachability_hops={hops}"),
                    address=int(dispatch_addr),
                    function=handler_name,
                )],
                details={
                    "interface_uuid": interface_uuid,
                    "proc_idx": proc_idx,
                    "handler_function": handler_name,
                    "handler_addr": hex(int(dispatch_addr)),
                    "anchor_function": anchor_name,
                    "reachability_hops": hops,
                },
            ))

    # NDR v2 — format-string walk: identify which dispatch methods
    # accept wchar_t* path parameters. Uses a bounded FC_WSTRING byte
    # scan that works for both NDR32 and NDR64 dialects (FC codes are
    # preserved across grammars; Oi2 header parsing is not needed for
    # the path-type detection signal).
    meta_path = CATEGORY_META["remote_callable_path_method"]
    for interface_base, entries in discovered.items():
        transfer_syntax = _read_transfer_syntax(bv, interface_base)
        proc_string_ptr, fmt_offset_ptr, type_format_ptr = _find_midl_server_info(
            bv, interface_base)
        if proc_string_ptr is None:
            continue
        method_count = len(entries)
        for proc_idx, dispatch_addr in enumerate(entries):
            if dispatch_addr == 0:
                continue
            if not _ndr_proc_has_wstring_param(
                    bv, proc_string_ptr, fmt_offset_ptr,
                    proc_idx, method_count,
                    type_format_ptr=type_format_ptr):
                continue
            handler_fn = _function_containing(bv, dispatch_addr)
            handler_name = (
                getattr(handler_fn, "name", "") or f"sub_{dispatch_addr:x}"
            )
            findings.append(Finding(
                id="",
                category="remote_callable_path_method",
                severity=meta_path["severity"],
                address=int(dispatch_addr),
                function=handler_name,
                binary=binary, arch=arch, platform=platform,
                detector=detector,
                knowledge_refs=list(meta_path["knowledge_refs"]),
                cwe=list(meta_path["cwe"]),
                mitre_attack=list(meta_path["mitre"]),
                confidence=0.75,
                description=(
                    f"RPC interface {interface_uuid} method procnum "
                    f"{proc_idx} ({handler_name}) accepts a wchar_t* "
                    f"path-type parameter (FC_WSTRING/FC_C_WSTRING "
                    f"detected in NDR format string; transfer syntax: "
                    f"{transfer_syntax}). Low-privilege callers can "
                    f"supply an attacker-controlled path to this "
                    f"method — the BlueHammer-class exploitation "
                    f"primitive when combined with a TOCTOU shape "
                    f"on path resolution."
                ),
                evidence=[Evidence(
                    kind="ndr_wstring_param",
                    source=detector,
                    payload=(
                        f"interface_uuid={interface_uuid} "
                        f"proc_idx={proc_idx} "
                        f"handler=0x{dispatch_addr:x} "
                        f"transfer_syntax={transfer_syntax} "
                        f"ndr_scan=v3b(TF_offset)|v3(FC_RP/FC_UP)|v2(FC_WSTRING/FC_C_WSTRING)"
                    ),
                    address=int(dispatch_addr),
                    function=handler_name,
                )],
                details={
                    "interface_uuid": interface_uuid,
                    "proc_idx": proc_idx,
                    "handler_addr": hex(int(dispatch_addr)),
                    "handler_function": handler_name,
                    "transfer_syntax": transfer_syntax,
                    "ndr_fc_type": "FC_WSTRING|FC_RP->FC_C_WSTRING",
                    "ndr_scanner_version": "v3",
                },
            ))

    return findings


# Built-in known-interface anchors. Future: load from a curated
# knowledge entry / config file. For now, ship Defender's
# IMpService as the seed because it's the primary motivating case.
_KNOWN_INTERFACES = (
    {
        "uuid": "c503f532-443a-4c69-8300-ccd1fbdb3839",
        "name": "IMpService",
        "binary_hint": "MpSvc",  # only walk on binaries whose name contains this
        "anchor_function_substring": "MpIsPathSymlink",
    },
)


def analyze(session, *, binary: Optional[str] = None,
            arch: Optional[str] = None, platform: Optional[str] = None,
            detector: str = "analysis.rpc_interface",
            ) -> list[Finding]:
    """Argus-standard entry. Walks known RPC interfaces if the
    binary matches the interface's binary_hint. Output: findings
    for dispatch enumeration + reachability composites."""
    if session is None:
        return []
    bv = getattr(session, "bv", None)
    if bv is None:
        return []
    binary = binary or getattr(session, "binary_path", "") or ""
    arch = arch or (str(bv.arch) if bv.arch else "unknown")
    platform = platform or (str(bv.platform) if bv.platform else "unknown")

    bn = binary.lower()
    out: list[Finding] = []
    for known in _KNOWN_INTERFACES:
        hint = known.get("binary_hint", "").lower()
        if hint and hint not in bn:
            continue
        out.extend(find_rpc_interface_methods(
            bv,
            interface_uuid=known["uuid"],
            binary=binary, arch=arch, platform=platform,
            anchor_function_substring=known.get("anchor_function_substring"),
            detector=detector,
        ))
    return out


__all__ = [
    "analyze", "find_rpc_interface_methods", "CATEGORY_META",
    "_KNOWN_INTERFACES",
    "_read_transfer_syntax", "_find_midl_server_info",
    "_ndr_proc_has_wstring_param",
    "_tf_is_wstring_pointer",
    "_FC_FP", "_FC_OP", "_POINTER_FC_CODES",
]
