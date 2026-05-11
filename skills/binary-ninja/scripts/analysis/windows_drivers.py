"""Windows kernel driver structural analysis.

Phase 1 enhancement E2 of the Argus BYOVD detection extension.
Discovers the IRP dispatch wiring of a Windows .sys driver:

- Finds DriverEntry (binary entry-point function, plus tail-callees
  that take `(PDRIVER_OBJECT, PUNICODE_STRING)`).
- Walks DriverEntry's body for stores of the form
  `DriverObject->MajorFunction[N] = <handler>`.
- Returns a structured dispatch table the rest of the pipeline
  (taint analyzer, IOCTL-handler seeding) consumes.

The dispatch table on x64 Windows lives at offset 0x70 of
`DRIVER_OBJECT` and contains 28 PVOID entries (`IRP_MJ_MAXIMUM_FUNCTION + 1`).
We detect both type-aware HLIL (`arg1->MajorFunction[N] = h`) and
type-unaware MLIL (`*(arg1 + 0x70 + N*8) = h`) shapes — Binja
typically resolves the type-aware shape on `windows-kernel-x86_64`
platform binaries, but stripped drivers without WDK signatures
sometimes fall through to the raw shape.

This module is intentionally narrow — it doesn't attempt to detect
`PDRIVER_EXTENSION->AddDevice` (PnP) or `FastIoDispatch` table
wiring; those are Phase 1++ extensions documented in
`heuristics/windows_drivers.py` notes when they land.

Knowledge anchor:
    `[[Memory/Knowledge/em_rootkit_irp_minifilter_callbacks]]`
    `[[Memory/Knowledge/a64_procedures_ms_abi]]` (for the IOCTL
    handler ABI consumed by `analysis/taint.py`).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from ..output.finding import Finding, Severity, Evidence


# ─────────────────────────────────────────────────────────────────
# DRIVER_OBJECT layout (x86_64 Windows)
# ─────────────────────────────────────────────────────────────────


# DRIVER_OBJECT.MajorFunction array start offset and size on x64.
DRIVER_OBJECT_MAJORFUNC_OFFSET = 0x70
DRIVER_OBJECT_MAJORFUNC_COUNT = 28          # IRP_MJ_MAXIMUM_FUNCTION + 1
DRIVER_OBJECT_MAJORFUNC_END = (
    DRIVER_OBJECT_MAJORFUNC_OFFSET + DRIVER_OBJECT_MAJORFUNC_COUNT * 8
)

# IRP_MJ_* code → human-readable name. Source: ntddk.h.
IRP_MJ_NAMES: dict[int, str] = {
    0x00: "IRP_MJ_CREATE",
    0x01: "IRP_MJ_CREATE_NAMED_PIPE",
    0x02: "IRP_MJ_CLOSE",
    0x03: "IRP_MJ_READ",
    0x04: "IRP_MJ_WRITE",
    0x05: "IRP_MJ_QUERY_INFORMATION",
    0x06: "IRP_MJ_SET_INFORMATION",
    0x07: "IRP_MJ_QUERY_EA",
    0x08: "IRP_MJ_SET_EA",
    0x09: "IRP_MJ_FLUSH_BUFFERS",
    0x0a: "IRP_MJ_QUERY_VOLUME_INFORMATION",
    0x0b: "IRP_MJ_SET_VOLUME_INFORMATION",
    0x0c: "IRP_MJ_DIRECTORY_CONTROL",
    0x0d: "IRP_MJ_FILE_SYSTEM_CONTROL",
    0x0e: "IRP_MJ_DEVICE_CONTROL",
    0x0f: "IRP_MJ_INTERNAL_DEVICE_CONTROL",
    0x10: "IRP_MJ_SHUTDOWN",
    0x11: "IRP_MJ_LOCK_CONTROL",
    0x12: "IRP_MJ_CLEANUP",
    0x13: "IRP_MJ_CREATE_MAILSLOT",
    0x14: "IRP_MJ_QUERY_SECURITY",
    0x15: "IRP_MJ_SET_SECURITY",
    0x16: "IRP_MJ_POWER",
    0x17: "IRP_MJ_SYSTEM_CONTROL",
    0x18: "IRP_MJ_DEVICE_CHANGE",
    0x19: "IRP_MJ_QUERY_QUOTA",
    0x1a: "IRP_MJ_SET_QUOTA",
    0x1b: "IRP_MJ_PNP",
}


# IRP_MJ codes that take user-influenceable input (the IOCTL
# dispatcher is the canonical attacker-reachable entry; the others
# can also be reached by file handle holders via the I/O manager).
USER_REACHABLE_IRP_MJ: frozenset[int] = frozenset({
    0x00,  # CREATE — open the device
    0x02,  # CLOSE — release the device handle
    0x03,  # READ
    0x04,  # WRITE
    0x05,  # QUERY_INFORMATION
    0x06,  # SET_INFORMATION
    0x0e,  # DEVICE_CONTROL — IOCTL, the primary attack surface
    0x0f,  # INTERNAL_DEVICE_CONTROL
})


# ─────────────────────────────────────────────────────────────────
# Result types
# ─────────────────────────────────────────────────────────────────


@dataclass
class DispatchRegistration:
    """One `DriverObject->MajorFunction[N] = H` assignment."""

    irp_mj: int
    irp_mj_name: str
    handler_addr: int
    write_addr: int                 # the address of the assignment instruction
    write_function: str             # the function performing the assignment

    @property
    def is_ioctl(self) -> bool:
        return self.irp_mj == 0x0e

    @property
    def is_user_reachable(self) -> bool:
        return self.irp_mj in USER_REACHABLE_IRP_MJ


@dataclass
class DispatchTable:
    """Aggregated dispatch wiring for one driver."""

    registrations: list[DispatchRegistration] = field(default_factory=list)
    ioctl_handlers: list[int] = field(default_factory=list)        # unique handler addresses
    user_reachable_handlers: list[int] = field(default_factory=list)

    def merge(self, reg: DispatchRegistration) -> None:
        self.registrations.append(reg)
        if reg.is_ioctl and reg.handler_addr not in self.ioctl_handlers:
            self.ioctl_handlers.append(reg.handler_addr)
        if reg.is_user_reachable and reg.handler_addr not in self.user_reachable_handlers:
            self.user_reachable_handlers.append(reg.handler_addr)


# ─────────────────────────────────────────────────────────────────
# Discovery
# ─────────────────────────────────────────────────────────────────


def _is_windows_kernel_driver(bv) -> bool:
    """True if `bv` looks like a Windows kernel-mode driver.

    Discriminator: PE binary on a `windows-kernel-*` platform, with
    INIT or PAGE sections (kernel-driver-specific section names).
    """
    if bv is None:
        return False
    vt = str(getattr(bv, "view_type", "") or "").upper()
    if "PE" not in vt:
        return False
    plat = str(getattr(bv, "platform", "") or "").lower()
    if "kernel" not in plat:
        # Some kernel drivers report a non-kernel platform but still
        # have the kernel-driver section markers.
        sections = getattr(bv, "sections", None)
        if not sections:
            return False
        names = set(sections.keys() if hasattr(sections, "keys") else [])
        return bool(names & {"INIT", "PAGE", ".init", ".PAGE"})
    return True


def _follow_entry_chain(bv, max_depth: int = 4) -> list:
    """Return [DriverEntry, real_DriverEntry, ...] — the chain of
    functions reachable from the binary entry point that are
    candidates for IRP dispatch wiring.

    Walks tail-calls and direct calls from the entry point. Many
    drivers (dbutil_2_3.sys included) have a stub entry that calls
    into the real DriverEntry; we want both.
    """
    if bv is None:
        return []
    entry = bv.get_function_at(getattr(bv, "entry_point", 0))
    if entry is None:
        return []
    seen: set[int] = set()
    chain: list = []
    work: list[tuple[object, int]] = [(entry, 0)]
    while work:
        func, depth = work.pop(0)
        if func is None or func.start in seen:
            continue
        seen.add(func.start)
        chain.append(func)
        if depth >= max_depth:
            continue
        for callee in getattr(func, "callees", []) or []:
            if callee.start not in seen:
                work.append((callee, depth + 1))
    return chain


def _extract_assignment_offset(inst) -> Optional[int]:
    """If `inst` is a store whose destination is `<base> + <offset>`
    where offset lies in the MajorFunction array, return offset.
    Otherwise None.

    Handles two MLIL shapes:

    1. **MediumLevelILStoreStruct** — Binja's preferred form when the
       base variable has a struct type (typical for `windows-kernel-x86_64`
       binaries where Binja resolves DRIVER_OBJECT). Operands layout:
       `[base_var_expr, offset, value_expr]`.

    2. **MediumLevelILStore** — raw store; dest is an arithmetic
       expression of `<base> + <const>`. Falls through to
       `_trace_offset_from_arg` for any base variable in the function.

    Note: we deliberately don't require the base to equal the
    function's first parameter. The offset+stride pattern (DRIVER_OBJECT.
    MajorFunction at +0x70 with 28×8-byte slots) is uniquely
    BYOVD/driver-shaped, and Binja often inserts intermediate variable
    copies (`rdi = arg1`) that defeat naive var-equality checks.
    The entry-chain filter at the call-site of this function already
    limits us to DriverEntry-reachable code.
    """
    op_name = type(inst).__name__
    # 1. Typed struct store: explicit offset in operands
    if op_name == "MediumLevelILStoreStruct":
        operands = list(getattr(inst, "operands", []) or [])
        for op in operands:
            if isinstance(op, int):
                return int(op)
        return None
    # 2. Raw store: trace offset from base
    if "Store" not in op_name:
        return None
    dest = getattr(inst, "dest", None)
    if dest is None:
        return None
    return _trace_offset_any(dest)


def _trace_offset_any(expr, max_depth: int = 4) -> Optional[int]:
    """Walk an MLIL expression tree; return the SUM of constant terms
    that are added to a SINGLE non-constant base variable. Returns
    None when no constant is present, OR when the expression contains
    a runtime-indexed term in addition to the base (e.g. `rax << 3`),
    which would make the offset indeterminate.

    Caller doesn't care which base var; the offset+stride pattern is
    BYOVD-keying enough on its own (no other Windows-driver struct
    has 28 PVOID slots starting at +0x70).

    Folds nested Add: `rcx + 0xb0 + 0x70` (parsed as
    `(rcx + 0xb0) + 0x70`) returns 0x120. Compilers emit this shape
    when DRIVER_OBJECT.MajorFunction is referenced through an
    intermediate offset (e.g., GoFly64 — a base-pointer is rebased
    inside DriverEntry and per-slot writes are then expressed as
    `<rebased> + <slot_offset>` plus the original `0x70`).
    """
    if expr is None or max_depth <= 0:
        return None
    nonconst, const_sum = _sum_offset_terms(expr, max_depth)
    if nonconst != 1:
        # Either zero base vars (pure constant — not a store-to-
        # struct shape) or 2+ non-constant terms (runtime-indexed
        # write). Both → no determinate offset.
        return None
    return const_sum


def _sum_offset_terms(expr, max_depth: int = 4) -> tuple[int, int]:
    """Recursively decompose `expr` into (nonconst_term_count,
    constant_sum). Walks Add nodes; treats Shift / Mul / non-Add
    subtrees that aren't pure constants as a single non-constant
    term (so we can detect runtime-indexed writes).

    Returns (count_of_distinct_nonconst_subtrees, sum_of_constants).
    """
    if expr is None or max_depth <= 0:
        return (0, 0)
    op_name = type(expr).__name__
    # Pure constant.
    cv = _expr_const(expr)
    if cv is not None:
        return (0, int(cv))
    if "Add" in op_name:
        # Recurse into children.
        children = list(getattr(expr, "operands", []) or [])
        left = getattr(expr, "left", None)
        right = getattr(expr, "right", None)
        if left is not None and right is not None:
            children = [left, right]
        nonconst_total = 0
        const_total = 0
        for c in children:
            nc, cs = _sum_offset_terms(c, max_depth - 1)
            nonconst_total += nc
            const_total += cs
        return (nonconst_total, const_total)
    # Non-Add, non-Const subtree — treat as a single opaque non-
    # constant term. Examples: VarSsa, Shift (rax << 3), Mul, Load,
    # Sub, etc. Recursing into these would falsely fold their
    # internal constants (`rax << 3` would otherwise contribute 3).
    return (1, 0)


def _expr_const(expr) -> Optional[int]:
    if expr is None:
        return None
    val = getattr(expr, "constant", None)
    if val is not None:
        try:
            return int(val)
        except Exception:
            return None
    op_name = type(expr).__name__
    if "Const" in op_name:
        for attr in ("value", "constant"):
            v = getattr(expr, attr, None)
            if v is not None:
                try:
                    return int(v)
                except Exception:
                    continue
    return None


def _store_value_function_addr(inst, bv) -> Optional[int]:
    """Return the constant function address being stored, if any.

    Handles both `MediumLevelILStoreStruct` (last operand is the
    value) and raw `MediumLevelILStore` (`.src` carries it).
    """
    op_name = type(inst).__name__
    val: Optional[int] = None
    if op_name == "MediumLevelILStoreStruct":
        operands = list(getattr(inst, "operands", []) or [])
        if operands:
            val = _expr_const(operands[-1])
    if val is None:
        src = getattr(inst, "src", None)
        if src is not None:
            val = _expr_const(src)
    if val is None or val == 0:
        return None
    # Confirm the value resolves to a function in this binary.
    if bv.get_function_at(val) is not None:
        return val
    # Some drivers route through an intermediate stub at a non-function
    # address (e.g., a thunk). Accept any address inside .text — the
    # downstream consumer can check.
    sec = bv.get_sections_at(val) if hasattr(bv, "get_sections_at") else []
    for s in sec or []:
        sname = getattr(s, "name", "")
        if sname in (".text", "PAGE", "INIT"):
            return val
    return None


def _function_first_param_var(func):
    """First parameter Variable for `func`, or None."""
    pvars = getattr(func, "parameter_vars", None)
    if not pvars:
        return None
    try:
        return list(pvars)[0]
    except Exception:
        return None


def _scan_function_for_dispatch_writes(func) -> list[DispatchRegistration]:
    """Scan one function's MLIL for `<base>->MajorFunction[N] = handler`
    writes and return the registrations found.

    Three idioms are recognised:

    1. **Per-slot StoreStruct** — Binja's typed shape when DRIVER_OBJECT
       is known; one MLIL_STORE_STRUCT per registered IRP_MJ slot.
       The dbutil + TfSysMon dispatch path.
    2. **Per-slot raw Store** — fallback when type recovery missed.
    3. **Bulk `__memfill_u64` intrinsic** — `rep stosq` compiler idiom
       used when ALL IRP_MJ slots route to the same handler. Common
       in process-killer drivers (Viragt64) where there's only one
       dispatch routine. Operands: `(target_addr, handler, count)`.
       We accept any (target, handler, count) combination where:
       - target is `<base> + <offset>` with offset in
         `[OFFSET, OFFSET + DRIVER_OBJECT_MAJORFUNC_END - OFFSET)`
         (lets compilers shift the start pointer to e.g.
         `&MajorFunction[2]` for partial fills)
       - handler is a constant pointer into .text
       - count is a constant in [1, 28]
       Each filled slot becomes one DispatchRegistration.
    """
    out: list[DispatchRegistration] = []
    if func is None:
        return out
    bv = getattr(func, "view", None) or getattr(func, "_view", None)
    if bv is None:
        return out
    mlil = getattr(func, "mlil", None)
    if mlil is None:
        return out
    fname = getattr(func, "name", "<anon>")

    for block in mlil:
        for inst in block:
            tn = type(inst).__name__

            # Path 3: __memfill_u64 / __rep_movsq intrinsic
            if "Intrinsic" in tn:
                regs = _extract_dispatch_from_memfill(inst, bv, fname)
                out.extend(regs)
                continue

            # Paths 1 & 2: per-slot store
            try:
                offset = _extract_assignment_offset(inst)
            except Exception:
                offset = None
            if offset is None:
                continue
            if offset < DRIVER_OBJECT_MAJORFUNC_OFFSET or offset >= DRIVER_OBJECT_MAJORFUNC_END:
                continue
            slot = offset - DRIVER_OBJECT_MAJORFUNC_OFFSET
            if slot % 8 != 0:
                continue
            irp_mj = slot // 8
            handler_addr = _store_value_function_addr(inst, bv)
            if handler_addr is None:
                continue
            out.append(DispatchRegistration(
                irp_mj=irp_mj,
                irp_mj_name=IRP_MJ_NAMES.get(irp_mj, f"IRP_MJ_{irp_mj:#x}"),
                handler_addr=handler_addr,
                write_addr=int(getattr(inst, "address", 0) or 0),
                write_function=fname,
            ))
    return out


def _extract_dispatch_from_memfill(inst, bv, fname: str) -> list[DispatchRegistration]:
    """Recognise `__memfill_u64(major_func_slot_ptr, handler, count)`
    and emit one DispatchRegistration per slot the fill covers.

    Confidence rules. The intrinsic + (handler in .text) + (count
    `IRP_MJ_MAXIMUM_FUNCTION + 1`) is a strong dispatch-fill
    fingerprint on its own — DRIVER_OBJECT.MajorFunction is the only
    28-slot function-pointer array kernel drivers rep-stosq into.
    When the offset traces cleanly to `+0x70` we use it; when it
    doesn't (compilers emit `<rebased_pointer> - <const>` shapes
    that defeat naive offset tracing — Viragt64 uses
    `rdi_1 - 0xe0` where `rdi_1 = arg1 + 0x150`), we accept the
    fill as IRP_MJ_CREATE..IRP_MJ_PNP iff count == 28 (i.e., a
    full dispatch table fill).

    Tolerant of MLIL printer differences across Binja versions —
    walks the params list rather than assuming positional names.
    """
    out: list[DispatchRegistration] = []
    intrinsic = getattr(inst, "intrinsic", None)
    iname = ""
    if intrinsic is not None:
        iname = getattr(intrinsic, "name", "") or str(intrinsic)
    # Match common qword-fill intrinsics. `__memfill_u64` is Binja's
    # canonical form; `__rep_movsq` / `__stosq` sometimes appear
    # depending on Binja version + arch module.
    if iname not in ("__memfill_u64", "__rep_stosq", "__stosq"):
        return out

    params = list(getattr(inst, "params", []) or [])
    if len(params) < 3:
        return out
    target_expr, handler_expr, count_expr = params[0], params[1], params[2]

    handler_addr = _expr_const(handler_expr)
    if handler_addr is None or handler_addr == 0:
        return out
    if bv.get_function_at(handler_addr) is None:
        sec = bv.get_sections_at(handler_addr) if hasattr(bv, "get_sections_at") else []
        if not any(getattr(s, "name", "") in (".text", "PAGE", "INIT")
                   for s in sec or []):
            return out

    count = _expr_const(count_expr) or 0
    if count <= 0 or count > DRIVER_OBJECT_MAJORFUNC_COUNT:
        return out

    # Try to derive a starting slot from the target offset.
    offset = _trace_offset_any(target_expr)
    start_slot = None
    if offset is not None and DRIVER_OBJECT_MAJORFUNC_OFFSET <= offset < DRIVER_OBJECT_MAJORFUNC_END:
        slot_offset = offset - DRIVER_OBJECT_MAJORFUNC_OFFSET
        if slot_offset % 8 == 0:
            start_slot = slot_offset // 8

    # Fallback: if offset tracing failed but count is the canonical
    # full-fill (28 = IRP_MJ_MAXIMUM_FUNCTION + 1), accept this as
    # a full dispatch table fill from slot 0. The 28-slot constant
    # is the discriminator — no other kernel-driver structure has
    # 28 PVOID entries that compilers fill via rep-stosq.
    if start_slot is None:
        if count == DRIVER_OBJECT_MAJORFUNC_COUNT:
            start_slot = 0
        else:
            return out

    last_slot = min(DRIVER_OBJECT_MAJORFUNC_COUNT, start_slot + count)
    write_addr = int(getattr(inst, "address", 0) or 0)
    for irp_mj in range(start_slot, last_slot):
        out.append(DispatchRegistration(
            irp_mj=irp_mj,
            irp_mj_name=IRP_MJ_NAMES.get(irp_mj, f"IRP_MJ_{irp_mj:#x}"),
            handler_addr=handler_addr,
            write_addr=write_addr,
            write_function=fname,
        ))
    return out


def extract_dispatch_table(bv) -> DispatchTable:
    """Find all `DriverObject->MajorFunction[N] = handler` writes
    reachable from the binary entry point.

    Walks the entry point's tail-callee chain; for each function in
    the chain whose first parameter is a candidate DRIVER_OBJECT, scans
    MLIL for the dispatch-write pattern and aggregates results.

    Returns an empty `DispatchTable` if the binary isn't a Windows
    kernel driver or no writes are found.
    """
    table = DispatchTable()
    if not _is_windows_kernel_driver(bv):
        return table
    chain = _follow_entry_chain(bv)
    seen_signatures: set[tuple[int, int]] = set()
    for func in chain:
        for reg in _scan_function_for_dispatch_writes(func):
            sig = (reg.irp_mj, reg.handler_addr)
            if sig in seen_signatures:
                continue
            seen_signatures.add(sig)
            table.merge(reg)
    return table


def discover_ioctl_handlers(bv) -> list[int]:
    """Convenience wrapper for taint analysis: returns the list of
    function addresses that handle IRP_MJ_DEVICE_CONTROL on this
    driver. May include duplicates of `user_reachable_handlers` —
    callers should de-dupe."""
    return list(extract_dispatch_table(bv).ioctl_handlers)


# ─────────────────────────────────────────────────────────────────
# Public entry — emits Findings describing the dispatch wiring
# ─────────────────────────────────────────────────────────────────


def analyze(session, *, binary: Optional[str] = None,
            arch: Optional[str] = None,
            platform: Optional[str] = None) -> list[Finding]:
    """Phase-1 entry. Emits one INFO Finding per IOCTL handler
    registration plus one HIGH Finding cataloguing the full dispatch
    wiring on the driver.

    Severity rationale:

    - **IOCTL handler registration** (HIGH) — the most attacker-
      reachable surface; on a unsigned/BYOVD driver this is the
      attack-surface entry. Worth flagging individually so taint
      findings later can be correlated by handler address.
    - **Dispatch wiring summary** (INFO) — per-binary metadata about
      *all* registered MajorFunction slots. Useful for triage but
      not itself a vulnerability.
    """
    if session is None:
        return []
    bv = getattr(session, "bv", None)
    if bv is None:
        return []
    binary = binary or getattr(session, "binary_path", "") or ""
    arch = arch or (str(bv.arch) if bv.arch else "unknown")
    platform = platform or (str(bv.platform) if bv.platform else "unknown")

    table = extract_dispatch_table(bv)
    if not table.registrations:
        return []

    findings: list[Finding] = []

    # Per-handler findings, IOCTL handlers prioritised.
    seen_handlers: set[int] = set()
    for reg in sorted(table.registrations, key=lambda r: (not r.is_ioctl, r.irp_mj)):
        if reg.handler_addr in seen_handlers:
            continue
        seen_handlers.add(reg.handler_addr)
        sev = Severity.HIGH if reg.is_ioctl else (
            Severity.MEDIUM if reg.is_user_reachable else Severity.LOW
        )
        # Aggregate the IRP_MJ slots routing to this handler
        slots = [(r.irp_mj, r.irp_mj_name) for r in table.registrations
                 if r.handler_addr == reg.handler_addr]
        slot_text = ", ".join(f"{name}({mj:#x})" for mj, name in sorted(slots))
        finder = bv.get_function_at(reg.handler_addr)
        fname = getattr(finder, "name", f"sub_{reg.handler_addr:x}") if finder else f"<no_func@{reg.handler_addr:x}>"
        findings.append(Finding(
            id="",
            category="kernel_irp_handler_registered",
            severity=sev,
            address=reg.handler_addr,
            function=fname,
            binary=binary,
            arch=arch,
            platform=platform,
            detector="analysis.windows_drivers",
            knowledge_refs=[
                "[[Memory/Knowledge/em_rootkit_irp_minifilter_callbacks]]",
                "[[Memory/Knowledge/a64_procedures_ms_abi]]",
            ],
            cwe=[],
            mitre_attack=["T1014"],
            description=(
                f"Driver registers {fname} as the handler for "
                f"{slot_text}. " +
                ("This is the IOCTL dispatcher — primary attacker-reachable surface."
                 if reg.is_ioctl else
                 "User-reachable IRP slot."
                 if reg.is_user_reachable else
                 "Internal IRP slot.")
            ),
            details={
                "slots": [{"irp_mj": mj, "irp_mj_name": name}
                          for mj, name in sorted(slots)],
                "is_ioctl_dispatcher": reg.is_ioctl,
                "is_user_reachable": reg.is_user_reachable,
                "wiring_call_site": hex(reg.write_addr),
                "wiring_function": reg.write_function,
            },
            evidence=[Evidence(
                kind="dispatch_wiring",
                source="analysis.windows_drivers",
                payload=f"{reg.write_function} @ {hex(reg.write_addr)}: "
                        f"DriverObject->MajorFunction[{reg.irp_mj:#x}] = {fname}",
                address=reg.write_addr,
                function=reg.write_function,
            )],
        ))

    return findings
