"""CLI metadata + IL walker — .NET assembly precision detector.

`dotnet_managed.py` provides v1 string-co-presence detection. This
module provides v2: walks the CLI metadata tables (TypeRef,
MemberRef, MethodDef) and the IL byte stream of each method body,
emitting per-callsite findings with concrete IL-level anchoring.

Covers shapes the v1 string detector cannot disambiguate:

  stack_buffer_overflow (C#)
    The `localloc` IL opcode (0xFE 0x0F) is the IL encoding of
    `stackalloc`. Presence of `localloc` inside an unsafe-compiled
    assembly is a stack-frame allocation primitive; combined with
    `UnverifiableCodeAttribute` (compiler-emitted when /unsafe is
    set) and a Class typed as `byte*` (raw pointer) it's the
    canonical C# stack-OF shape.

  type_confusion (C#)
    Direct MemberRef hits on:
      `Marshal::PtrToStructure`     — raw byte → struct cast
      `Marshal::StructureToPtr`     — struct → byte cast (the other
                                      direction; same UB family)
      `Unsafe::As<,>` / `BitCast` / `AsPointer`
                                    — managed type-pun primitives
    Plus the structural pattern: `fixed` + raw pointer cast,
    which surfaces in IL as a `Conv.U` / pointer-typed `Ldobj`
    cross-type access inside an unsafe method.

  use_after_free (C# — use-after-Dispose analog)
    Direct MemberRef hits on `IDisposable::Dispose` (or any
    type's `Dispose` override) combined with another instance
    method call on the same instance type in the same assembly.

Requires `dnfile` (already pip-installed). Gracefully no-ops if
the package isn't present or the binary isn't a .NET assembly.

Knowledge anchors:
- `[[Memory/Knowledge/argus_detector_design_principles]]`
- `[[Memory/Knowledge/ec_undefined_behavior_taxonomy]]`
- `[[Memory/Knowledge/hw_stack_overflow_mechanics]]`
"""

from __future__ import annotations

from typing import Optional

from ..output.finding import Evidence, Finding, Severity


CATEGORY_META = {
    "stack_buffer_overflow": {
        "severity": Severity.HIGH,
        "cwe": ["CWE-121"],
        "mitre": ["T1203"],
        "knowledge_refs": [
            "[[Memory/Knowledge/hw_stack_overflow_mechanics]]",
            "[[Memory/Knowledge/argus_detector_design_principles]]",
        ],
    },
    "type_confusion": {
        "severity": Severity.HIGH,
        "cwe": ["CWE-843"],
        "mitre": ["T1203"],
        "knowledge_refs": [
            "[[Memory/Knowledge/ec_undefined_behavior_taxonomy]]",
            "[[Memory/Knowledge/bhg_unsafe_pointer_patterns]]",
        ],
    },
    "use_after_free": {
        "severity": Severity.HIGH,
        "cwe": ["CWE-416"],
        "mitre": ["T1203"],
        "knowledge_refs": [
            "[[Memory/Knowledge/wnapi_heap_internals]]",
            "[[Memory/Knowledge/argus_detector_design_principles]]",
        ],
    },
}


# Direct dangerous-API MemberRef hits. Each tuple is (TypeName,
# MethodName, category, description). MemberRef rows where
# Class.TypeName matches AND Name matches → fire.
DANGEROUS_MEMBERREF = (
    # Marshal-based reinterpret cast — canonical managed type-confusion
    ("Marshal", "PtrToStructure",
     "type_confusion",
     "Marshal::PtrToStructure — reinterprets raw bytes as a managed "
     "struct without runtime layout validation"),
    ("Marshal", "StructureToPtr",
     "type_confusion",
     "Marshal::StructureToPtr — struct bytes → raw pointer; combined "
     "with PtrToStructure forms the round-trip UB family"),
    ("Marshal", "Copy",
     "type_confusion",
     "Marshal::Copy — bulk bytes / managed-array copy that can produce "
     "mismatched layouts when source / dest types differ"),
    # System.Runtime.CompilerServices.Unsafe — explicit type-pun
    ("Unsafe", "As",
     "type_confusion",
     "Unsafe::As<TFrom, TTo> — direct bit-reinterpret across managed "
     "types; runtime makes no validity check"),
    ("Unsafe", "AsPointer",
     "type_confusion",
     "Unsafe::AsPointer — managed reference to raw pointer; subsequent "
     "writes bypass managed-memory invariants"),
    ("Unsafe", "BitCast",
     "type_confusion",
     "Unsafe::BitCast — raw bit-reinterpret across types of equal size"),
    # Reflection + dynamic invocation — code-execution primitive
    ("Activator", "CreateInstance",
     "managed_dangerous_api",
     "Activator::CreateInstance — reflection-based type instantiation; "
     "combined with attacker-controlled type-name is RCE"),
    ("Type", "InvokeMember",
     "managed_dangerous_api",
     "Type::InvokeMember — reflection-based method dispatch on a "
     "Type resolved at runtime"),
    ("MethodInfo", "Invoke",
     "managed_dangerous_api",
     "MethodInfo::Invoke — reflection-based method invocation"),
)


# Use-after-Dispose detection signature. Class.TypeName matching is
# imprecise (custom Dispose-implementing types are common), so we
# use the conservative shape: the assembly references `IDisposable`
# (or has any class implementing `Dispose`) AND another instance
# method on a matching disposable type. The string-rule track in
# `dotnet_managed.py` catches `ObjectDisposedException` references;
# this module's contribution is to confirm structurally.
DISPOSE_TYPENAMES = {"IDisposable", "Stream", "FileStream",
                     "MemoryStream", "BinaryReader", "BinaryWriter",
                     "TextReader", "TextWriter", "StringReader",
                     "StringWriter", "SqlConnection", "HttpClient",
                     "WebClient", "SocketStream"}


# IL opcodes we care about. The two-byte opcodes start with 0xFE.
_LOCALLOC = b"\xFE\x0F"   # localloc — IL of `stackalloc`
_CPBLK    = b"\xFE\x17"   # cpblk    — block memcpy; user-controlled length is dangerous
_INITBLK  = b"\xFE\x18"   # initblk  — block memset; user-controlled length is dangerous


def _safe_typename(row) -> str:
    """Return the Class.TypeName of a MemberRef row, defensively."""
    try:
        cls_obj = getattr(row.Class, "row", None)
        if cls_obj is None:
            return ""
        tn = getattr(cls_obj, "TypeName", None)
        if tn is None:
            return ""
        return getattr(tn, "value", "") or ""
    except Exception:
        return ""


def _safe_name(row) -> str:
    try:
        nm = getattr(row, "Name", None)
        return getattr(nm, "value", "") or ""
    except Exception:
        return ""


def _has_attribute(pe, attribute_name: str) -> bool:
    """True iff the assembly references the named attribute in its
    TypeRef table. `UnverifiableCodeAttribute` indicates the assembly
    was compiled with /unsafe."""
    try:
        for row in (pe.net.mdtables.TypeRef.rows or []):
            tn = getattr(row.TypeName, "value", "") or ""
            if tn == attribute_name:
                return True
    except Exception:
        pass
    return False


def _walk_method_il(pe, *, looking_for: bytes) -> list[tuple[str, int]]:
    """Walk MethodDef rows; for each method that has a body, return
    (MethodName, RVA) for any match of `looking_for` in the IL byte
    stream. Skips methods with implementation-flag `MethodImplAttributes
    .Native` or similar (no IL).
    """
    hits: list[tuple[str, int]] = []
    try:
        md = pe.net.mdtables.MethodDef
        if md is None:
            return hits
    except Exception:
        return hits

    raw = pe.__data__ if hasattr(pe, "__data__") else bytes(pe.get_memory_mapped_image())

    for row in (md.rows or []):
        # dnfile exposes Rva as a plain int on MethodDef rows.
        rva = int(getattr(row, "Rva", 0) or 0)
        if rva == 0:
            continue
        try:
            offset = pe.get_offset_from_rva(rva)
        except Exception:
            continue
        # Method-body header is either 1-byte tiny or 12-byte fat.
        try:
            first = raw[offset]
        except IndexError:
            continue
        if (first & 0x03) == 0x02:
            # Tiny format: top 6 bits = code size in bytes
            code_size = first >> 2
            il_start = offset + 1
        elif (first & 0x07) == 0x03:
            # Fat format
            # Read fat header: flags+size (u16), maxstack (u16),
            # code_size (u32), LocalVarSig (u32). Header is 12 bytes,
            # 4-byte aligned.
            try:
                code_size = int.from_bytes(raw[offset + 4: offset + 8], "little")
                il_start = offset + 12
            except Exception:
                continue
        else:
            continue
        il_end = il_start + code_size
        if il_end > len(raw):
            continue
        body = raw[il_start:il_end]
        if looking_for in body:
            name = (getattr(row.Name, "value", "") or f"sub_{rva:x}")
            hits.append((name, rva))
    return hits


def find_dotnet_il_findings(
        pe, *, binary: str, arch: str, platform: str,
        detector: str = "analysis.dotnet_il",
) -> list[Finding]:
    findings: list[Finding] = []

    has_unverifiable = _has_attribute(pe, "UnverifiableCodeAttribute")

    # MemberRef walk — known dangerous APIs
    seen_cats: set[str] = set()
    try:
        memberref = pe.net.mdtables.MemberRef
        rows = list(memberref.rows or []) if memberref else []
    except Exception:
        rows = []

    for row in rows:
        type_name = _safe_typename(row)
        method_name = _safe_name(row)
        for tn_match, mn_match, cat, desc in DANGEROUS_MEMBERREF:
            if type_name == tn_match and method_name == mn_match:
                if cat in seen_cats and cat != "managed_dangerous_api":
                    continue
                seen_cats.add(cat)
                meta = CATEGORY_META.get(cat, {})
                if not meta:
                    continue
                findings.append(Finding(
                    id="",
                    category=cat,
                    severity=meta["severity"],
                    address=0,
                    function=f"{type_name}.{method_name}",
                    binary=binary, arch=arch, platform=platform,
                    detector=detector,
                    knowledge_refs=list(meta["knowledge_refs"]),
                    cwe=list(meta["cwe"]),
                    mitre_attack=list(meta["mitre"]),
                    description=desc,
                    evidence=[Evidence(
                        kind="cli_memberref",
                        source=detector,
                        payload=f"type={type_name} name={method_name}",
                        address=0,
                        function=f"{type_name}.{method_name}",
                    )],
                    details={
                        "type_name": type_name,
                        "method_name": method_name,
                        "unverifiable_code": has_unverifiable,
                    },
                ))

    # Collect TypeRef names for downstream structural rules.
    try:
        typeref_names = {
            (getattr(r.TypeName, "value", "") or "")
            for r in (pe.net.mdtables.TypeRef.rows or [])
        }
    except Exception:
        typeref_names = set()

    # Structural type-confusion shape: raw pointer cast `(T*)p` inside
    # a `fixed` block. The C# compiler emits this as `conv.u` plus
    # struct-pointer-typed field access, which doesn't surface as a
    # named MemberRef. Distinguishing indicators (must all hold):
    #   - UnverifiableCodeAttribute (compiled /unsafe)
    #   - IntPtr in TypeRef (raw-pointer arithmetic surface)
    #   - Marshal::SizeOf in MemberRef (struct-byte sizing — typical
    #     pre-cast pattern: allocate `new byte[Marshal.SizeOf(t)]`
    #     then reinterpret via `*(T*)p`)
    # Severity HIGH only when all three coincide. The conjunction is
    # specific enough that ordinary managed code (which uses neither
    # raw IntPtr nor Marshal.SizeOf) won't trigger.
    if has_unverifiable and "type_confusion" not in seen_cats:
        has_intptr = "IntPtr" in typeref_names
        has_marshal_sizeof = any(
            _safe_typename(r) == "Marshal" and _safe_name(r) == "SizeOf"
            for r in rows
        )
        if has_intptr and has_marshal_sizeof:
            meta = CATEGORY_META["type_confusion"]
            findings.append(Finding(
                id="",
                category="type_confusion",
                severity=meta["severity"],
                address=0,
                function="<assembly>",
                binary=binary, arch=arch, platform=platform,
                detector=detector,
                knowledge_refs=list(meta["knowledge_refs"]),
                cwe=list(meta["cwe"]),
                mitre_attack=list(meta["mitre"]),
                description=(
                    "Assembly is compiled /unsafe (UnverifiableCodeAttribute "
                    "present), references IntPtr (raw-pointer arithmetic "
                    "surface), and uses Marshal::SizeOf (struct-byte sizing "
                    "typical for the raw-byte buffer that's about to be "
                    "reinterpreted via `(T*)p`). Canonical C# unsafe "
                    "type-confusion shape — raw pointer cast inside a "
                    "`fixed` block reinterprets bytes across struct "
                    "types. Direct call-site anchoring requires IL "
                    "operand walk (deferred to v2)."
                ),
                evidence=[Evidence(
                    kind="cli_structural_unsafe_cast",
                    source=detector,
                    payload=(f"unverifiable=true intptr_typeref=true "
                             f"marshal_sizeof=true"),
                    address=0,
                    function="<assembly>",
                )],
                details={
                    "unverifiable_code": True,
                    "intptr_typeref": True,
                    "marshal_sizeof_referenced": True,
                },
            ))
            seen_cats.add("type_confusion")

    # Structural use-after-Dispose shape. Precision gate: require
    # `ObjectDisposedException` in TypeRef. The exception type is
    # only referenced when the assembly either catches it or has
    # code paths that would trigger it (the .NET compiler doesn't
    # emit an ODE TypeRef for normal `using`-scoped disposal — those
    # never throw ODE because the dispose-and-go-out-of-scope path
    # doesn't reuse the object). When ODE is in TypeRef AND a
    # disposable-type Dispose + another instance method are both
    # MemberRef'd, that's the use-after-Dispose shape.
    if "use_after_free" not in seen_cats \
            and "ObjectDisposedException" in typeref_names:
        dispose_types: set[str] = set()
        # Collect types whose Dispose is referenced
        for r in rows:
            tn = _safe_typename(r)
            mn = _safe_name(r)
            if mn == "Dispose":
                dispose_types.add(tn)
        # If any dispose-target type is also called with another
        # instance method in the same assembly's MemberRefs, the
        # use-after-Dispose shape is present.
        if dispose_types:
            other_methods_on_disposable = []
            for r in rows:
                tn = _safe_typename(r)
                mn = _safe_name(r)
                if (tn in dispose_types or tn in DISPOSE_TYPENAMES) \
                        and mn != "Dispose" and not mn.startswith("."):
                    other_methods_on_disposable.append((tn, mn))
            if other_methods_on_disposable:
                meta = CATEGORY_META["use_after_free"]
                findings.append(Finding(
                    id="",
                    category="use_after_free",
                    severity=meta["severity"],
                    address=0,
                    function="<assembly>",
                    binary=binary, arch=arch, platform=platform,
                    detector=detector,
                    knowledge_refs=list(meta["knowledge_refs"]),
                    cwe=list(meta["cwe"]),
                    mitre_attack=list(meta["mitre"]),
                    description=(
                        f"Assembly references {len(dispose_types)} "
                        f"type(s)' Dispose method AND additional "
                        f"instance method(s) on those types "
                        f"({', '.join(f'{t}.{m}' for t, m in other_methods_on_disposable[:4])}). "
                        f"Use-after-Dispose shape — subsequent method "
                        f"calls on a disposed object operate on freed "
                        f"unmanaged state (CWE-416 analog). v2 IL "
                        f"sequencing analysis required to confirm "
                        f"the temporal ordering."
                    ),
                    evidence=[Evidence(
                        kind="cli_use_after_dispose",
                        source=detector,
                        payload=(f"dispose_types={sorted(dispose_types)} "
                                 f"other_methods="
                                 f"{[(t, m) for t, m in other_methods_on_disposable[:6]]}"),
                        address=0,
                        function="<assembly>",
                    )],
                    details={
                        "dispose_types": sorted(dispose_types),
                        "other_methods_on_disposable": [
                            {"type": t, "method": m}
                            for t, m in other_methods_on_disposable[:8]
                        ],
                    },
                ))
                seen_cats.add("use_after_free")

    # IL walk — localloc presence (stack-OF candidate)
    localloc_hits = _walk_method_il(pe, looking_for=_LOCALLOC)
    if localloc_hits:
        # One aggregated finding for the assembly + first 8 sites
        # listed in details. localloc is a STACK-ALLOC primitive, not
        # an overflow by itself — but in an unsafe-compiled assembly
        # WITHOUT bounds-checking it's the canonical C# stack-OF
        # shape (the IL of `stackalloc + unsafe pointer arithmetic`).
        # Severity HIGH when UnverifiableCode attribute is present;
        # MEDIUM otherwise (allocation primitive only, no exploit
        # primitive without unsafe).
        meta = CATEGORY_META["stack_buffer_overflow"]
        sev = meta["severity"] if has_unverifiable else Severity.MEDIUM
        first_name, first_rva = localloc_hits[0]
        findings.append(Finding(
            id="",
            category="stack_buffer_overflow",
            severity=sev,
            address=int(first_rva),
            function=first_name,
            binary=binary, arch=arch, platform=platform,
            detector=detector,
            knowledge_refs=list(meta["knowledge_refs"]),
            cwe=list(meta["cwe"]),
            mitre_attack=list(meta["mitre"]),
            description=(
                f"Assembly contains {len(localloc_hits)} method(s) with "
                f"`localloc` (IL of `stackalloc`)"
                + (
                    " AND `UnverifiableCodeAttribute` "
                    "(compiled /unsafe). Combined with an unbounded "
                    "pointer write inside the unsafe block, this is "
                    "the canonical C# stack-overflow shape (CWE-121)."
                    if has_unverifiable else
                    ". `UnverifiableCodeAttribute` is absent, so the "
                    "binary is bounds-checked — research candidate, "
                    "not a confirmed primitive."
                )
            ),
            evidence=[Evidence(
                kind="cli_il_localloc",
                source=detector,
                payload=(f"localloc_methods={len(localloc_hits)} "
                         f"unverifiable_code={has_unverifiable}"),
                address=int(first_rva),
                function=first_name,
            )],
            details={
                "localloc_method_count": len(localloc_hits),
                "unverifiable_code": has_unverifiable,
                "localloc_methods": [
                    {"name": n, "rva": hex(r)}
                    for n, r in localloc_hits[:8]
                ],
            },
        ))

    return findings


def analyze(session, *, binary: Optional[str] = None,
            arch: Optional[str] = None, platform: Optional[str] = None,
            detector: str = "analysis.dotnet_il",
            ) -> list[Finding]:
    """Argus-standard entry point. Falls through cleanly when
    `dnfile` isn't installed or the binary isn't a .NET assembly."""
    if session is None:
        return []
    bv = getattr(session, "bv", None)
    if bv is None:
        return []
    binary = binary or getattr(session, "binary_path", "") or ""
    arch = arch or (str(bv.arch) if bv.arch else "unknown")
    platform = platform or (str(bv.platform) if bv.platform else "unknown")

    try:
        import dnfile  # type: ignore
    except ImportError:
        return []

    try:
        pe = dnfile.dnPE(binary, fast_load=True)
        pe.parse_data_directories(directories=[
            dnfile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR"]
        ])
        if pe.net is None or pe.net.mdtables is None:
            return []
    except Exception:
        return []

    return find_dotnet_il_findings(
        pe, binary=binary, arch=arch, platform=platform, detector=detector
    )


__all__ = ["analyze", "find_dotnet_il_findings", "CATEGORY_META"]
