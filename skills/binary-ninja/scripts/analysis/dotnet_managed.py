"""Managed / metadata-rich binary detector — .NET + Go.

Some compiled languages embed substantial type and API metadata
in the produced binary, even after stripping:
  - .NET assemblies (`.dll`) carry IL + the CLR metadata table
    with every type, method, and member name.
  - Go binaries carry runtime-type strings (`*pkg.Type`),
    package paths, and standard-library entry-point names.

Argus's native-instruction taint pipeline doesn't apply to
either: there's no MSVC-style import table, no
machine-instruction sinks at the language-relevant level. But
the strings ARE recoverable from the binary's string table, and
dangerous-API references leave distinctive markers.

This detector emits findings when those markers co-occur. v1 is
heuristic string co-presence; precise enough for canonical
fixture shapes and useful as a first-pass against real
managed/Go binaries. v2 would walk the IL (.NET) or DWARF /
gopclntab (Go) and inspect actual call sites.

Knowledge anchor: `[[Memory/Knowledge/argus_detector_design_principles]]`
"""

from __future__ import annotations

from typing import Optional

from ..heuristics._base import strings_in
from ..output.finding import Evidence, Finding, Severity
from . import _il_helpers as ilh                                # noqa: F401


CATEGORY_META = {
    "insecure_deserialization": {
        "severity": Severity.CRITICAL,
        "cwe": ["CWE-502"],
        "mitre": ["T1190"],
        "knowledge_refs": [
            "[[Memory/Knowledge/argus_detector_design_principles]]",
        ],
    },
    "managed_unsafe_block": {
        "severity": Severity.MEDIUM,
        "cwe": ["CWE-119"],
        "mitre": ["T1203"],
        "knowledge_refs": [
            "[[Memory/Knowledge/argus_detector_design_principles]]",
        ],
    },
    "managed_dangerous_api": {
        "severity": Severity.HIGH,
        "cwe": ["CWE-749"],
        "mitre": ["T1059"],
        "knowledge_refs": [
            "[[Memory/Knowledge/argus_detector_design_principles]]",
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
    "type_confusion": {
        "severity": Severity.HIGH,
        "cwe": ["CWE-843"],
        "mitre": ["T1203"],
        "knowledge_refs": [
            "[[Memory/Knowledge/ec_undefined_behavior_taxonomy]]",
            "[[Memory/Knowledge/bhg_unsafe_pointer_patterns]]",
        ],
    },
    "type_confusion_candidate": {
        "severity": Severity.INFO,
        "cwe": ["CWE-843"],
        "mitre": ["T1203"],
        "knowledge_refs": [
            "[[Memory/Knowledge/ec_undefined_behavior_taxonomy]]",
            "[[Memory/Knowledge/bhg_unsafe_pointer_patterns]]",
        ],
    },
    "stack_buffer_overflow": {
        "severity": Severity.HIGH,
        "cwe": ["CWE-121"],
        "mitre": ["T1203"],
        "knowledge_refs": [
            "[[Memory/Knowledge/hw_stack_overflow_mechanics]]",
            "[[Memory/Knowledge/argus_detector_design_principles]]",
        ],
    },
    "rust_runtime_present": {
        "severity": Severity.INFO,
        "cwe": [],
        "mitre": [],
        "knowledge_refs": [
            "[[Memory/Knowledge/argus_detector_design_principles]]",
        ],
    },
}


# (category, all_required_strings, description)
# When `all_required_strings` are ALL present in the assembly's
# metadata, the corresponding category is emitted.
_MANAGED_RULES: tuple[tuple[str, tuple[str, ...], str], ...] = (
    # Classical BinaryFormatter deserialise — universally exploitable
    # via gadget chains.
    ("insecure_deserialization",
     ("BinaryFormatter", "Deserialize"),
     "BinaryFormatter.Deserialize reference in .NET assembly — gadget-chain RCE class"),
    # ObjectInputStream-like alternates.
    ("insecure_deserialization",
     ("NetDataContractSerializer", "ReadObject"),
     "NetDataContractSerializer.ReadObject — same gadget-chain class as BinaryFormatter"),
    ("insecure_deserialization",
     ("SoapFormatter", "Deserialize"),
     "SoapFormatter.Deserialize — gadget-chain class"),
    ("insecure_deserialization",
     ("LosFormatter", "Deserialize"),
     "LosFormatter.Deserialize — ASP.NET gadget-chain class"),
    ("insecure_deserialization",
     ("JavaScriptSerializer", "Deserialize"),
     "JavaScriptSerializer with TypeNameHandling — gadget-chain candidate"),
    # JSON.NET TypeNameHandling.All / Auto produces gadget-chain
    # candidate when paired with attacker-controlled JSON.
    ("insecure_deserialization",
     ("Newtonsoft.Json", "TypeNameHandling"),
     "Newtonsoft.Json + TypeNameHandling reference — gadget-chain candidate when value is All / Auto"),

    # Dangerous-API class. These aren't always bugs but warrant
    # operator attention — the assembly invokes the API class.
    ("managed_dangerous_api",
     ("System.Diagnostics.Process", "Start"),
     "Process.Start in managed code — command-injection candidate when args attacker-controlled"),
    ("managed_dangerous_api",
     ("System.Reflection.Assembly", "Load"),
     "Assembly.Load — runtime code-load primitive (reflection-based code execution)"),
    ("managed_dangerous_api",
     ("Marshal.GetDelegateForFunctionPointer",),
     "Marshal.GetDelegateForFunctionPointer — native-to-managed cast primitive"),

    # Use-after-Dispose analog (C# / .NET). Pure managed code doesn't
    # UAF in the C sense (GC), but `IDisposable.Dispose()` releases
    # unmanaged resources; subsequent method calls on the disposed
    # object operate on freed unmanaged state. `ObjectDisposedException`
    # in the metadata is a strong indicator — the binary either calls
    # APIs that throw ODE or implements IDisposable and references the
    # exception type itself. CWE-416 (analog).
    ("use_after_free",
     ("ObjectDisposedException",),
     "ObjectDisposedException reference in managed assembly — "
     "use-after-Dispose analog; subsequent method call on a disposed "
     "object operates on freed unmanaged state"),

    # Managed type-confusion shapes (Rust transmute / C# Unsafe.As /
    # Marshal.PtrToStructure). Strings co-presence is the v1 signal;
    # v2 (CLI metadata MemberRef walk) gates precisely.
    ("type_confusion",
     ("Marshal", "PtrToStructure"),
     "Marshal.PtrToStructure reference — reinterprets raw bytes as a "
     "managed struct without validating layout (C# unsafe-pointer "
     "type-confusion shape)"),
    ("type_confusion",
     ("System.Runtime.CompilerServices.Unsafe", "As"),
     "System.Runtime.CompilerServices.Unsafe.As reference — managed "
     "type-pun primitive (compiles to direct bit-reinterpret across "
     "T1 and T2)"),
)


def _strings_contain_all(string_set: set, needles: tuple) -> bool:
    """True iff every needle appears as a substring in some string
    in `string_set`. Each needle independently — they don't have to
    co-occur in the same string."""
    for n in needles:
        if not any(n in s for s in string_set):
            return False
    return True


def _is_managed_assembly(bv) -> bool:
    """Heuristic: this is a .NET managed assembly when its strings
    include the CLR metadata-blob markers."""
    string_table = strings_in(bv) or []
    markers = ("System.Runtime", "System.Object", "mscorlib",
               "System.Private.CoreLib", "Microsoft.NETCore.App")
    seen = set()
    for s, _ in string_table:
        for m in markers:
            if m in s:
                seen.add(m)
    return len(seen) >= 1


def _is_rust_binary(bv) -> bool:
    """Heuristic: Rust binaries embed distinctive runtime markers.
    Optimised release builds strip most `core::*` paths, so detection
    leans on `rust_panic` (always present from the unwind machinery)
    plus a cargo-registry path embedded in panic strings.
    """
    string_table = strings_in(bv) or []
    seen_panic = False
    seen_cargo = False
    for s, _ in string_table:
        if not seen_panic and "rust_panic" in s:
            seen_panic = True
        if not seen_cargo and ".cargo" in s and "registry" in s:
            seen_cargo = True
        # Fallback: any of the older `core::` / `__rust_alloc`
        # markers also count.
        if "__rust_alloc" in s or "core::panicking" in s:
            return True
        if seen_panic and seen_cargo:
            return True
    return seen_panic


# Rust-specific managed-equivalent rules. Rust mangles crate
# names into symbol-prefix form (`_ZN<len><crate>...`) — most
# crate names don't appear as standalone strings. The detection
# leans on serde-stack runtime strings (the cargo registry path
# embedded in panics, `serde_core` runtime, and the `deserialize`
# trait-method name).
_RUST_RULES: tuple[tuple[str, tuple[str, ...], str], ...] = (
    # serde-stack deserialiser. The `deserialize` trait method
    # name surfaces as a string when a binary uses any serde
    # deserialise path. Combine with `serde_core` (libcore runtime)
    # to suppress on binaries that just happen to use serde for
    # serialise only.
    ("insecure_deserialization",
     ("serde_core", "deserialize"),
     "serde stack deserialise — bincode / serde_json / rmp-serde on attacker bytes (DoS / type-narrowing class)"),
)


def _is_go_binary(bv) -> bool:
    """Heuristic: this is a Go binary when its strings include
    distinctive runtime markers (`runtime.morestack`, package
    path strings, or `*pkg.Type` reflection-name prefixes)."""
    string_table = strings_in(bv) or []
    markers = ("runtime.morestack", "go:itab.", "runtime.g0",
               "gopclntab", "runtime.malloc", "encoding/gob",
               "go.string.")
    seen = set()
    for s, _ in string_table:
        for m in markers:
            if m in s:
                seen.add(m)
                if len(seen) >= 2:
                    return True
    return False


# Go-specific managed-equivalent rules — keyed on package paths and
# canonical receiver names that the Go runtime emits as strings
# for reflection (`*pkg.Type` form).
_GO_RULES: tuple[tuple[str, tuple[str, ...], str], ...] = (
    # encoding/gob deserialiser — gob.Decoder.Decode on attacker
    # data is the canonical Go gadget-chain class (no length cap,
    # decoder allocates per attacker spec).
    ("insecure_deserialization",
     ("*gob.Decoder", "gob.NewDecoder"),
     "encoding/gob Decoder reference — gob.Decode on attacker-controlled stream"),
    ("insecure_deserialization",
     ("*gob.Decoder",),
     "encoding/gob Decoder reference — gob.Decode on attacker-controlled stream"),
    # encoding/json with reflection-based type-narrowing under
    # interface{} unmarshal — the "Trail of Bits / Go reflection
    # confused-deputy" class.
    ("insecure_deserialization",
     ("encoding/json", "*json.Decoder", "json.NewDecoder"),
     "json.Decoder.Decode with interface{} target — type-narrowing gadget class"),

    # cgo-boundary stack-overflow shape. Pure Go can't classical-stack-
    # overflow (runtime guards every slice access), but a cgo
    # boundary delegates to C — where the C side can do whatever the
    # author wrote, including `strcpy(buf, attacker_input)`. The
    # binary having BOTH `_cgo_runtime_cgocall` (cgo entry-point
    # bridge) AND `strcpy` (libc function pulled in by the cgo C
    # blob) is a strong indicator of a cgo-bridged C blob with
    # classical bounds-free string operations.
    ("stack_buffer_overflow",
     ("_cgo_runtime_cgocall", "strcpy"),
     "Go binary with cgo bridge + strcpy reference — C blob crossed "
     "via cgo can stack-overflow with the same C-side bounds-free "
     "semantics (CWE-121, cgo-bridged)"),

    # Unsafe.Pointer-based reinterpret. Go binaries that import
    # `unsafe` have a runtime-visible string for it. The runtime
    # version detector already requires Go origin; an `unsafe.Pointer`
    # marker plus user-package functions (main.*) is a research-
    # candidate signal — could be type-confusion OR a UAF analog
    # OR a legitimate optimisation pattern. Emit as candidate /
    # INFO-grade until gopclntab walk or MLIL inspection gates it.
    ("type_confusion_candidate",
     ("unsafe.Pointer", "main."),
     "Go binary references unsafe.Pointer in main package — research "
     "candidate; the unsafe.Pointer escape valve can produce both "
     "type-confusion (cross-struct reinterpret) and UAF (raw pointer "
     "into a slice whose backing array gets reallocated). v2 "
     "gopclntab walk required to classify per call site."),
)


# Rust-rules extension. The release-build string table is identical
# across stack-OF / type-confusion / UAF cells, so per-category
# precision from strings alone is impossible. Emit an info-grade
# `language_origin` finding so the rollup can identify the binary's
# language without making per-bug claims. PDB / DWARF v2 will refine.
_RUST_INFO_RULES: tuple[tuple[str, tuple[str, ...], str], ...] = (
    ("rust_runtime_present",
     ("panicked at", "rust_panic"),
     "Rust-compiled binary (release-build stdlib panic machinery "
     "present). Per-category classification requires PDB / DWARF "
     "walk; release builds strip user-code symbols."),
)


def find_dotnet_managed_findings(
        bv, *, binary: str, arch: str, platform: str,
        detector: str = "analysis.dotnet_managed",
) -> list[Finding]:
    findings: list[Finding] = []
    if bv is None:
        return findings
    is_dotnet = _is_managed_assembly(bv)
    is_go = _is_go_binary(bv)
    is_rust = _is_rust_binary(bv)
    if not is_dotnet and not is_go and not is_rust:
        return findings
    string_set = {s for s, _ in (strings_in(bv) or [])}
    if not string_set:
        return findings

    rules = list(_MANAGED_RULES) if is_dotnet else []
    if is_go:
        rules.extend(_GO_RULES)
    if is_rust:
        rules.extend(_RUST_RULES)
        rules.extend(_RUST_INFO_RULES)

    seen_categories: set[str] = set()
    for category, needles, description in rules:
        if category in seen_categories and category != "managed_dangerous_api":
            # For most categories, emit once per assembly. Dangerous-
            # API findings emit per-rule because each names a
            # distinct API.
            continue
        if not _strings_contain_all(string_set, needles):
            continue
        seen_categories.add(category)
        meta = CATEGORY_META.get(category, {})
        # Anchor at the entry of the assembly (no per-call-site
        # resolution available without IL parsing).
        anchor_func = None
        for fn in (bv.functions or []):
            if (getattr(fn, "name", "") or "") in ("Main", "Vuln.Main",
                                                   "_CorExeMain"):
                anchor_func = fn
                break
        if anchor_func is None:
            anchor_func = bv.entry_function or (
                bv.functions[0] if bv.functions else None)
        addr = int(getattr(anchor_func, "start", 0) or 0)
        fname = getattr(anchor_func, "name", "<entry>") if anchor_func else "<binary>"
        findings.append(Finding(
            id="",
            category=category,
            severity=meta["severity"],
            address=addr,
            function=fname,
            binary=binary, arch=arch, platform=platform,
            detector=detector,
            knowledge_refs=list(meta["knowledge_refs"]),
            cwe=list(meta["cwe"]),
            mitre_attack=list(meta["mitre"]),
            description=description,
            evidence=[Evidence(
                kind=("method_call" if category == "insecure_deserialization"
                      else "managed_type_reference"),
                source=detector,
                payload=f"strings_present={list(needles)}",
                address=addr, function=fname,
            ), Evidence(
                kind="managed_type_reference",
                source=detector,
                payload=" ".join(needles),
                address=addr, function=fname,
            )],
            details={
                "matched_strings": list(needles),
                "managed_assembly": True,
            },
        ))
    return findings


def analyze(session, *, binary: Optional[str] = None,
            arch: Optional[str] = None, platform: Optional[str] = None,
            detector: str = "analysis.dotnet_managed"
            ) -> list[Finding]:
    if session is None:
        return []
    bv = getattr(session, "bv", None)
    if bv is None:
        return []
    binary = binary or getattr(session, "binary_path", "") or ""
    arch = arch or (str(bv.arch) if bv.arch else "unknown")
    platform = platform or (str(bv.platform) if bv.platform else "unknown")
    return find_dotnet_managed_findings(
        bv, binary=binary, arch=arch, platform=platform, detector=detector,
    )
