"""Pre-verification write detection (Plan B from Run 15).

Detects the canonical "commit-before-verify with no rollback" CFG
shape: a function performs a data-commit (writes attacker-supplied
bytes to a file or allocates and fills a buffer) BEFORE running an
integrity check, AND the failure branch of the check does not roll
back the write. The committed data persists when verification fails,
giving an attacker a primitive for poisoning trusted state.

This is the EAC EOS arbitrary-write chain's canonical pattern (Sub
01 from the BinaryBounty/h1/EpicGames work). Generalises to package
installers (pre-extract before signature check), downloader caches
(commit-before-verify), and any signed-content pipeline that writes
first and verifies second.

Detection v1 — function-level structural pattern:

1. Function calls a data-commit sink (WriteFile / WriteFileEx /
   NtWriteFile / etc.).
2. Function does NOT call a matching rollback API (DeleteFileW /
   DeleteFileA for filesystem commits).
3. Function contains at least one conditional branch — implying a
   failure path exists where the un-rolled-back commit persists.

Limitations (v1):

- Function-level granularity, not per-CFG-path. A function that
  conditionally calls DeleteFileW (only on the success path)
  passes the detector. v2 should use CFG dominance: confirm that
  every path from the commit to function-exit goes through a
  rollback when the verification fails.
- Resource-type parameterisation is partial. v1 covers the
  Win32-API filesystem case (WriteFile → DeleteFileW). v2 should
  parameterise by resource type to cover Empty()+AddUninitialized()
  / FMemory::Free pairs (UE5), heap-allocator pre-fill (custom
  pre-verify protocols), and registry-key commits.
- Native-API writes (NtWriteFile via Nt-syscall stubs) are
  included in the commit set but matched only when imported by
  name; obfuscated direct-syscall stubs (per Run 15 daydream)
  bypass this detector.

Knowledge anchors:
- `[[Memory/Knowledge/eac_eos_arbitrary_write_chain]]` — canonical
  pattern (Component 2 of the EAC EOS chain)
"""

from __future__ import annotations

from typing import Optional

from ..heuristics._base import imports_in
from ..lib.scoring import apply_signals_to_finding
from ..output.finding import Evidence, Finding, Severity
from . import _cfg_primitives as cfg
from . import _il_helpers as ilh


# ─────────────────────────────────────────────────────────────────
# Sink sets — commit / cleanup pairs by resource type
# ─────────────────────────────────────────────────────────────────


# Data-commit imports — calls that write attacker-supplied data to a
# persistent or downstream-trusted location. Mapping: import → resource
# type label (used to select the matching rollback set).
_COMMIT_IMPORTS: dict[str, str] = {
    # Win32 file I/O
    "WriteFile":    "win32_file",
    "WriteFileEx":  "win32_file",
    # Native API
    "NtWriteFile":  "native_file",
    "ZwWriteFile":  "native_file",
    # POSIX
    "write":        "posix_file",
    "pwrite":       "posix_file",
    "writev":       "posix_file",
    # Note: memcpy / memmove are too generic to count as "commits" at
    # this layer — they're often internal data movement, not commits
    # to a trust boundary. Add explicit native-buffer commits here as
    # they're identified.
}


# Rollback / cleanup imports per resource type — a function that
# commits to `<resource_type>` should also call something from the
# matching rollback set if it claims to clean up on failure.
_ROLLBACK_BY_RESOURCE: dict[str, frozenset[str]] = {
    "win32_file": frozenset({
        "DeleteFileA", "DeleteFileW", "DeleteFile",
        "MoveFileExA", "MoveFileExW",        # rename to backup is also rollback
        "RemoveDirectoryA", "RemoveDirectoryW",
    }),
    "native_file": frozenset({
        "NtDeleteFile", "ZwDeleteFile",
        "NtSetInformationFile", "ZwSetInformationFile",   # via FileDispositionInformation
    }),
    "posix_file": frozenset({
        "unlink", "remove", "rmdir", "unlinkat",
    }),
    # UE5 engine-allocator commits — `Empty(N)+AddUninitialized(N)`
    # commits the buffer; rollback is a fresh `Empty()` reset
    # (or `FMemory::Free`) on the failure path. v2 daydream-flagged
    # — covers the UE5 FString allocation-amplification chain.
    "ue5_buffer": frozenset({
        "Empty",                  # FString/TArray reset
        "FMemory::Free", "FMemory::Realloc",
        "Reset",                  # TArray::Reset
        "Reserve",                # may overwrite with smaller alloc
    }),
}


# Resource-type expansion: the UE5 `Empty()+AddUninitialized()`
# commit pattern. Detector v2 — pattern-matches mangled names via
# substring (template parameter variation tolerated).
_UE5_COMMIT_TOKENS: tuple[str, ...] = (
    "AddUninitialized", "AddDefaulted", "AddZeroed",
    # Parallel: BulkSerialize-class direct-write
    "BulkSerializeFromArray",
)


# Verify-class imports — calls that imply integrity verification is
# happening near the commit. Used to UPGRADE confidence: a function
# that commits + (later) verifies is a stronger signal than commit
# alone, and one that commits + verifies + has no rollback is the
# canonical "pre-verify write with no cleanup" pattern.
_VERIFY_IMPORTS: frozenset[str] = frozenset({
    # Win32 cryptographic verify
    "WinVerifyTrust", "WinVerifyTrustEx",
    "CryptVerifySignatureA", "CryptVerifySignatureW",
    "CryptVerifyMessageSignature", "CryptVerifyDetachedMessageSignature",
    "BCryptVerifySignature",
    "NCryptVerifySignature",
    "CryptHashCertificate",
    # OpenSSL / libcrypto
    "EVP_VerifyFinal", "EVP_VerifyUpdate",
    "ECDSA_verify", "RSA_verify",
    "EVP_DigestVerifyFinal",
    # mbedtls
    "mbedtls_pk_verify", "mbedtls_rsa_pkcs1_verify",
    # Hash compare (weaker — could be safe or unsafe depending on use)
    "memcmp",     # only counted when applied to digest output
})


CATEGORY_META = {
    "pre_verification_write": {
        "severity": Severity.HIGH,
        "cwe": ["CWE-471", "CWE-377"],
        "mitre": ["T1546"],
        "knowledge_refs": [
            "[[Memory/Knowledge/eac_eos_arbitrary_write_chain]]",
        ],
    },
}


# ─────────────────────────────────────────────────────────────────
# Helpers — function-level call-set introspection
# ─────────────────────────────────────────────────────────────────


def _to_ssa(func):
    """Normalise to MLIL SSA form. Accepts either Function or
    MediumLevelILFunction; returns the SSA form or None.
    """
    if func is None:
        return None
    # MediumLevelILFunction → .ssa_form
    if hasattr(func, "ssa_form"):
        ssa = func.ssa_form
        if ssa is not None and hasattr(ssa, "instructions"):
            return ssa
        # Some forms have .instructions directly
        if hasattr(func, "instructions"):
            return func
    # Regular Function → .mlil → .ssa_form
    mlil = getattr(func, "mlil", None)
    if mlil is not None:
        ssa = getattr(mlil, "ssa_form", None)
        if ssa is not None and hasattr(ssa, "instructions"):
            return ssa
        if hasattr(mlil, "instructions"):
            return mlil
    return None


def _function_call_set(bv, func) -> set[str]:
    """Return the set of named imports called from `func`, including
    transitive thunk calls.

    Walks MLIL Call instructions, resolves each call's destination to
    a symbol, and adds the symbol's short_name to the result set.
    """
    if bv is None:
        return set()
    out: set[str] = set()
    ssa = _to_ssa(func)
    if ssa is None:
        return out
    try:
        for inst in ssa.instructions:
            op_name = type(inst).__name__
            if "Call" not in op_name:
                continue
            dest = getattr(inst, "dest", None)
            cval = getattr(dest, "constant", None) if dest else None
            if cval is None:
                continue
            sym = bv.get_symbol_at(int(cval))
            if sym is None:
                continue
            short = getattr(sym, "short_name", None) or sym.name or ""
            if short:
                out.add(short)
                # Also strip `__imp_` prefix so callers can match
                # against the canonical name.
                if short.startswith("__imp_"):
                    out.add(short[len("__imp_"):])
    except Exception:
        pass
    return out


def _function_has_conditional(func) -> bool:
    """True if `func` contains any conditional branch instruction.

    Implies a failure path exists where un-rolled-back commits
    persist. Pure-success-path functions (no conditionals) are
    excluded — they don't have a "verification failure" branch
    and can't match the pattern.
    """
    ssa = _to_ssa(func)
    if ssa is None:
        return False
    try:
        for inst in ssa.instructions:
            op_name = type(inst).__name__
            if "If" in op_name or "Cmp" in op_name:
                return True
    except Exception:
        pass
    return False


def _rollback_dominates_all_exits_after_commit(func, commit_addr: int,
                                               rollback_call_sites: list[int]
                                               ) -> bool:
    """v2: True iff every CFG path from the commit site to a function
    return passes through at least one rollback call.

    Replaces the v1 function-level grant ("function calls SOMETHING
    from rollback_set => assume cleanup is in place"). v2 confirms
    the cleanup actually happens on the failure path.

    Implementation: a rollback call must dominate every return
    instruction reachable from the commit site. Equivalently,
    every return site that's reachable from the commit must have
    at least one rollback call dominating it.

    Returns True when the function is plausibly safe (rollback
    covers exits), False when at least one return path lacks
    rollback coverage.
    """
    if not rollback_call_sites:
        return False
    ssa = _to_ssa(func)
    if ssa is None:
        return False
    # Find all return sites
    return_addrs: list[int] = []
    try:
        for inst in ssa.instructions:
            if "Ret" in type(inst).__name__ and "Return" not in type(inst).__name__:
                # MediumLevelILRet / similar
                return_addrs.append(int(getattr(inst, "address", 0)))
            elif "Return" in type(inst).__name__:
                return_addrs.append(int(getattr(inst, "address", 0)))
    except Exception:
        return False
    if not return_addrs:
        return False
    # Filter to returns reachable from commit (i.e., commit dominates ret)
    # A return that doesn't post-dominate the commit is irrelevant.
    relevant_returns = []
    for ret_addr in return_addrs:
        try:
            if cfg.instruction_dominates(func, commit_addr, ret_addr):
                relevant_returns.append(ret_addr)
        except Exception:
            relevant_returns.append(ret_addr)    # be inclusive on error
    if not relevant_returns:
        # Commit doesn't reach any return (dead code? early-exit?) — treat as safe
        return True
    # For each relevant return, check: at least one rollback dominates it
    for ret_addr in relevant_returns:
        covered = False
        for rb_addr in rollback_call_sites:
            if rb_addr <= commit_addr:
                # Rollback before commit doesn't apply
                continue
            try:
                if cfg.instruction_dominates(func, rb_addr, ret_addr):
                    covered = True
                    break
            except Exception:
                continue
        if not covered:
            return False
    return True


# ─────────────────────────────────────────────────────────────────
# Detector
# ─────────────────────────────────────────────────────────────────


def find_pre_verification_writes(bv, *, binary: str, arch: str, platform: str,
                                 detector: str = "analysis.integrity_check_order"
                                 ) -> list[Finding]:
    findings: list[Finding] = []
    if bv is None:
        return findings
    imports = imports_in(bv)

    # Quick filter: binary must import at least one commit sink
    commit_imports_present = imports & set(_COMMIT_IMPORTS)
    if not commit_imports_present:
        return findings

    # For each commit sink call site, classify the containing function
    # by its call-set. Emit one finding per function where the pattern
    # matches.
    seen_function_keys: set[int] = set()
    for sink_name in commit_imports_present:
        resource = _COMMIT_IMPORTS[sink_name]
        rollback_set = _ROLLBACK_BY_RESOURCE.get(resource, frozenset())
        for addr, mlil in ilh.call_sites_of_import(bv, sink_name):
            if mlil is None:
                continue
            func = getattr(mlil, "function", None)
            if func is None:
                continue
            fkey = ilh.function_key(func)
            if fkey in seen_function_keys:
                continue
            seen_function_keys.add(fkey)

            call_set = _function_call_set(bv, func)
            # v2: CFG-path-sensitive rollback check.
            # If this function imports rollbacks for this resource,
            # confirm they actually dominate every return reachable
            # from the commit. Function-level grant (v1) was too
            # permissive — a function with rollback only on the
            # success path was wrongly cleared.
            if call_set & rollback_set:
                # Locate rollback call addresses
                rollback_addrs: list[int] = []
                for rb_name in (call_set & rollback_set):
                    for rb_addr, _rb_mlil in ilh.call_sites_of_import(bv, rb_name):
                        # Only count rollbacks IN THIS function
                        rb_func = getattr(_rb_mlil, "function", None) if _rb_mlil else None
                        if rb_func is not None and ilh.function_key(rb_func) == fkey:
                            rollback_addrs.append(rb_addr)
                if _rollback_dominates_all_exits_after_commit(
                        func, addr, rollback_addrs):
                    continue
                # Falls through to emit — rollback present but doesn't
                # cover all failure paths.
            # Skip pure-success-path functions (no conditional branch
            # means no failure path)
            if not _function_has_conditional(func):
                continue
            # Verify presence is a confidence boost, not a gate; the
            # canonical EAC pattern uses a CUSTOM verify_payload and
            # imports nothing from the verify set. Track for
            # description.
            verify_present = bool(call_set & _VERIFY_IMPORTS)
            func_name = ilh.function_display_name(func)
            meta = CATEGORY_META["pre_verification_write"]
            finding = Finding(
                id="",
                category="pre_verification_write",
                severity=meta["severity"],
                address=addr,
                function=func_name,
                binary=binary, arch=arch, platform=platform,
                detector=detector,
                knowledge_refs=list(meta["knowledge_refs"]),
                cwe=list(meta["cwe"]),
                mitre_attack=list(meta["mitre"]),
                description=(
                    f"{sink_name}@0x{addr:x} commits data to {resource} in "
                    f"{func_name} but the function does not call any rollback "
                    f"({sorted(rollback_set)[:3]}...) on the failure path. "
                    f"{'Imported verify call detected; commit precedes verify.' if verify_present else 'Custom verify likely (no imported verify in this function).'}"
                ),
                evidence=[Evidence(
                    kind="commit_without_rollback",
                    source=detector,
                    payload=(f"commit={sink_name}@0x{addr:x} resource={resource} "
                             f"verify_imported={verify_present}"),
                    address=addr,
                    function=func_name,
                )],
                details={
                    "commit_name": sink_name,
                    "resource_type": resource,
                    "verify_imported": verify_present,
                    "rollback_set_searched": sorted(rollback_set),
                },
            )
            apply_signals_to_finding(finding, [
                "commit_without_rollback_for_resource",   # SPECIFIC
            ])
            findings.append(finding)

    return findings


# ─────────────────────────────────────────────────────────────────
# Public entry
# ─────────────────────────────────────────────────────────────────


def analyze(session, *, binary: Optional[str] = None,
            arch: Optional[str] = None, platform: Optional[str] = None,
            detector: str = "analysis.integrity_check_order"
            ) -> list[Finding]:
    if session is None:
        return []
    bv = getattr(session, "bv", None)
    if bv is None:
        return []
    binary = binary or getattr(session, "binary_path", "") or ""
    arch = arch or (str(bv.arch) if bv.arch else "unknown")
    platform = platform or (str(bv.platform) if bv.platform else "unknown")

    return find_pre_verification_writes(
        bv, binary=binary, arch=arch, platform=platform, detector=detector,
    )
