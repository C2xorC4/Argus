"""Crypto / security-primitive analysis.

Combines `heuristics/crypto.py` data-driven matches (LCG / MT19937
constants, weak-key strings, CSPRNG vs non-CSPRNG imports, MD5 / DES
markers) with a structural detector for the *PRNG-flows-to-security-
sink* pattern (the canonical UE5 HandshakeSecret class).

Knowledge anchors:
- `[[Memory/Knowledge/ue5_prng_handshake_secret_recovery]]` — the
  real-world weak-PRNG-in-security-path finding.
- `[[Memory/Knowledge/gameguard_research_22_findings]]` — LCG-XOR
  custom cipher in production anti-cheat (also in obfuscation.py).

Phase 1 detectors:

1. Heuristics passthrough — LCG/MT/MD5/DES/AES-marker constants,
   weak-key strings, CSPRNG/non-CSPRNG import presence.
2. PRNG-to-crypto-sink — `rand()` / `random()` / `mt19937` output
   flowing as an argument to a known crypto API (BCryptEncrypt,
   EVP_*, HMAC_Init, gcry_*). Emits `weak_prng_in_security_path`.
3. CSPRNG-vs-non-CSPRNG balance — when only non-CSPRNG imports are
   present, emit a binary-scope advisory; when both are present, no
   finding (the safe path is reachable).

Phase 1 limitations:
- Variable-name-driven escalation (e.g., `token = rand()`) is not
  yet implemented; it requires symbol info that's typically stripped
  on production binaries. Phase 1+ will add it gated on `bv.symbols`
  density.
- IV reuse detection requires parameter-value range tracking across
  multiple cipher-init calls; deferred.
- Custom cipher signature recognition uses LCG constants; detection
  for rolling-XOR / one-byte-XOR patterns is Phase 1+.
"""

from __future__ import annotations

from typing import Optional

from ..heuristics import crypto as heur_crypto
from ..heuristics._base import imports_in
from ..output.finding import Evidence, Finding, Severity
from . import _il_helpers as ilh
from . import mitigations as mitigations_mod


# ─────────────────────────────────────────────────────────────────
# Crypto-sink registry — when PRNG output flows to one of these,
# the bug is `weak_prng_in_security_path` (high severity).
# ─────────────────────────────────────────────────────────────────


CRYPTO_SINKS: set[str] = {
    # Win32 CNG (BCrypt)
    "BCryptEncrypt", "BCryptDecrypt",
    "BCryptGenerateKeyPair", "BCryptGenerateSymmetricKey",
    "BCryptDeriveKeyPBKDF2", "BCryptDeriveKey",
    "BCryptHashData", "BCryptCreateHash",
    "BCryptSignHash", "BCryptVerifySignature",
    # Win32 legacy CryptoAPI
    "CryptHashData", "CryptCreateHash",
    "CryptEncrypt", "CryptDecrypt",
    "CryptDeriveKey", "CryptDestroyKey",
    "CryptGenKey",
    # OpenSSL
    "EVP_EncryptInit", "EVP_EncryptInit_ex", "EVP_EncryptUpdate",
    "EVP_DecryptInit", "EVP_DecryptInit_ex",
    "EVP_DigestInit", "EVP_DigestInit_ex", "EVP_DigestUpdate",
    "HMAC_Init", "HMAC_Init_ex", "HMAC_Update",
    "RSA_sign", "RSA_verify",
    "PKCS5_PBKDF2_HMAC", "PKCS5_PBKDF2_HMAC_SHA1",
    # libgcrypt
    "gcry_cipher_setkey", "gcry_cipher_setiv", "gcry_cipher_encrypt",
    "gcry_md_write", "gcry_mac_write", "gcry_kdf_derive",
    # Other security-relevant sinks (HMAC keying, signing keys)
    "HMAC", "SHA256_Update", "SHA1_Update", "MD5_Update",
}


PRNG_FUNCTIONS: set[str] = set(heur_crypto.NON_CSPRNG_IMPORTS.import_names)
CSPRNG_FUNCTIONS: set[str] = set(heur_crypto.CSPRNG_IMPORTS.import_names)


# ─────────────────────────────────────────────────────────────────
# Finding metadata
# ─────────────────────────────────────────────────────────────────


WEAK_PRNG_SECURITY_FLOW_META = {
    "category": "weak_prng_in_security_path",
    "severity": Severity.HIGH,
    "cwe": ["CWE-338", "CWE-330"],
    "mitre_attack": ["T1600"],
    "knowledge_refs": [
        "[[Memory/Knowledge/ue5_prng_handshake_secret_recovery]]",
    ],
}

CSPRNG_ABSENT_META = {
    "category": "csprng_absent",
    "severity": Severity.LOW,
    "cwe": ["CWE-330"],
    "mitre_attack": [],
    "knowledge_refs": [
        "[[Memory/Knowledge/ue5_prng_handshake_secret_recovery]]",
    ],
}


# ─────────────────────────────────────────────────────────────────
# Structural detector: PRNG output → crypto-sink flow
# ─────────────────────────────────────────────────────────────────


def _enumerate_prng_calls(bv) -> list[tuple[str, int, object]]:
    """Return [(prng_name, call_addr, mlil_inst), ...] for each call to
    a non-CSPRNG function present in the binary."""
    out: list[tuple[str, int, object]] = []
    imports = imports_in(bv)
    for prng_name in PRNG_FUNCTIONS:
        if prng_name not in imports:
            continue
        for addr, mlil in ilh.call_sites_of_import(bv, prng_name):
            if mlil is None:
                continue
            out.append((prng_name, addr, mlil))
    return out


def _flows_to_crypto_sink(bv, function, output_var,
                          *, max_depth: int = 3) -> Optional[tuple[str, int]]:
    """Walk SSA def-use forward from `output_var`. If a use is a Call
    to one of `CRYPTO_SINKS`, return (sink_name, call_addr). Else None.
    """
    if function is None or output_var is None:
        return None
    visited: set = set()
    stack: list = [(output_var, 0)]
    while stack:
        var, depth = stack.pop()
        key = (id(function), str(var))
        if key in visited or depth > max_depth:
            continue
        visited.add(key)
        for use in ilh.ssa_uses_of(function, var):
            op_name = getattr(getattr(use, "operation", None), "name", "")
            if "CALL" in op_name:
                callee_addr = ilh.callee_address_of_call(use)
                if callee_addr is not None and bv is not None:
                    sym = bv.get_symbol_at(callee_addr)
                    if sym is not None:
                        sink_name = (getattr(sym, "short_name", None)
                                     or getattr(sym, "name", ""))
                        if sink_name in CRYPTO_SINKS:
                            return (sink_name, int(getattr(use, "address", 0)))
                # Continue propagation through call output (intra-proc)
                ssa_form = getattr(use, "ssa_form", None)
                output = (getattr(use, "output", None)
                          or getattr(ssa_form, "dest", None) if ssa_form else None)
                if output is None:
                    continue
                outputs = output if hasattr(output, "__iter__") else [output]
                for new_var in outputs:
                    stack.append((new_var, depth + 1))
                continue
            # Non-call use: propagate via output
            output = getattr(use, "output", None)
            if output is None:
                ssa_form = getattr(use, "ssa_form", None)
                output = getattr(ssa_form, "dest", None) if ssa_form else None
            if output is None:
                continue
            outputs = output if hasattr(output, "__iter__") else [output]
            for new_var in outputs:
                stack.append((new_var, depth + 1))
    return None


def find_prng_to_security_sink(bv, *, binary: str, arch: str, platform: str,
                              detector: str) -> list[Finding]:
    findings: list[Finding] = []
    for prng_name, prng_addr, mlil in _enumerate_prng_calls(bv):
        output_var = ilh.call_output_ssa(mlil)
        if output_var is None:
            continue
        function = getattr(mlil, "function", None)
        result = _flows_to_crypto_sink(bv, function, output_var)
        if result is None:
            continue
        sink_name, sink_addr = result
        meta = WEAK_PRNG_SECURITY_FLOW_META
        func_name = getattr(function, "name", "") if function else ""
        findings.append(Finding(
            id="",
            category=meta["category"],
            severity=meta["severity"],
            address=sink_addr,
            function=func_name,
            binary=binary, arch=arch, platform=platform,
            detector=detector,
            knowledge_refs=list(meta["knowledge_refs"]),
            cwe=list(meta["cwe"]),
            mitre_attack=list(meta["mitre_attack"]),
            description=(
                f"non-CSPRNG output ({prng_name}@0x{prng_addr:x}) flows to "
                f"crypto sink ({sink_name}@0x{sink_addr:x})"
            ),
            evidence=[Evidence(
                kind="prng_to_sink_flow",
                source=detector,
                payload=f"{prng_name}@0x{prng_addr:x} -> {sink_name}@0x{sink_addr:x}",
                address=sink_addr,
                function=func_name,
            )],
            details={
                "prng_name": prng_name,
                "prng_addr": hex(prng_addr),
                "sink_name": sink_name,
                "sink_addr": hex(sink_addr),
            },
        ))
    return findings


# ─────────────────────────────────────────────────────────────────
# CSPRNG balance check
# ─────────────────────────────────────────────────────────────────


def find_csprng_absence(bv, *, binary: str, arch: str, platform: str,
                       detector: str) -> list[Finding]:
    """Emit a low-severity advisory when a binary uses non-CSPRNG
    imports without any CSPRNG import — the safe path isn't even
    reachable."""
    if bv is None:
        return []
    imports = imports_in(bv)
    has_non_csprng = any(n in imports for n in PRNG_FUNCTIONS)
    has_csprng = any(n in imports for n in CSPRNG_FUNCTIONS)
    if not has_non_csprng or has_csprng:
        return []
    meta = CSPRNG_ABSENT_META
    return [Finding(
        id="",
        category=meta["category"],
        severity=meta["severity"],
        address=0,
        function="<binary>",
        binary=binary, arch=arch, platform=platform,
        detector=detector,
        knowledge_refs=list(meta["knowledge_refs"]),
        cwe=list(meta["cwe"]),
        mitre_attack=list(meta["mitre_attack"]),
        description=(
            "binary imports non-CSPRNG functions but no CSPRNG entry — "
            "any security-relevant random output is predictable"
        ),
        details={
            "non_csprng_present": [n for n in PRNG_FUNCTIONS if n in imports],
        },
    )]


# ─────────────────────────────────────────────────────────────────
# Public entry
# ─────────────────────────────────────────────────────────────────


def analyze(session, *, binary: Optional[str] = None,
            arch: Optional[str] = None, platform: Optional[str] = None,
            score_against_mitigations: bool = True,
            detector: str = "analysis.crypto") -> list[Finding]:
    if session is None:
        return []
    bv = getattr(session, "bv", None)
    if bv is None:
        return []
    binary = binary or getattr(session, "binary_path", "") or ""
    arch = arch or (str(bv.arch) if bv.arch else "unknown")
    platform = platform or (str(bv.platform) if bv.platform else "unknown")

    findings: list[Finding] = []
    # 1. Heuristics-driven (constants, strings, imports).
    findings.extend(heur_crypto.match(
        bv, binary=binary, arch=arch, platform=platform,
    ))
    # 2. Structural — PRNG flow to crypto sink.
    findings.extend(find_prng_to_security_sink(
        bv, binary=binary, arch=arch, platform=platform, detector=detector,
    ))
    # 3. CSPRNG-absent advisory.
    findings.extend(find_csprng_absence(
        bv, binary=binary, arch=arch, platform=platform, detector=detector,
    ))

    if score_against_mitigations and findings and binary:
        try:
            profile = mitigations_mod.extract_mitigations(binary, bv=bv)
            mitigations_mod.score_findings(findings, profile)
        except Exception:
            pass

    return findings
