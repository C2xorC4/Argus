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

import re
from typing import Optional

from ..heuristics import crypto as heur_crypto
from ..heuristics._base import imports_in
from ..output.finding import Evidence, Finding, Severity
from . import _il_helpers as ilh
from . import mitigations as mitigations_mod


# ─────────────────────────────────────────────────────────────────
# Security-name escalation
# ─────────────────────────────────────────────────────────────────
#
# Symbol-name signal: a non-CSPRNG call inside a function whose name
# (or caller's name) carries a security-class identifier is the
# canonical UE5 HandshakeSecret shape — `FMath::Rand` inside
# `UpdateSecret`/`MakeNonce`/`IssueToken`. Catches cases where the
# PRNG output never reaches a registered crypto API, but the
# enclosing context makes the security relevance explicit.
#
# Matched as substring for distinct tokens, or word-bounded for
# tokens prone to noise (key → monkey, iv → drive, sig → design).
# Token alternation is case-insensitive via the `(?i:...)` inline
# group; boundary anchors stay case-sensitive so the camelCase
# transition (`(?<=[a-z])(?=[A-Z])`) actually requires a case
# transition. A whole-pattern IGNORECASE flag would make `[a-z]` and
# `[A-Z]` both match any letter and silently degrade the boundary
# check to "any letter to any letter."
_SEC_NAME_RE = re.compile(
    r"(?:^|_|(?<=[a-z])(?=[A-Z]))"
    r"(?P<tok>(?i:token|secret|nonce|password|passwd|credential|"
    r"session|cookie|salt|hmac|signature|challenge|csrf|xsrf|"
    r"otp|cipher|encrypt|decrypt|handshake|"
    r"key|iv|auth|sig|seed|mfa))"
    r"(?:_|s\b|$|(?=[A-Z])|[0-9])",
)


_PRIMARY_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def _user_facing_identifier(name: str) -> Optional[str]:
    """Extract the primary user-facing identifier from a function name,
    or None if the name is a compiler / runtime / std-internal symbol.

    Filtering rules (MSVC + Itanium-aware):
    - `__*` — C runtime / compiler intrinsics rejected.
    - `j_*` — jump-thunk prefix stripped.
    - `??*` — MSVC special-name mangling (ctors, dtors, operators).
      The primary name is a special token, not user-facing — reject.
    - `?_*` / `?$*` — MSVC std/template internals — reject.
    - `?Name@@*` — free function (no class scope). Primary = `Name`.
      Accept only if `Name` is a clean identifier.
    - `?Name@Class@@*` — class method. Primary = `Name`. Accept only
      if the class portion does NOT start with `?$` / `?_` (which
      would indicate a std-template / std-internal scope).

    The regex match against the primary identifier alone avoids
    spurious hits on noise embedded in mangled-type signatures
    (e.g. `?$basic_string` in a return type does not bleed into the
    name match for a user function returning `std::string`).
    """
    if not name:
        return None
    base = name[2:] if name.startswith("j_") else name
    if base.startswith("__"):
        return None
    if base.startswith("??"):
        return None
    if base.startswith("?_") or base.startswith("?$"):
        return None
    if base.startswith("?"):
        # MSVC mangling: primary identifier sits between the leading
        # `?` and the FIRST `@`. After the first `@`, either:
        #   - another `@` follows immediately (free function:
        #     `?Name@@signature`)
        #   - a class/namespace scope precedes `@@`
        #     (`?Name@Class@@signature`)
        # The earlier `find("@@")` form jumped over the class scope
        # and pulled `Name@Class` in as the primary, which then fails
        # the identifier regex. Use the first `@` consistently.
        first_at = base.find("@")
        if first_at <= 1:
            return None
        primary = base[1:first_at]
        rest = base[first_at + 1:]
        # If the class scope is std-internal / template-internal,
        # reject the whole symbol.
        if (rest and not rest.startswith("@")
                and (rest.startswith("?$") or rest.startswith("?_"))):
            return None
    else:
        primary = base
    if not _PRIMARY_NAME_RE.match(primary):
        return None
    return primary


def _security_named_context(function) -> Optional[str]:
    """Return a description of the security-named context for the
    function containing the PRNG call, or None if no such context.

    Two scopes considered:
    1. The function itself — name matches a security-class token.
    2. The function's callers — at least one caller's name matches.

    Returns a human-readable string identifying the matched scope and
    token (e.g., `function:issue_token~token`,
    `caller:UpdateSecret~secret`). Used both for emission gating and
    for evidence.
    """
    if function is None:
        return None
    src_func = getattr(function, "source_function", None) or function
    name = getattr(src_func, "name", "") or ""
    primary = _user_facing_identifier(name)
    if primary is None:
        # Not a user-facing function (compiler intrinsic, jump thunk,
        # std-internal). Do not credit caller-chain matches to it —
        # otherwise every std::basic_string thunk that issue_token
        # happens to call would inherit a "called from token-named
        # caller" context.
        return None
    m = _SEC_NAME_RE.search(primary)
    if m:
        return f"function:{name}~{m.group('tok').lower()}"
    try:
        callers = list(getattr(src_func, "callers", []))
    except Exception:
        callers = []
    for caller in callers:
        cname = getattr(caller, "name", "") or ""
        cprimary = _user_facing_identifier(cname)
        if not cprimary:
            continue
        cm = _SEC_NAME_RE.search(cprimary)
        if cm:
            return f"caller:{cname}~{cm.group('tok').lower()}"
    return None


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

LOW_ENTROPY_SEED_META = {
    "category": "low_entropy_prng_seed",
    "severity": Severity.HIGH,
    "cwe": ["CWE-338", "CWE-330", "CWE-336"],
    "mitre_attack": ["T1600"],
    "knowledge_refs": [
        "[[Memory/Knowledge/ue5_prng_handshake_secret_recovery]]",
    ],
}

IV_REUSE_META = {
    "category": "iv_reuse",
    "severity": Severity.HIGH,
    "cwe": ["CWE-329", "CWE-330", "CWE-323"],
    "mitre_attack": ["T1600"],
    "knowledge_refs": [
        "[[Memory/Knowledge/ue5_prng_handshake_secret_recovery]]",
    ],
}

# Cipher-init APIs and the parameter index of their IV. Used by
# `find_iv_reuse` to extract IV-parameter expressions and group call
# sites by IV identity (constant value or memory address). When the
# same identity appears at multiple init sites — or when the constant
# 0 is passed even once — IV reuse is the bug.
_CIPHER_INIT_IV_INDEX: dict[str, int] = {
    # OpenSSL EVP — `EVP_EncryptInit_ex(ctx, cipher, impl, key, iv)` etc.
    "EVP_EncryptInit_ex": 4,
    "EVP_EncryptInit": 3,
    "EVP_DecryptInit_ex": 4,
    "EVP_DecryptInit": 3,
    # Win32 CNG — `BCryptEncrypt(hKey, pbInput, cbInput, pPaddingInfo,
    # pbIV, cbIV, pbOutput, ...)` — IV is param 4.
    "BCryptEncrypt": 4,
    "BCryptDecrypt": 4,
    # libgcrypt — `gcry_cipher_setiv(hd, iv, ivlen)` — IV is param 1.
    "gcry_cipher_setiv": 1,
}


CSPRNG_LAUNDERED_TO_PRNG_META = {
    "category": "csprng_laundered_to_weak_prng",
    "severity": Severity.MEDIUM,
    "cwe": ["CWE-330", "CWE-338"],
    "mitre_attack": ["T1600"],
    "knowledge_refs": [
        "[[Memory/Knowledge/ue5_prng_handshake_secret_recovery]]",
    ],
}


# CSPRNG output sources — when one of these flows into srand/srandom
# argument, the seed is high-entropy but the resulting PRNG is still
# weak. The pattern is a code-review smell that suggests a developer
# tried to "fix" weak randomness by using a CSPRNG seed. Output
# of subsequent rand() calls is still predictable from a small
# sequence of observations; CSPRNG seeding doesn't help.
_CSPRNG_OUTPUT_FUNCTIONS: frozenset[str] = frozenset({
    "BCryptGenRandom", "CryptGenRandom",
    "RtlGenRandom", "SystemFunction036",
    "RAND_bytes", "RAND_priv_bytes",
    "getrandom", "arc4random", "arc4random_buf",
    "/dev/urandom",        # synthetic if literal-string match
})


# Low-entropy time-source imports — when these flow into srand/srandom
# (or the engine equivalents), the resulting PRNG state is recoverable
# given approximate boot/connect time. The canonical exploitation
# vector behind UE5 HandshakeSecret recovery.
_LOW_ENTROPY_TIME_SOURCES: frozenset[str] = frozenset({
    # POSIX
    "time", "gettimeofday", "clock", "clock_gettime", "times",
    # Win32
    "GetTickCount", "GetTickCount64",
    "QueryPerformanceCounter", "QueryUnbiasedInterruptTime",
    "GetSystemTimeAsFileTime", "GetSystemTime",
    "GetSystemTimePreciseAsFileTime",
    "RtlQueryPerformanceCounter",
    # CPU intrinsics — shipped as compiler-provided functions in
    # some toolchains (when imported by name)
    "__rdtsc", "_rdtsc",
})


# Seed-class imports — seeding APIs whose argument is the seed value
# we want to trace.
_PRNG_SEED_FUNCTIONS: frozenset[str] = frozenset({
    "srand", "srandom", "seed48", "lcong48", "srand48",
    # Engine-specific (when imported by name)
    "srand_r",
})


# ─────────────────────────────────────────────────────────────────
# Structural detector: PRNG output → crypto-sink flow
# ─────────────────────────────────────────────────────────────────


def _enumerate_prng_calls(bv) -> list[tuple[str, int, object]]:
    """Return [(prng_name, call_addr, mlil_inst), ...] for each call to
    a non-CSPRNG function present in the binary, INCLUDING synthetic
    PRNG sources discovered via LCG-constant pattern hits.

    Synthetic-source hookup (Plan C v2): functions that contain glibc
    rand-LCG / MSVC rand-LCG / Mersenne-Twister constants are
    inlined-PRNG implementations even when the binary doesn't import
    `rand()` directly. UE5's `FMath::Rand` wraps `rand()` inline; the
    LCG constants live in `.rdata`. Enumerating calls to those
    functions gives us PRNG sources without name resolution.
    """
    out: list[tuple[str, int, object]] = []
    imports = imports_in(bv)
    for prng_name in PRNG_FUNCTIONS:
        if prng_name not in imports:
            continue
        for addr, mlil in ilh.call_sites_of_import(bv, prng_name):
            if mlil is None:
                continue
            out.append((prng_name, addr, mlil))

    # Synthetic PRNG sources from LCG-constant pattern hits
    synthetic = _enumerate_synthetic_prng_call_sites(bv)
    out.extend(synthetic)
    return out


def _functions_containing_lcg_constants(bv) -> set[int]:
    """Run the LCG-constant heuristics and return the set of function
    start addresses that contain them.

    Re-runs the constant-pattern scan rather than caching to keep the
    analyzer stateless — the cost is bounded (constant-pattern scans
    are sub-second on typical binaries).
    """
    if bv is None:
        return set()
    function_addrs: set[int] = set()
    # Use the heuristics to find LCG / MT constants — the same machinery
    # that produces `lcg_constants` findings.
    findings = heur_crypto.match(bv, binary="", arch="", platform="",
                                 detector="analysis.crypto.synthetic")
    for f in findings:
        cat = getattr(f, "category", "")
        if cat in ("lcg_constants", "mt19937_use", "lcg_xor_cipher"):
            # Find the function containing this finding's address
            try:
                for func in bv.get_functions_containing(int(f.address)):
                    function_addrs.add(int(func.start))
            except Exception:
                continue
    return function_addrs


def _enumerate_synthetic_prng_call_sites(bv) -> list[tuple[str, int, object]]:
    """For each function identified as containing LCG / MT constants,
    enumerate its caller-side call sites. Each caller's call to the
    LCG-containing function becomes a synthetic PRNG source — the
    output SSA var is tainted as PRNG-derived, just like `rand()`.

    Returns [(synthetic_name, call_addr, mlil_inst), ...].
    """
    if bv is None:
        return []
    lcg_funcs = _functions_containing_lcg_constants(bv)
    if not lcg_funcs:
        return []
    out: list[tuple[str, int, object]] = []
    for func_addr in lcg_funcs:
        target_func = bv.get_function_at(func_addr)
        if target_func is None:
            continue
        target_name = ilh.function_display_name(target_func) or f"sub_{func_addr:x}"
        # Find callers of this function
        try:
            callers = list(target_func.callers)
        except Exception:
            callers = []
        for caller in callers:
            mlil = getattr(caller, "mlil", None)
            if mlil is None:
                continue
            ssa = getattr(mlil, "ssa_form", None) or mlil
            try:
                for inst in ssa.instructions:
                    op_name = type(inst).__name__
                    if "Call" not in op_name:
                        continue
                    cval = getattr(getattr(inst, "dest", None), "constant", None)
                    if cval is None or int(cval) != func_addr:
                        continue
                    out.append((f"synthetic_lcg:{target_name}",
                                int(getattr(inst, "address", 0)), inst))
            except Exception:
                continue
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
    """Emit `weak_prng_in_security_path` for non-CSPRNG output that
    reaches a security-relevant context. Two emission paths:

    Path A — PRNG output flows to a registered crypto-API call
    (BCrypt/EVP/HMAC/etc.). Direct dataflow, highest confidence.

    Path B — PRNG output is produced inside a function whose name
    (or whose caller's name) matches a security-class token (token,
    secret, key, nonce, ...). Catches the canonical UE5 shape where
    the PRNG output is buffered as a "secret" / "token" and never
    passes through an OS crypto API.
    """
    findings: list[Finding] = []
    seen_keys: set[tuple[str, int]] = set()
    meta = WEAK_PRNG_SECURITY_FLOW_META
    for prng_name, prng_addr, mlil in _enumerate_prng_calls(bv):
        output_var = ilh.call_output_ssa(mlil)
        if output_var is None:
            continue
        function = getattr(mlil, "function", None)
        func_name = ""
        if function is not None:
            sf = getattr(function, "source_function", None) or function
            func_name = getattr(sf, "name", "") or ""

        # Path A — PRNG → recognized crypto sink
        result = _flows_to_crypto_sink(bv, function, output_var)
        if result is not None:
            sink_name, sink_addr = result
            key = (prng_name, sink_addr)
            if key in seen_keys:
                continue
            seen_keys.add(key)
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
                    "match_path": "crypto_sink",
                },
            ))
            continue

        # Path B — PRNG inside a security-named context
        ctx = _security_named_context(function)
        if ctx is None:
            continue
        key = (prng_name, prng_addr)
        if key in seen_keys:
            continue
        seen_keys.add(key)
        findings.append(Finding(
            id="",
            category=meta["category"],
            severity=meta["severity"],
            address=prng_addr,
            function=func_name,
            binary=binary, arch=arch, platform=platform,
            detector=detector,
            knowledge_refs=list(meta["knowledge_refs"]),
            cwe=list(meta["cwe"]),
            mitre_attack=list(meta["mitre_attack"]),
            description=(
                f"non-CSPRNG ({prng_name}@0x{prng_addr:x}) used inside "
                f"security-named context [{ctx}]"
            ),
            evidence=[Evidence(
                kind="prng_in_security_named_context",
                source=detector,
                payload=f"{prng_name}@0x{prng_addr:x} ctx={ctx}",
                address=prng_addr,
                function=func_name,
            )],
            details={
                "prng_name": prng_name,
                "prng_addr": hex(prng_addr),
                "context": ctx,
                "match_path": "security_name",
            },
        ))

    # Path C — binary-scope heuristic. Inlined PRNG implementations
    # (std::mt19937 operator(), Boost.Random, custom LCG) hide the
    # call-graph link between the engine internals and the consuming
    # security-named function, so Path A/B (which need a Call edge)
    # miss them. Path C closes the gap with a coarser signal: if the
    # binary contains MT/LCG indicators AND has a security-named
    # function AND has no CSPRNG imports, emit at the security-named
    # function.
    #
    # FP gate: skip if any CSPRNG import is present (the developer
    # presumably uses it for security material). FP gate also avoids
    # emitting Path C for a function where Path A/B already emitted.
    imports = imports_in(bv)
    if not (imports & CSPRNG_FUNCTIONS):
        try:
            heur_findings = heur_crypto.match(
                bv, binary=binary, arch=arch, platform=platform,
                detector=f"{detector}.heuristic",
            )
        except Exception:
            heur_findings = []
        weak_indicator_cats = {"mt19937_use", "lcg_constants", "lcg_xor_cipher"}
        has_weak_indicator = any(
            getattr(f, "category", "") in weak_indicator_cats
            for f in heur_findings
        )
        if has_weak_indicator:
            already_emitted_primaries: set[str] = set()
            for f in findings:
                if getattr(f, "category", "") != meta["category"]:
                    continue
                p = _user_facing_identifier(getattr(f, "function", "") or "")
                if p:
                    already_emitted_primaries.add(p.lower())
            try:
                func_iter = sorted(
                    bv.functions,
                    key=lambda f: (getattr(f, "name", "") or "").startswith("j_"),
                )
            except Exception:
                func_iter = []
            for func in func_iter:
                fname = getattr(func, "name", "") or ""
                primary = _user_facing_identifier(fname)
                if not primary:
                    continue
                m = _SEC_NAME_RE.search(primary)
                if not m:
                    continue
                if primary.lower() in already_emitted_primaries:
                    continue
                already_emitted_primaries.add(primary.lower())
                ctx = f"function:{fname}~{m.group('tok').lower()}"
                func_start = int(getattr(func, "start", 0))
                key = ("path_c_name", func_start)
                if key in seen_keys:
                    continue
                seen_keys.add(key)
                findings.append(Finding(
                    id="",
                    category=meta["category"],
                    severity=meta["severity"],
                    address=func_start,
                    function=fname,
                    binary=binary, arch=arch, platform=platform,
                    detector=detector,
                    knowledge_refs=list(meta["knowledge_refs"]),
                    cwe=list(meta["cwe"]),
                    mitre_attack=list(meta["mitre_attack"]),
                    description=(
                        f"binary contains weak-PRNG indicators (mt19937/lcg) "
                        f"and lacks CSPRNG imports; security-named function "
                        f"'{fname}' [{ctx}] is the likely consumer of "
                        f"non-cryptographic randomness in security material"
                    ),
                    evidence=[Evidence(
                        kind="weak_prng_indicator_with_security_named_function",
                        source=detector,
                        payload=f"context={ctx} csprng_absent=True",
                        address=func_start,
                        function=fname,
                    )],
                    details={
                        "context": ctx,
                        "match_path": "binary_scope_indicator",
                        "csprng_absent": True,
                    },
                ))
    return findings


# ─────────────────────────────────────────────────────────────────
# IV reuse detection
# ─────────────────────────────────────────────────────────────────


def _extract_iv_identity(expr) -> Optional[tuple[str, int]]:
    """Return a hashable identity for an IV parameter expression.

    - `("const", value)` — the IV parameter is a constant integer
      (the `0` constant for a zero IV is the canonical case).
    - `("addr", addr)` — the IV parameter is a constant pointer to
      a fixed data-segment address (an IV buffer in `.rdata` or
      `.data`). Recognised both via direct `MediumLevelILConstPtr`
      operations AND via `MediumLevelILVarSsa` whose tracked
      `PossibleValueSet` resolves to a `ConstantPointerValue`.
      Stack-frame-relative variables are intentionally NOT dedup'd
      (they're per-call locals, exactly the safe pattern for
      per-encryption fresh IVs).
    - `None` — the parameter's source can't be statically resolved
      to a single identity (computed expression, undetermined value,
      function return). Don't dedup these — too noisy.
    """
    if expr is None:
        return None
    cval = getattr(expr, "constant", None)
    if cval is not None:
        try:
            return ("const", int(cval))
        except Exception:
            return None
    op_name = type(expr).__name__
    if "ConstantPtr" in op_name or "ConstPtr" in op_name:
        v = getattr(expr, "value", None) or getattr(expr, "constant", None)
        try:
            return ("addr", int(v))
        except Exception:
            return None
    if "Load" in op_name:
        src = getattr(expr, "src", None)
        cv = getattr(src, "constant", None) if src is not None else None
        if cv is not None:
            try:
                return ("addr", int(cv))
            except Exception:
                pass
    # Variable whose tracked value resolves to a constant pointer.
    # Binja's PossibleValueSet exposes `.type` (RegisterValueType) and
    # `.value` (the int when the type is ConstantValue or
    # ConstantPointerValue). StackFrameOffset / Undetermined / Imported
    # produce no static identity.
    val = getattr(expr, "value", None)
    if val is not None:
        vtype = getattr(val, "type", None)
        type_name = (getattr(vtype, "name", "") or str(vtype) or "").lower()
        if "constantpointer" in type_name or "constant_pointer" in type_name:
            v = getattr(val, "value", None)
            if v is not None:
                try:
                    return ("addr", int(v))
                except Exception:
                    return None
        if type_name == "constantvalue" or type_name == "constant_value":
            v = getattr(val, "value", None)
            if v is not None:
                try:
                    return ("const", int(v))
                except Exception:
                    return None
    return None


def find_iv_reuse(bv, *, binary: str, arch: str, platform: str,
                  detector: str) -> list[Finding]:
    """Emit `iv_reuse` when a cipher-init call passes the same IV
    identity (constant value or buffer address) at 2+ call sites, OR
    passes a constant zero IV at any single site.
    """
    findings: list[Finding] = []
    if bv is None:
        return findings
    imports = imports_in(bv)
    init_apis = [a for a in _CIPHER_INIT_IV_INDEX if a in imports]
    if not init_apis:
        return findings

    by_identity: dict[tuple, list[tuple[str, int, str]]] = {}
    for api in init_apis:
        iv_idx = _CIPHER_INIT_IV_INDEX[api]
        for addr, mlil in ilh.call_sites_of_import(bv, api):
            if mlil is None:
                continue
            params = ilh.call_params(mlil)
            if len(params) <= iv_idx:
                continue
            ident = _extract_iv_identity(params[iv_idx])
            if ident is None:
                continue
            func = getattr(mlil, "function", None)
            sf = getattr(func, "source_function", None) or func
            fname = getattr(sf, "name", "") or ""
            by_identity.setdefault(ident, []).append((api, addr, fname))

    meta = IV_REUSE_META
    for ident, sites in by_identity.items():
        kind, val = ident
        is_zero = (kind == "const" and val == 0)
        if len(sites) < 2 and not is_zero:
            continue
        first_api, first_addr, first_fn = sites[0]
        ident_repr = (f"const=0x{val:x}" if kind == "const"
                      else f"addr=0x{val:x}")
        if is_zero and len(sites) < 2:
            description = (
                f"{first_api}@0x{first_addr:x} passes constant zero IV — "
                "any encryption with a zero IV under a fixed key produces "
                "deterministic ciphertext (catastrophic for CTR/GCM/CBC)"
            )
        else:
            description = (
                f"{len(sites)} cipher-init call(s) reuse the same IV "
                f"identity ({ident_repr}); "
                f"first: {first_api}@0x{first_addr:x}"
            )
        evidence = [Evidence(
            kind="iv_identity_shared_across_init_calls",
            source=detector,
            payload=(f"identity={ident_repr} sites="
                     + ", ".join(f"{a}@0x{ad:x}" for a, ad, _ in sites[:8])),
            address=first_addr,
            function=first_fn,
        )]
        findings.append(Finding(
            id="",
            category=meta["category"],
            severity=meta["severity"],
            address=first_addr,
            function=first_fn,
            binary=binary, arch=arch, platform=platform,
            detector=detector,
            knowledge_refs=list(meta["knowledge_refs"]),
            cwe=list(meta["cwe"]),
            mitre_attack=list(meta["mitre_attack"]),
            description=description,
            evidence=evidence,
            details={
                "iv_identity": ident_repr,
                "site_count": len(sites),
                "sites": [(a, hex(ad), fn) for a, ad, fn in sites[:8]],
                "zero_iv": is_zero,
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
# Low-entropy PRNG seed detection (Plan C — Run 16)
# ─────────────────────────────────────────────────────────────────


def _ssa_def_traces_to_time_source(bv, function, ssa_var,
                                   *, max_hops: int = 5) -> Optional[str]:
    """Walk SSA defs from `ssa_var` looking for a Call whose target
    is in `_LOW_ENTROPY_TIME_SOURCES`. Returns the time-source name
    if found, else None.

    The chase passes through SetVar (alias copies), CastInt (the
    `(unsigned)time(NULL)` shape), and Call-output unwrap.
    """
    if function is None or ssa_var is None:
        return None
    seen: set = set()
    cur = ssa_var
    for _ in range(max_hops):
        key = str(cur)
        if key in seen:
            return None
        seen.add(key)
        defn = ilh.ssa_def_of(function, cur)
        if defn is None:
            return None
        # Is the def site itself a Call to a time source?
        op_name = type(defn).__name__
        if "Call" in op_name:
            cval = getattr(getattr(defn, "dest", None), "constant", None)
            if cval is not None and bv is not None:
                sym = bv.get_symbol_at(int(cval))
                if sym is not None:
                    name = (getattr(sym, "short_name", None)
                            or getattr(sym, "name", ""))
                    if name in _LOW_ENTROPY_TIME_SOURCES:
                        return name
            return None
        src_expr = getattr(defn, "src", None)
        if src_expr is None:
            return None
        # Check if src expression IS a Call (some MLIL forms wrap calls
        # inside SetVarSsa.src)
        src_op = type(src_expr).__name__
        if "Call" in src_op:
            cval = getattr(getattr(src_expr, "dest", None), "constant", None)
            if cval is not None and bv is not None:
                sym = bv.get_symbol_at(int(cval))
                if sym is not None:
                    name = (getattr(sym, "short_name", None)
                            or getattr(sym, "name", ""))
                    if name in _LOW_ENTROPY_TIME_SOURCES:
                        return name
            return None
        # Chase through SetVar / cast / arithmetic
        nested = ilh.expr_to_ssa_var(src_expr)
        if nested is None:
            # Recurse into operands once for cast / arithmetic
            for op in getattr(src_expr, "operands", []) or []:
                if hasattr(op, "var") and hasattr(op, "version"):
                    cur = op
                    nested = op
                    break
                nested_inner = ilh.expr_to_ssa_var(op)
                if nested_inner is not None:
                    cur = nested_inner
                    nested = nested_inner
                    break
            if nested is None:
                return None
            continue
        cur = nested
    return None


def _ssa_def_traces_to_csprng_source(bv, function, ssa_var,
                                     *, max_hops: int = 5) -> Optional[str]:
    """Walk SSA defs from `ssa_var` looking for a Call whose target
    is in `_CSPRNG_OUTPUT_FUNCTIONS`. Returns the source name if
    found, else None.

    Same shape as `_ssa_def_traces_to_time_source` but for the
    CSPRNG side — used to detect the daydream-flagged
    "BCryptGenRandom → srand → rand → key" laundering pattern.
    """
    if function is None or ssa_var is None:
        return None
    seen: set = set()
    cur = ssa_var
    for _ in range(max_hops):
        key = str(cur)
        if key in seen:
            return None
        seen.add(key)
        defn = ilh.ssa_def_of(function, cur)
        if defn is None:
            return None
        op_name = type(defn).__name__
        if "Call" in op_name:
            cval = getattr(getattr(defn, "dest", None), "constant", None)
            if cval is not None and bv is not None:
                sym = bv.get_symbol_at(int(cval))
                if sym is not None:
                    name = (getattr(sym, "short_name", None)
                            or getattr(sym, "name", ""))
                    if name in _CSPRNG_OUTPUT_FUNCTIONS:
                        return name
            return None
        src_expr = getattr(defn, "src", None)
        if src_expr is None:
            return None
        # Embedded Call?
        if "Call" in type(src_expr).__name__:
            cval = getattr(getattr(src_expr, "dest", None), "constant", None)
            if cval is not None and bv is not None:
                sym = bv.get_symbol_at(int(cval))
                if sym is not None:
                    name = (getattr(sym, "short_name", None)
                            or getattr(sym, "name", ""))
                    if name in _CSPRNG_OUTPUT_FUNCTIONS:
                        return name
            return None
        nested = ilh.expr_to_ssa_var(src_expr)
        if nested is None:
            for op in getattr(src_expr, "operands", []) or []:
                nested_inner = ilh.expr_to_ssa_var(op)
                if nested_inner is not None:
                    nested = nested_inner
                    break
            if nested is None:
                return None
        cur = nested
    return None


def find_csprng_laundered_to_prng(bv, *, binary: str, arch: str, platform: str,
                                  detector: str) -> list[Finding]:
    """Detect `BCryptGenRandom(...) → srand(that) → rand() → key`-class
    laundering: a CSPRNG output is used to seed a weak PRNG. The
    seed is high-entropy but the resulting PRNG output is still
    predictable from a few observations.

    Daydream-flagged pattern — without explicit detection a tag-based
    entropy classifier would clear the chain because the seed came
    from a CSPRNG.
    """
    findings: list[Finding] = []
    if bv is None:
        return findings
    imports = imports_in(bv)
    seed_present = imports & _PRNG_SEED_FUNCTIONS
    if not seed_present:
        return findings

    for seed_name in seed_present:
        for addr, mlil in ilh.call_sites_of_import(bv, seed_name):
            if mlil is None:
                continue
            params = ilh.call_params(mlil)
            if not params:
                continue
            seed_arg = ilh.expr_to_ssa_var(params[0])
            if seed_arg is None:
                continue
            function = getattr(mlil, "function", None)
            csprng_src = _ssa_def_traces_to_csprng_source(bv, function, seed_arg)
            if csprng_src is None:
                continue
            func_name = ilh.function_display_name(function)
            meta = CSPRNG_LAUNDERED_TO_PRNG_META
            finding = Finding(
                id="",
                category=meta["category"],
                severity=meta["severity"],
                address=addr,
                function=func_name,
                binary=binary, arch=arch, platform=platform,
                detector=detector,
                knowledge_refs=list(meta["knowledge_refs"]),
                cwe=list(meta["cwe"]),
                mitre_attack=list(meta["mitre_attack"]),
                description=(
                    f"{seed_name}@0x{addr:x} seeded from {csprng_src}() — "
                    f"the seed is high-entropy but the resulting weak-PRNG "
                    f"output is still predictable from a few observations. "
                    f"Use the CSPRNG output directly as keying material; "
                    f"do not pass it through {seed_name.replace('s','')}-family."
                ),
                evidence=[Evidence(
                    kind="csprng_to_weak_prng_seed",
                    source=detector,
                    payload=f"{seed_name}@0x{addr:x} <- {csprng_src}",
                    address=addr,
                    function=func_name,
                )],
                details={
                    "seed_name": seed_name,
                    "csprng_source": csprng_src,
                },
            )
            from ..lib.scoring import apply_signals_to_finding
            apply_signals_to_finding(finding, [
                "csprng_laundered_through_weak_prng",   # SPECIFIC
            ])
            findings.append(finding)
    return findings


def find_low_entropy_seeds(bv, *, binary: str, arch: str, platform: str,
                           detector: str) -> list[Finding]:
    """Detect `srand(time(NULL))`-class low-entropy seed patterns.

    Walks call sites of seed-class imports (`srand`, `srandom`, etc.).
    For each, traces the seed argument's SSA-def chain backwards
    looking for a call to a low-entropy time source. Emit a Finding
    when the chain matches.
    """
    findings: list[Finding] = []
    if bv is None:
        return findings
    imports = imports_in(bv)
    seed_present = imports & _PRNG_SEED_FUNCTIONS
    if not seed_present:
        return findings

    for seed_name in seed_present:
        for addr, mlil in ilh.call_sites_of_import(bv, seed_name):
            if mlil is None:
                continue
            params = ilh.call_params(mlil)
            if not params:
                continue
            seed_arg = ilh.expr_to_ssa_var(params[0])
            if seed_arg is None:
                continue
            function = getattr(mlil, "function", None)
            time_src = _ssa_def_traces_to_time_source(bv, function, seed_arg)
            if time_src is None:
                continue
            func_name = ilh.function_display_name(function)
            meta = LOW_ENTROPY_SEED_META
            finding = Finding(
                id="",
                category=meta["category"],
                severity=meta["severity"],
                address=addr,
                function=func_name,
                binary=binary, arch=arch, platform=platform,
                detector=detector,
                knowledge_refs=list(meta["knowledge_refs"]),
                cwe=list(meta["cwe"]),
                mitre_attack=list(meta["mitre_attack"]),
                description=(
                    f"{seed_name}@0x{addr:x} seeded from {time_src}() output — "
                    f"the resulting PRNG state is recoverable given approximate "
                    f"boot or connect time. Any security-relevant output "
                    f"derived from subsequent {seed_name.replace('s','')}-family "
                    f"calls is predictable."
                ),
                evidence=[Evidence(
                    kind="low_entropy_seed",
                    source=detector,
                    payload=f"{seed_name}@0x{addr:x} <- {time_src}",
                    address=addr,
                    function=func_name,
                )],
                details={
                    "seed_name": seed_name,
                    "time_source": time_src,
                },
            )
            from ..lib.scoring import apply_signals_to_finding
            apply_signals_to_finding(finding, [
                "low_entropy_seed_to_prng",       # SPECIFIC
            ])
            findings.append(finding)

    return findings


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
    # 4. Low-entropy seed (Plan C / Run 17).
    findings.extend(find_low_entropy_seeds(
        bv, binary=binary, arch=arch, platform=platform, detector=detector,
    ))
    # 5. CSPRNG-to-weak-PRNG laundering (Plan C v2 / Run 19).
    findings.extend(find_csprng_laundered_to_prng(
        bv, binary=binary, arch=arch, platform=platform, detector=detector,
    ))
    # 6. IV reuse — same identity in 2+ cipher-init calls, or a
    # constant-zero IV in any single call.
    findings.extend(find_iv_reuse(
        bv, binary=binary, arch=arch, platform=platform, detector=detector,
    ))

    if score_against_mitigations and findings and binary:
        try:
            profile = mitigations_mod.extract_mitigations(binary, bv=bv)
            mitigations_mod.score_findings(findings, profile)
        except Exception:
            pass

    return findings
