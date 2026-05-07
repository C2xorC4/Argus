"""Crypto / security-primitive heuristics.

Pattern data for `analysis/crypto.py`. Covers:

- Non-cryptographic PRNG imports (analysis/crypto.py escalates to
  Finding only when output flows to a security-tagged sink).
- CSPRNG imports — informational, used to confirm a safe path.
- LCG / Mersenne-Twister / cipher constants — well-known bad ones.
- Crypto-primitive S-box / round-constant signatures — for in-binary
  crypto identification.
- Hardcoded weak / test keys + zero IVs.

Knowledge anchors:
- `[[Memory/Knowledge/ue5_prng_handshake_secret_recovery]]` — the
  canonical weak-PRNG-in-security-path real-world finding.
- `[[Memory/Knowledge/gameguard_research_22_findings]]` — LCG-XOR
  string cipher in production anti-cheat.
"""

from __future__ import annotations

from ._base import (
    ConstantPattern, ImportPattern, Pattern, StringPattern, StructuralPattern,
    emit_finding, find_constant, function_at, imports_in, strings_in,
)
from ..output.finding import Severity


# ─────────────────────────────────────────────────────────────────
# PRNG imports — non-CSPRNG flagged (info), CSPRNG informational
# ─────────────────────────────────────────────────────────────────


NON_CSPRNG_IMPORTS = ImportPattern(
    name="crypto.non_csprng_imports",
    description="Non-cryptographic PRNG import — investigate sinks via analysis/crypto.py",
    severity=Severity.INFO,
    category="non_csprng_use",
    cwe=["CWE-338", "CWE-330"],
    mitre_attack=["T1600"],
    knowledge_refs=["[[Memory/Knowledge/ue5_prng_handshake_secret_recovery]]"],
    import_names=[
        "rand", "srand", "random", "srandom",
        "drand48", "lrand48", "mrand48", "nrand48", "jrand48",
        "rand_r", "rand_s",
    ],
    all_required=False,
)

CSPRNG_IMPORTS = ImportPattern(
    name="crypto.csprng_imports",
    description="CSPRNG import — informational; confirms the safe-path is reachable",
    severity=Severity.INFO,
    category="csprng_use",
    knowledge_refs=["[[Memory/Knowledge/ue5_prng_handshake_secret_recovery]]"],
    import_names=[
        "BCryptGenRandom", "CryptGenRandom",
        "RtlGenRandom", "SystemFunction036",
        "getrandom", "arc4random", "arc4random_buf",
        "RAND_bytes", "RAND_priv_bytes",        # OpenSSL
    ],
    all_required=False,
)


# ─────────────────────────────────────────────────────────────────
# LCG constants — flagged as combo (require_all on the canonical pair)
# ─────────────────────────────────────────────────────────────────


GLIBC_RAND_LCG = ConstantPattern(
    name="crypto.glibc_rand_lcg",
    description="glibc rand() LCG constants 1103515245 + 12345 — custom RNG or LCG-XOR string cipher",
    severity=Severity.MEDIUM,
    category="lcg_constants",
    cwe=["CWE-338"],
    mitre_attack=["T1027"],
    knowledge_refs=[
        "[[Memory/Knowledge/gameguard_research_22_findings]]",
        "[[Memory/Knowledge/ue5_prng_handshake_secret_recovery]]",
    ],
    constants=[1103515245, 12345],
    bit_widths=[32],
)

MSVC_RAND_LCG = ConstantPattern(
    name="crypto.msvc_rand_lcg",
    description="MSVC rand() LCG constants 214013 + 2531011",
    severity=Severity.MEDIUM,
    category="lcg_constants",
    cwe=["CWE-338"],
    mitre_attack=["T1027"],
    knowledge_refs=["[[Memory/Knowledge/gameguard_research_22_findings]]"],
    constants=[214013, 2531011],
    bit_widths=[32],
)

MT19937_INIT = ConstantPattern(
    name="crypto.mt19937_constants",
    description="Mersenne Twister magic (matrix coefficient + tempering masks)",
    severity=Severity.LOW,
    category="mt19937_use",
    cwe=["CWE-338"],
    knowledge_refs=["[[Memory/Knowledge/ue5_prng_handshake_secret_recovery]]"],
    constants=[0x9908B0DF, 0x9D2C5680, 0xEFC60000, 0x6C078965],
    bit_widths=[32],
)


# ─────────────────────────────────────────────────────────────────
# Crypto-primitive markers
# ─────────────────────────────────────────────────────────────────


AES_SBOX_MARKER = ConstantPattern(
    name="crypto.aes_sbox_marker",
    description="First 4 bytes of AES S-box (0x63 0x7c 0x77 0x7b) — AES implementation present",
    severity=Severity.INFO,
    category="aes_implementation_marker",
    knowledge_refs=[],
    constants=[0x7B777C63],
    bit_widths=[32],
    notes="Not a vulnerability; presence indicates an in-binary AES.",
)

SHA256_INIT_MARKER = ConstantPattern(
    name="crypto.sha256_init_marker",
    description="SHA-256 initial hash value 0x6A09E667 — SHA-256 implementation present",
    severity=Severity.INFO,
    category="sha256_implementation_marker",
    knowledge_refs=[],
    constants=[0x6A09E667],
    bit_widths=[32],
)

MD5_INIT_MARKER = ConstantPattern(
    name="crypto.md5_init_marker",
    description="MD5 init constant 0x67452301 — MD5 implementation present (MD5 is broken; flag in security paths)",
    severity=Severity.LOW,
    category="md5_implementation_marker",
    cwe=["CWE-327", "CWE-328"],
    knowledge_refs=[],
    constants=[0x67452301],
    bit_widths=[32],
)

# Salsa20 / ChaCha20 sigma constant — "expand 32-byte k". The 32-bit
# little-endian encoding of "expa" is 0x61707865; the canonical
# initial state of the Salsa20/ChaCha20 stream cipher. Presence
# indicates a custom or vendored stream-cipher implementation,
# common in obfuscation and DRM tooling.
SALSA_CHACHA_SIGMA = ConstantPattern(
    name="crypto.salsa_chacha_sigma",
    description="Salsa20 / ChaCha20 sigma constant 0x61707865 (\"expa\") — stream-cipher implementation present",
    severity=Severity.INFO,
    category="stream_cipher_marker",
    cwe=[],
    mitre_attack=["T1027"],
    knowledge_refs=[],
    constants=[0x61707865],
    bit_widths=[32],
    notes="Not a vulnerability per se — flags a custom stream-cipher impl, "
          "useful for downstream weak-PRNG-in-security-path escalation.",
)

# RC4 KSA / PRGA structural-marker constant — the byte 0xAA appears as
# the conventional padding-test value during RC4 self-checks; not a
# strong indicator. Stronger: 256-byte permutation array filled at
# function entry. Approximate via the 0x100 / 256 constant inside a
# function whose body has heavy XOR + table-index swap activity. The
# flow detector in `analysis/crypto.py` correlates this pattern with
# its callers — for a binary-scope marker we only assert the
# constant's presence as a low-confidence signal.
RC4_TABLE_SIZE_MARKER = ConstantPattern(
    name="crypto.rc4_table_size_marker",
    description="RC4 256-byte permutation table size constant — possible RC4 KSA",
    severity=Severity.INFO,
    category="rc4_table_marker",
    cwe=[],
    knowledge_refs=[],
    constants=[256],
    bit_widths=[32],
    notes="Very low specificity; only meaningful when correlated with "
          "byte-array-loop patterns in the same function. Currently emitted "
          "as a hint; analysis/crypto.py should suppress unless the "
          "containing function also matches XOR-loop heuristics.",
)


# ─────────────────────────────────────────────────────────────────
# Hardcoded weak material
# ─────────────────────────────────────────────────────────────────


DES_WEAK_KEY_STRINGS = StringPattern(
    name="crypto.des_weak_keys",
    description="Hardcoded DES weak / semi-weak key bytes",
    severity=Severity.HIGH,
    category="hardcoded_weak_key",
    cwe=["CWE-321"],
    knowledge_refs=[],
    string_literals=[
        # Canonical DES weak / semi-weak keys (alternating bit patterns).
        # `"0123456789abcdef"` was previously here as a "canonical test
        # key" but it's overwhelmingly the hex-encoding alphabet
        # (`out[i] = "0123456789abcdef"[byte & 0xF];`), so it produces
        # a near-100% FP rate against any binary that prints hex.
        "0101010101010101", "FEFEFEFEFEFEFEFE",
        "1F1F1F1F0E0E0E0E", "E0E0E0E0F1F1F1F1",
    ],
)

ZERO_IV_STRING = StringPattern(
    name="crypto.zero_iv_marker",
    description="Hardcoded zero IV — IV reuse hazard candidate",
    severity=Severity.MEDIUM,
    category="iv_reuse_candidate",
    cwe=["CWE-329", "CWE-330"],
    knowledge_refs=[],
    string_literals=["00000000000000000000000000000000"],
    notes="Very high false-positive rate as a plain string. analysis/crypto.py confirms by tracing the IV argument of an EVP_*Init / BCryptEncrypt call.",
)


# ─────────────────────────────────────────────────────────────────
# Structural — analysis/crypto.py owns the recogniser
# ─────────────────────────────────────────────────────────────────


PRNG_TO_SECURITY_SINK = StructuralPattern(
    name="crypto.prng_to_security_sink",
    description="rand()/random() output flows to a variable named token/secret/key/nonce/iv/session/cookie/csrf/salt",
    severity=Severity.HIGH,
    category="weak_prng_in_security_path",
    cwe=["CWE-338"],
    knowledge_refs=["[[Memory/Knowledge/ue5_prng_handshake_secret_recovery]]"],
    shape={"kind": "ssa_taint_flow",
           "source": "non_csprng",
           "sink_name_pattern": r"(?i)(token|secret|key|nonce|iv|session|cookie|csrf|salt|hmac)"},
)


# ─────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────


PATTERNS: list[Pattern] = [
    NON_CSPRNG_IMPORTS, CSPRNG_IMPORTS,
    GLIBC_RAND_LCG, MSVC_RAND_LCG, MT19937_INIT,
    AES_SBOX_MARKER, SHA256_INIT_MARKER, MD5_INIT_MARKER,
    SALSA_CHACHA_SIGMA,
    DES_WEAK_KEY_STRINGS, ZERO_IV_STRING,
    PRNG_TO_SECURITY_SINK,
]


def match(bv, *, binary: str, arch: str, platform: str,
          detector: str = "heuristics.crypto") -> list:
    findings = []
    imports = imports_in(bv)

    # Imports
    for pat in (NON_CSPRNG_IMPORTS, CSPRNG_IMPORTS):
        hits = [n for n in pat.import_names if n in imports]
        if not hits:
            continue
        findings.append(emit_finding(
            pat,
            address=0, function="<binary>",
            binary=binary, arch=arch, platform=platform,
            detector=detector,
            description_extra=f"imports: {', '.join(hits)}",
            details={"matched_imports": hits},
        ))

    # Constants — combos require all listed values present
    for pat in (GLIBC_RAND_LCG, MSVC_RAND_LCG, MT19937_INIT,
                AES_SBOX_MARKER, SHA256_INIT_MARKER, MD5_INIT_MARKER,
                SALSA_CHACHA_SIGMA):
        all_hits: list[tuple[int, int]] = []
        for c in pat.constants:
            for w in pat.bit_widths:
                hits = find_constant(bv, c, w)
                for addr in hits:
                    all_hits.append((c, addr))
        if not all_hits:
            continue
        # For LCG combos we want both constants present.
        if pat in (GLIBC_RAND_LCG, MSVC_RAND_LCG):
            present = {c for c, _ in all_hits}
            if not all(c in present for c in pat.constants):
                continue
        first_addr = all_hits[0][1]
        func = function_at(bv, first_addr)
        findings.append(emit_finding(
            pat,
            address=first_addr,
            function=getattr(func, "name", "") if func else "",
            binary=binary, arch=arch, platform=platform,
            detector=detector,
            description_extra=f"constants: {', '.join(hex(c) for c, _ in all_hits[:8])}",
            details={"constant_hits": [(hex(c), hex(a)) for c, a in all_hits[:32]]},
        ))

    # Strings
    string_table = strings_in(bv)
    for pat in (DES_WEAK_KEY_STRINGS, ZERO_IV_STRING):
        hits = [(s, a) for s, a in string_table
                if any(needle in s for needle in pat.string_literals)]
        if not hits:
            continue
        first_addr = hits[0][1]
        findings.append(emit_finding(
            pat,
            address=first_addr, function="<binary>",
            binary=binary, arch=arch, platform=platform,
            detector=detector,
            description_extra=f"strings: {len(hits)} hits",
            details={"matched_strings": [s for s, _ in hits[:16]]},
        ))

    return findings
