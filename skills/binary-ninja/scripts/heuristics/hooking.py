"""Hooking heuristics — D3D / IAT / VFT hooking patterns.

Game-hacking lineage. The patterns here detect both *the hooks
themselves* (from the cheat side) and *anti-hooking* (from the
target side that tries to prevent them).

Knowledge anchors:
- `[[Memory/Knowledge/gh_hooking_techniques_d3d_iat_vft]]` — full
  taxonomy from *Game Hacking*: D3D EndScene/Present, IAT entry
  rewrite, VFT slot replacement, inline hooks.
- `[[Memory/Knowledge/gh_anti_cheat_evasion]]` — overlap with
  evasion.py.
- `[[Memory/Knowledge/em_hook_evasion_three_approaches]]` — the
  defender's three approaches; this module catalogs the *attacker*
  hooks those approaches counter.
"""

from __future__ import annotations

from ._base import (
    ImportPattern, Pattern, StringPattern, StructuralPattern,
    emit_finding, imports_in, strings_in,
)
from ..output.finding import Severity


# ─────────────────────────────────────────────────────────────────
# Inline hook + trampoline imports
# ─────────────────────────────────────────────────────────────────


VIRTUAL_PROTECT = ImportPattern(
    name="hooking.virtual_protect",
    description="VirtualProtect — typical IAT/inline-hook setup (RWX page transition)",
    severity=Severity.LOW,
    category="virtual_protect_use",
    mitre_attack=["T1574"],
    knowledge_refs=["[[Memory/Knowledge/gh_hooking_techniques_d3d_iat_vft]]"],
    import_names=["VirtualProtect", "VirtualProtectEx",
                  "NtProtectVirtualMemory", "ZwProtectVirtualMemory"],
    all_required=False,
    notes="Many legitimate uses; downstream analysis classifies via taint flow into the page-permission target.",
)


# ─────────────────────────────────────────────────────────────────
# D3D / DirectX hooks — game-hack canonical
# ─────────────────────────────────────────────────────────────────


D3D_INTERFACE_STRINGS = StringPattern(
    name="hooking.d3d_interface_strings",
    description="DirectX interface name strings — D3D EndScene / Present hook candidate",
    severity=Severity.MEDIUM,
    category="d3d_hook_indicator",
    mitre_attack=["T1574"],
    knowledge_refs=["[[Memory/Knowledge/gh_hooking_techniques_d3d_iat_vft]]"],
    string_literals=[
        "IDirect3DDevice9", "IDirect3DDevice11", "ID3D11Device",
        "ID3D11DeviceContext",
        "IDXGISwapChain", "IDXGIFactory",
        "EndScene", "Present",
        "d3d9.dll", "d3d11.dll", "dxgi.dll",
    ],
    case_sensitive=False,
    notes="Combination of `IDXGISwapChain` + `Present` + `VirtualProtect` is high-confidence D3D hook.",
)

OPENGL_HOOK_STRINGS = StringPattern(
    name="hooking.opengl_hook_strings",
    description="OpenGL function-name strings — wglGetProcAddress / glCreateContext hook candidate",
    severity=Severity.LOW,
    category="opengl_hook_indicator",
    mitre_attack=["T1574"],
    knowledge_refs=["[[Memory/Knowledge/gh_hooking_techniques_d3d_iat_vft]]"],
    string_literals=[
        "wglGetProcAddress", "wglMakeCurrent", "wglCreateContext",
        "glCreateContext", "glSwapBuffers",
        "opengl32.dll",
    ],
    case_sensitive=False,
)


# ─────────────────────────────────────────────────────────────────
# IAT-rewrite + VFT-hijack — structural patterns
# ─────────────────────────────────────────────────────────────────


IAT_HOOK_PATTERN = StructuralPattern(
    name="hooking.iat_hook",
    description="Writes to IAT slot of a target module (function pointer replacement)",
    severity=Severity.HIGH,
    category="iat_hook",
    mitre_attack=["T1574"],
    knowledge_refs=["[[Memory/Knowledge/gh_hooking_techniques_d3d_iat_vft]]"],
    shape={"kind": "iat_slot_write"},
)

VFT_HIJACK_PATTERN = StructuralPattern(
    name="hooking.vft_hijack",
    description="Writes to a virtual-function-table slot of a known interface (D3D / runtime)",
    severity=Severity.HIGH,
    category="vft_hijack",
    mitre_attack=["T1574"],
    knowledge_refs=["[[Memory/Knowledge/gh_hooking_techniques_d3d_iat_vft]]"],
    shape={"kind": "vft_slot_write", "min_offset": 0x18},   # past vtable[0..2]
)

INLINE_HOOK_PATTERN = StructuralPattern(
    name="hooking.inline_hook",
    description="Writes a 5-byte (x86) or 14-byte (x64) detour at the prologue of a target function",
    severity=Severity.HIGH,
    category="inline_hook",
    mitre_attack=["T1574"],
    knowledge_refs=["[[Memory/Knowledge/gh_hooking_techniques_d3d_iat_vft]]"],
    shape={"kind": "function_prologue_jmp_write"},
)


# ─────────────────────────────────────────────────────────────────
# Detour libraries — common helpers
# ─────────────────────────────────────────────────────────────────


DETOUR_LIB_STRINGS = StringPattern(
    name="hooking.detour_libraries",
    description="MS Detours / MinHook / Frida API strings — hook framework engagement",
    severity=Severity.MEDIUM,
    category="detour_library_engagement",
    mitre_attack=["T1574"],
    knowledge_refs=["[[Memory/Knowledge/gh_hooking_techniques_d3d_iat_vft]]"],
    string_literals=[
        "DetourTransactionBegin", "DetourAttach",
        "MH_Initialize", "MH_CreateHook", "MH_EnableHook",
        "frida_gum_interceptor", "interceptor_attach",
    ],
)


# ─────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────


PATTERNS: list[Pattern] = [
    VIRTUAL_PROTECT,
    D3D_INTERFACE_STRINGS, OPENGL_HOOK_STRINGS,
    IAT_HOOK_PATTERN, VFT_HIJACK_PATTERN, INLINE_HOOK_PATTERN,
    DETOUR_LIB_STRINGS,
]


def match(bv, *, binary: str, arch: str, platform: str,
          detector: str = "heuristics.hooking") -> list:
    findings = []
    imports = imports_in(bv)
    string_table = strings_in(bv)
    string_values = [s for s, _ in string_table]

    # VirtualProtect imports
    hits = [n for n in VIRTUAL_PROTECT.import_names if n in imports]
    if hits:
        findings.append(emit_finding(
            VIRTUAL_PROTECT,
            address=0, function="<binary>",
            binary=binary, arch=arch, platform=platform,
            detector=detector,
            description_extra=f"imports: {', '.join(hits)}",
            details={"matched_imports": hits},
        ))

    # String-driven patterns
    for pat in (D3D_INTERFACE_STRINGS, OPENGL_HOOK_STRINGS, DETOUR_LIB_STRINGS):
        compare = string_values
        literals = pat.string_literals
        if not pat.case_sensitive:
            compare = [v.lower() for v in string_values]
            literals = [s.lower() for s in literals]
        hits = [needle for needle in literals if any(needle in v for v in compare)]
        if not hits:
            continue
        first_addr = next(
            (a for v, a in string_table
             if any(needle in (v if pat.case_sensitive else v.lower())
                    for needle in literals)),
            0,
        )
        findings.append(emit_finding(
            pat,
            address=first_addr, function="<binary>",
            binary=binary, arch=arch, platform=platform,
            detector=detector,
            description_extra=f"strings: {', '.join(hits[:8])}",
            details={"matched_strings": hits[:32]},
        ))

    # Structural — recognised in analysis/* modules

    return findings
