"""Import-table heuristics — the dangerous-function baseline.

This module is *data-first*: it exports the canonical SOURCES,
SINKS, and BANNED tables that downstream analysis modules consume.
It does not emit findings on its own — combo patterns (the
process-injection trio, etc.) live in `injection.py`; the
banned-function-as-finding emits live in `analysis/taint.py` once
taint flow ties a banned import to attacker-controlled input.

Knowledge anchor: legacy `legacy/security_audit.py:DANGEROUS_FUNCTIONS`
(84 entries) extended with newer banned-API guidance from MS SDL
and CERT secure-coding standards.
"""

from __future__ import annotations

from ._base import ImportPattern, Pattern
from ..output.finding import Severity


# ─────────────────────────────────────────────────────────────────
# Taint sources — attacker-influenceable inputs
# ─────────────────────────────────────────────────────────────────


SOURCES_LIBC: set[str] = {
    "argv",                      # synthetic — main's argv parameter
    "getenv", "getenv_s", "secure_getenv",
    "fgets", "gets", "gets_s",
    "fread", "read", "recv", "recvfrom", "recvmsg",
    "scanf", "fscanf", "sscanf", "vscanf", "vfscanf", "vsscanf",
    "stdin",
    # Single-character / byte input — return value carries the
    # attacker-controlled byte (legacy `deep_analysis.py:TAINT_SOURCES`).
    "getchar", "getc", "fgetc", "getchar_unlocked",
    # Network connection accept — caller assumes the returned socket
    # is attacker-influenced (legacy `attack_surface.py:ENTRY_SOURCES`).
    "accept", "accept4",
    # IPC message receive — message body is attacker-controlled.
    "msgrcv", "mq_receive", "mq_timedreceive",
    # Shared-memory attach — region contents are attacker-controlled
    # when a hostile process has write access.
    "shmat",
}

SOURCES_WIN32: set[str] = {
    "GetCommandLineA", "GetCommandLineW",
    "GetEnvironmentVariableA", "GetEnvironmentVariableW",
    "ReadFile", "ReadFileEx",
    "recv", "recvfrom", "WSARecv", "WSARecvFrom",
    "RegQueryValueExA", "RegQueryValueExW",
    "GetUserNameA", "GetUserNameW",
    "GetComputerNameA", "GetComputerNameW",
    "InternetReadFile", "WinHttpReadData",
}

SOURCES: set[str] = SOURCES_LIBC | SOURCES_WIN32


# ─────────────────────────────────────────────────────────────────
# Taint sinks — places dangerous if reached by tainted data
# ─────────────────────────────────────────────────────────────────


# (sink_name, dangerous_argument_index, sink_class)
# arg_index: position of the dangerous parameter (0-based)
# sink_class: short tag — used by analysis/taint.py to tailor the Finding
SINKS: list[tuple[str, int, str]] = [
    # ── Memory copy — unbounded ──────────────────────────────────
    ("strcpy",      1, "buffer_overflow"),
    ("stpcpy",      1, "buffer_overflow"),
    ("strcat",      1, "buffer_overflow"),
    ("wcscpy",      1, "buffer_overflow"),
    ("wcscat",      1, "buffer_overflow"),
    ("lstrcpyA",    1, "buffer_overflow"),
    ("lstrcpyW",    1, "buffer_overflow"),
    ("lstrcatA",    1, "buffer_overflow"),
    ("lstrcatW",    1, "buffer_overflow"),
    ("memcpy",      2, "buffer_overflow"),       # length is the controllable param
    ("memmove",     2, "buffer_overflow"),
    ("bcopy",       2, "buffer_overflow"),

    # ── Memory copy — bounded but error-prone ───────────────────
    ("strncpy",     2, "buffer_overflow"),       # NUL-termination footgun
    ("strncat",     2, "buffer_overflow"),

    # ── Unbounded read — no length argument; the destination buffer
    # is filled until newline / NUL. Direct attacker-controlled write.
    ("gets",        0, "buffer_overflow"),

    # ── Stack allocation — tainted size flows to alloca. The return
    # is a stack pointer; large sizes blow the stack. Same `alloc_size`
    # class as malloc/calloc/realloc — consumers want the integer-OF
    # → undersized-alloc finding.
    ("alloca",      0, "alloc_size"),
    ("_alloca",     0, "alloc_size"),
    ("__builtin_alloca", 0, "alloc_size"),

    # ── FORTIFY_SOURCE checked variants — same vulnerability class
    # as the unchecked baseline. Compiler-generated runtime bound
    # checks cover the common case but NOT all overflow scenarios
    # (dynamic destination size, format-string sites, etc.).
    # Argument indices match the underlying API (legacy
    # `deep_analysis.py:TAINT_SINKS`).
    ("__strcpy_chk",   1, "buffer_overflow"),
    ("__strcat_chk",   1, "buffer_overflow"),
    ("__memcpy_chk",   2, "buffer_overflow"),
    ("__memmove_chk",  2, "buffer_overflow"),
    # `__sprintf_chk(str, flag, len, fmt, ...)` — fmt is at arg 3
    ("__sprintf_chk",  3, "format_string"),
    ("__vsprintf_chk", 3, "format_string"),
    # `__printf_chk(flag, fmt, ...)` — fmt at arg 1
    ("__printf_chk",   1, "format_string"),
    ("__vprintf_chk",  1, "format_string"),
    # `__fprintf_chk(stream, flag, fmt, ...)` — fmt at arg 2
    ("__fprintf_chk",  2, "format_string"),
    ("__vfprintf_chk", 2, "format_string"),
    # `__snprintf_chk(str, maxlen, flag, len, fmt, ...)` — fmt at arg 4
    ("__snprintf_chk", 4, "format_string"),
    ("__vsnprintf_chk", 4, "format_string"),
    ("__syslog_chk",   2, "format_string"),

    # ── Format string ────────────────────────────────────────────
    ("printf",      0, "format_string"),
    ("fprintf",     1, "format_string"),
    ("sprintf",     1, "format_string"),
    ("snprintf",    2, "format_string"),         # format arg
    ("vprintf",     0, "format_string"),
    ("vfprintf",    1, "format_string"),
    ("vsprintf",    1, "format_string"),
    ("vsnprintf",   2, "format_string"),
    ("syslog",      1, "format_string"),
    ("err",         1, "format_string"),
    ("errx",        1, "format_string"),
    ("warn",        0, "format_string"),
    ("warnx",       0, "format_string"),

    # ── Process / shell ──────────────────────────────────────────
    ("system",      0, "command_injection"),
    ("popen",       0, "command_injection"),
    ("execl",       0, "command_injection"),
    ("execlp",      0, "command_injection"),
    ("execle",      0, "command_injection"),
    ("execv",       0, "command_injection"),
    ("execvp",      0, "command_injection"),
    ("execvpe",     0, "command_injection"),
    ("WinExec",     0, "command_injection"),
    ("ShellExecuteA", 2, "command_injection"),
    ("ShellExecuteW", 2, "command_injection"),
    ("ShellExecuteExA", 0, "command_injection"),
    ("ShellExecuteExW", 0, "command_injection"),
    ("CreateProcessA", 1, "command_injection"),
    ("CreateProcessW", 1, "command_injection"),

    # ── File path ────────────────────────────────────────────────
    ("fopen",       0, "path_traversal"),
    ("freopen",     0, "path_traversal"),
    ("open",        0, "path_traversal"),
    ("openat",      1, "path_traversal"),
    ("CreateFileA", 0, "path_traversal"),
    ("CreateFileW", 0, "path_traversal"),
    # C++ stdlib filestream constructors — `this` is arg 0, path arg 1.
    # Itanium / GCC libstdc++ demangled forms; MSVC produces the
    # same short_names through Binja's demangler.
    ("std::ifstream::ifstream",    1, "path_traversal"),
    ("std::ofstream::ofstream",    1, "path_traversal"),
    ("std::fstream::fstream",      1, "path_traversal"),
    ("std::wifstream::wifstream",  1, "path_traversal"),
    ("std::wofstream::wofstream",  1, "path_traversal"),
    ("std::ifstream::open",        1, "path_traversal"),
    ("std::ofstream::open",        1, "path_traversal"),
    ("std::fstream::open",         1, "path_traversal"),

    # ── C++ stdin extraction — std::cin >> char[] ──────────────
    # libstdc++ internal helper that the unbounded operator>>(istream&,
    # char*) overload calls. No length argument → unbounded write into
    # the target buffer. Same hazard class as gets()/strcpy() but in
    # idiomatic C++.
    ("std::__istream_extract",     1, "buffer_overflow"),

    # ── SQL — typically reached only when SQLite/etc. is linked ──
    ("sqlite3_exec",     1, "sql_injection"),
    ("PQexec",           1, "sql_injection"),
    ("mysql_query",      1, "sql_injection"),

    # ── Allocation — integer-overflow → undersized alloc ─────────
    ("malloc",      0, "alloc_size"),
    ("calloc",      1, "alloc_size"),            # count × size; overflow class
    ("realloc",     1, "alloc_size"),
    ("HeapAlloc",   2, "alloc_size"),
    ("VirtualAlloc", 1, "alloc_size"),
    ("operator new",      0, "alloc_size"),
    ("operator new[]",    0, "alloc_size"),

    # ── Linux kernel — scatter-gather write at offset ────────────
    # CVE-2026-31431 ("copy.fail") shape: scatterwalk_map_and_copy
    # writes `nbytes` to a scatterlist at `start` offset. When start
    # is attacker-controlled (e.g., assoclen + cryptlen from
    # `struct aead_request *req` user-set fields) and the dst is
    # chained via sg_chain() into page-cache pages, this is an
    # OOB page-cache write.
    ("scatterwalk_map_and_copy", 2, "kernel_oob_write"),
    ("memcpy_to_iter",           1, "kernel_oob_write"),
    ("copy_to_iter",             1, "kernel_oob_write"),

    # ── Windows kernel — physical memory abuse / arbitrary R/W ──
    # CVE-2021-21551 ("dbutil_2_3.sys") class: signed driver exposes
    # IOCTL handlers that pass attacker-controlled data into the
    # physical-memory mapping APIs, yielding arbitrary kernel R/W.
    # The dangerous arg is the one that names a kernel address /
    # physical address / MSR index / allocation size; tainted
    # values there are the BYOVD primitive signature.
    ("MmMapIoSpace",                          0, "kernel_arbitrary_rw"),
    ("MmMapIoSpaceEx",                        0, "kernel_arbitrary_rw"),
    ("MmGetPhysicalAddress",                  0, "kernel_phys_disclosure"),
    ("MmAllocateContiguousMemorySpecifyCache", 0, "kernel_alloc_size"),
    ("MmAllocateContiguousMemory",            0, "kernel_alloc_size"),
    ("ZwMapViewOfSection",                    2, "kernel_arbitrary_rw"),
    ("NtMapViewOfSection",                    2, "kernel_arbitrary_rw"),
    ("__writemsr",                            0, "kernel_msr_write"),
    ("__readmsr",                             0, "kernel_msr_read"),
    # Kernel `RtlCopyMemory` / `memcpy` are listed under
    # buffer_overflow above; the Windows-kernel path uses the same
    # symbol names. The taint analyzer applies kernel-context
    # severity escalation when the binary is a kernel driver.

    # ── Windows kernel — process-handle abuse / arbitrary process termination ──
    # BYOVD process-killer class — signed driver exposes IOCTL handlers
    # that take an attacker-controlled PID, open a handle to the
    # target process via `Zw/NtOpenProcess`, then call
    # `Zw/NtTerminateProcess`. Used universally to disable AV/EDR
    # agents from user-mode (the "EDR killer" pattern).
    # The dangerous arg for OpenProcess family is the CLIENT_ID at
    # arg index 3 (PID lives in `CLIENT_ID.UniqueProcess`); for
    # TerminateProcess it's the handle (arg 0) — fired by tainted
    # propagation through the OpenProcess→handle→TerminateProcess
    # chain rather than direct PID-to-Terminate flow.
    ("ZwOpenProcess",                         3, "kernel_arbitrary_process_handle"),
    ("NtOpenProcess",                         3, "kernel_arbitrary_process_handle"),
    ("ZwTerminateProcess",                    0, "kernel_arbitrary_process_terminate"),
    ("NtTerminateProcess",                    0, "kernel_arbitrary_process_terminate"),
    ("PsLookupProcessByProcessId",            0, "kernel_arbitrary_process_handle"),
    # File overwrite class — signed driver exposes IOCTL that
    # takes attacker-controlled file path + bytes; used to overwrite
    # AV signature files / drop persistence payloads.
    ("ZwCreateFile",                          2, "kernel_arbitrary_file_open"),
    ("NtCreateFile",                          2, "kernel_arbitrary_file_open"),
    ("ZwWriteFile",                           5, "kernel_arbitrary_file_write"),
    ("NtWriteFile",                           5, "kernel_arbitrary_file_write"),
    # Registry-persistence class — signed driver writes registry
    # keys on behalf of attacker (kernel-mode bypass of access checks).
    ("ZwSetValueKey",                         1, "kernel_arbitrary_registry_write"),
    ("NtSetValueKey",                         1, "kernel_arbitrary_registry_write"),
]


# ─────────────────────────────────────────────────────────────────
# Banned functions — present in binary at all = info-level finding
# ─────────────────────────────────────────────────────────────────
# These are flagged as standalone signals (not requiring taint flow)
# because their use is universally discouraged — MS-banned-API list.


BANNED: list[ImportPattern] = [
    ImportPattern(
        name="banned_import.gets",
        description="`gets` is unbounded and removed in C11; presence in the binary indicates legacy or audit-failed code",
        severity=Severity.HIGH,
        category="banned_function",
        cwe=["CWE-242", "CWE-120"],
        knowledge_refs=[],
        import_names=["gets"],
    ),
    ImportPattern(
        name="banned_import.strcpy_family",
        description="`strcpy` / `strcat` / `sprintf` / `vsprintf` are unbounded — use bounded variants",
        severity=Severity.LOW,
        category="banned_function",
        cwe=["CWE-120"],
        knowledge_refs=[],
        import_names=["strcpy", "strcat", "sprintf", "vsprintf"],
    ),
    ImportPattern(
        name="banned_import.lstrcpy_family",
        description="`lstrcpy*` / `lstrcat*` (Win32) are unbounded; use `StringCch*` / `StringCb*`",
        severity=Severity.LOW,
        category="banned_function",
        cwe=["CWE-120"],
        knowledge_refs=[],
        import_names=["lstrcpyA", "lstrcpyW", "lstrcatA", "lstrcatW"],
    ),
    ImportPattern(
        name="banned_import.scanf_unbounded",
        description="`scanf` / `fscanf` / `sscanf` with `%s` are unbounded",
        severity=Severity.LOW,
        category="banned_function",
        cwe=["CWE-120"],
        knowledge_refs=[],
        import_names=["scanf", "fscanf", "sscanf", "vscanf", "vfscanf", "vsscanf"],
    ),
]


# ─────────────────────────────────────────────────────────────────
# FORTIFY — when a binary imports `__strcpy_chk` etc., the developer
# enabled FORTIFY_SOURCE; when only the unchecked variant appears,
# the build is missing the hardening. This signal feeds analysis/
# mitigations.py.
# ─────────────────────────────────────────────────────────────────


FORTIFY_CHECKED_VARIANTS: dict[str, str] = {
    "strcpy":   "__strcpy_chk",
    "strcat":   "__strcat_chk",
    "memcpy":   "__memcpy_chk",
    "memmove":  "__memmove_chk",
    "memset":   "__memset_chk",
    "sprintf":  "__sprintf_chk",
    "snprintf": "__snprintf_chk",
    "vsprintf": "__vsprintf_chk",
    "vsnprintf": "__vsnprintf_chk",
    "fprintf":  "__fprintf_chk",
    "printf":   "__printf_chk",
    "fgets":    "__fgets_chk",
    "read":     "__read_chk",
}


# ─────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────


PATTERNS: list[Pattern] = list(BANNED)


def match(bv, *, binary: str, arch: str, platform: str,
          detector: str = "heuristics.imports") -> list:
    """Emit Findings for banned imports present in the binary.

    Combo patterns (process-injection trio etc.) live in
    `injection.py`; this function only handles single-import banned
    signals.
    """
    from ._base import imports_in, emit_finding
    imports = imports_in(bv)
    out = []
    for pattern in BANNED:
        hits = [name for name in pattern.import_names if name in imports]
        if not hits:
            continue
        out.append(emit_finding(
            pattern,
            address=0,                       # binary-scope finding
            function="<binary>",
            binary=binary,
            arch=arch,
            platform=platform,
            detector=detector,
            description_extra=f"imports: {', '.join(hits)}",
            details={"matched_imports": hits},
        ))
    return out
