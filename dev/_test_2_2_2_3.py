"""Smoke-test for 2.2 (decimal IOCTL) and 2.3 (Python PoC parsing)."""
import re
from dataclasses import dataclass

@dataclass
class IoctlBinding:
    code: int
    matched_text: str
    file: str
    line: int

@dataclass
class IoctlDecoded:
    code: int
    device_type: int
    access: int
    function: int
    method: int

    @property
    def method_name(self):
        return ("METHOD_BUFFERED", "METHOD_IN_DIRECT",
                "METHOD_OUT_DIRECT", "METHOD_NEITHER")[self.method]

def decode_ioctl(code):
    return IoctlDecoded(
        code=code & 0xFFFFFFFF, device_type=(code >> 16) & 0xFFFF,
        access=(code >> 14) & 3, function=(code >> 2) & 0xFFF, method=code & 3,
    )

_IOCTL_CMP_RE = re.compile(r"IoControlCode\s*(?:==|!=)\s*(0x[0-9a-fA-F]+|-?\d+)")
_IOCTL_DIC_RE = re.compile(r"DeviceIoControl\s*\([^,)]+,\s*(0x[0-9a-fA-F]+|-?\d+)")
_IOCTL_SWITCH_VAR_PAT = (
    r"IoControlCode|ioControlCode|dwIoControlCode|IoctlCode|ioctlCode"
    r"|dwCtlCode|IoCtrl|ioCtrl|ulIoControlCode"
)
_IOCTL_SWITCH_RE = re.compile(
    r"\bswitch\s*\(\s*(?:\w+[\.\->]+)*(?:" + _IOCTL_SWITCH_VAR_PAT + r")\s*\)"
)
_IOCTL_CASE_RE = re.compile(r"\bcase\s+(0x[0-9a-fA-F]+|-?\d+)\s*:")
_CTL_CODE_RE = re.compile(
    r"\bCTL_CODE\s*\(\s*"
    r"(0x[0-9a-fA-F]+|\d+|FILE_DEVICE_\w+)\s*,\s*"
    r"(0x[0-9a-fA-F]+|\d+)\s*,\s*"
    r"(METHOD_\w+|\d+)\s*,\s*"
    r"(FILE_\w+|\d+)"
    r"\s*\)"
)
_CTL_CODE_METHOD_VALS = {
    "METHOD_BUFFERED": 0, "METHOD_IN_DIRECT": 1,
    "METHOD_OUT_DIRECT": 2, "METHOD_NEITHER": 3,
}
_CTL_CODE_ACCESS_VALS = {
    "FILE_ANY_ACCESS": 0, "FILE_SPECIAL_ACCESS": 0,
    "FILE_READ_ACCESS": 1, "FILE_WRITE_ACCESS": 2, "FILE_READ_WRITE_ACCESS": 3,
}
_CTL_CODE_DEVICE_VALS = {
    "FILE_DEVICE_UNKNOWN": 0x22, "FILE_DEVICE_DISK": 0x07,
    "FILE_DEVICE_KEYBOARD": 0x0B, "FILE_DEVICE_MOUSE": 0x0F,
    "FILE_DEVICE_NULL": 0x15, "FILE_DEVICE_VIRTUAL_DISK": 0x24,
    "FILE_DEVICE_KSEC": 0x39, "FILE_DEVICE_FIPS": 0x3A,
}

_PY_CONST_RE = re.compile(
    r"^([A-Z][A-Z0-9_]{2,})\s*=\s*(0x[0-9a-fA-F]+|-?\d+)", re.MULTILINE
)
_PY_DIC_RE = re.compile(
    r"DeviceIoControl\s*\([^,)]+,\s*(?:ctypes\.\w+\s*\(\s*)?(0x[0-9a-fA-F]+|-?\d+)"
)
_PY_DEVICE_PATH_RE = re.compile(
    r"""r['"]\\{2}\.\\([A-Za-z0-9_]+)|['"]\\{4}\.\\{2}([A-Za-z0-9_]+)"""
)


def _parse_ioctl_int(raw):
    r = raw.strip()
    if r.startswith(("0x", "0X")):
        return int(r, 16)
    return int(r)


def _looks_like_ioctl_constant(code):
    return bool((code & 0xFFFF0000) and (code & 0xFFFFFFFF))


def _scan_ioctl_switch_cases(text, file_path):
    out = []
    for m in _IOCTL_SWITCH_RE.finditer(text):
        brace_pos = text.find("{", m.end())
        if brace_pos == -1:
            continue
        depth, i = 1, brace_pos + 1
        while i < len(text) and depth > 0:
            c = text[i]
            if c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
            i += 1
        switch_body = text[brace_pos + 1: i - 1]
        body_offset = brace_pos + 1
        for cm in _IOCTL_CASE_RE.finditer(switch_body):
            try:
                code = _parse_ioctl_int(cm.group(1)) & 0xFFFFFFFF
            except Exception:
                continue
            if not _looks_like_ioctl_constant(code):
                continue
            abs_pos = body_offset + cm.start()
            line = text[:abs_pos].count("\n") + 1
            ctx = text[max(0, abs_pos - 20):abs_pos + 60].strip()
            out.append(IoctlBinding(code=code, matched_text=ctx,
                                    file=file_path, line=line))
    return out


def _scan_ctl_code_macros(text, file_path):
    out = []
    for m in _CTL_CODE_RE.finditer(text):
        dev_raw, fn_raw, meth_raw, acc_raw = (m.group(i) for i in range(1, 5))
        try:
            dev = (_CTL_CODE_DEVICE_VALS.get(dev_raw)
                   if dev_raw.startswith("FILE_") else _parse_ioctl_int(dev_raw))
            if dev is None:
                continue
            fn = _parse_ioctl_int(fn_raw)
            meth = (_CTL_CODE_METHOD_VALS.get(meth_raw)
                    if meth_raw.startswith("METHOD_") else _parse_ioctl_int(meth_raw))
            if meth is None:
                continue
            acc = (_CTL_CODE_ACCESS_VALS.get(acc_raw)
                   if acc_raw.startswith("FILE_") else _parse_ioctl_int(acc_raw))
            if acc is None:
                continue
        except Exception:
            continue
        code = ((dev << 16) | (acc << 14) | (fn << 2) | meth) & 0xFFFFFFFF
        line = text[:m.start()].count("\n") + 1
        ctx = text[max(0, m.start() - 30):m.end() + 30].strip()
        out.append(IoctlBinding(code=code, matched_text=ctx,
                                file=file_path, line=line))
    return out


def _scan_ioctl_bindings(text, file_path):
    out = []
    for m in _IOCTL_CMP_RE.finditer(text):
        try:
            code = _parse_ioctl_int(m.group(1)) & 0xFFFFFFFF
        except Exception:
            continue
        line = text[:m.start()].count("\n") + 1
        out.append(IoctlBinding(code=code,
                                matched_text=text[max(0, m.start()-30):m.end()+80].strip(),
                                file=file_path, line=line))
    for m in _IOCTL_DIC_RE.finditer(text):
        try:
            code = _parse_ioctl_int(m.group(1)) & 0xFFFFFFFF
        except Exception:
            continue
        line = text[:m.start()].count("\n") + 1
        out.append(IoctlBinding(code=code,
                                matched_text=text[max(0, m.start()-30):m.end()+60].strip(),
                                file=file_path, line=line))
    out.extend(_scan_ioctl_switch_cases(text, file_path))
    out.extend(_scan_ctl_code_macros(text, file_path))
    return out


def _scan_py_poc_bindings(text, file_path):
    ioctls, devices = [], []
    for m in _PY_DEVICE_PATH_RE.finditer(text):
        name = m.group(1) or m.group(2) or ""
        if name:
            devices.append(name)
    seen = set()
    for m in _PY_CONST_RE.finditer(text):
        try:
            code = _parse_ioctl_int(m.group(2)) & 0xFFFFFFFF
        except Exception:
            continue
        if not _looks_like_ioctl_constant(code) or code in seen:
            continue
        seen.add(code)
        line = text[:m.start()].count("\n") + 1
        ioctls.append(IoctlBinding(code=code, matched_text=m.group(0).strip(),
                                   file=file_path, line=line))
    for m in _PY_DIC_RE.finditer(text):
        try:
            code = _parse_ioctl_int(m.group(1)) & 0xFFFFFFFF
        except Exception:
            continue
        if not _looks_like_ioctl_constant(code) or code in seen:
            continue
        seen.add(code)
        line = text[:m.start()].count("\n") + 1
        ctx = text[max(0, m.start()-20):m.end()+40].strip()
        ioctls.append(IoctlBinding(code=code, matched_text=ctx,
                                   file=file_path, line=line))
    return ioctls, devices


# ── Tests ─────────────────────────────────────────────────────────

PASS = 0

def check(label, cond, detail=""):
    global PASS
    if cond:
        print(f"[PASS] {label}")
        PASS += 1
    else:
        print(f"[FAIL] {label}: {detail}")
        raise AssertionError(label)


# 2.2a: decimal comparison
b = _scan_ioctl_bindings("if (IoControlCode == 2236420) {}", "t.c")
check("decimal comparison", len(b) == 1 and b[0].code == 2236420,
      f"got {[hex(x.code) for x in b]}")

# 2.2b: negative decimal (high-bit IOCTL in IDA signed form)
b = _scan_ioctl_bindings("if (IoControlCode == -2144337912) {}", "t.c")
expected = (-2144337912) & 0xFFFFFFFF
check("negative decimal", len(b) == 1 and b[0].code == expected,
      f"got {[hex(x.code) for x in b]}")

# 2.2c: switch-case
text = (
    "switch (IoControlCode) {\n"
    "    case 0x222004: HandleOpen(); break;\n"
    "    case 2228236:  HandleClose(); break;\n"
    "    case 0:        break;\n"
    "}\n"
)
b = _scan_ioctl_bindings(text, "d.c")
codes = {x.code for x in b}
check("switch-case hex", 0x222004 in codes, f"codes={[hex(c) for c in codes]}")
check("switch-case decimal", 2228236 in codes, f"codes={[hex(c) for c in codes]}")
check("switch-case zero filtered", 0 not in codes, "0 should be filtered")

# 2.2d: CTL_CODE with named constants
b = _scan_ioctl_bindings(
    "CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)", "h.h"
)
expected = (0x22 << 16) | (0 << 14) | (0x800 << 2) | 0
check("CTL_CODE named consts", len(b) == 1 and b[0].code == expected,
      f"got {[hex(x.code) for x in b]}")

# 2.2e: CTL_CODE with METHOD_NEITHER
b = _scan_ioctl_bindings("CTL_CODE(0x22, 0x810, METHOD_NEITHER, FILE_ANY_ACCESS)", "h.h")
d = decode_ioctl(b[0].code)
check("CTL_CODE METHOD_NEITHER", d.method == 3, f"method={d.method}")

# 2.2f: CTL_CODE with numeric method
b = _scan_ioctl_bindings("CTL_CODE(0x22, 0x820, 3, 0)", "h.h")
d = decode_ioctl(b[0].code)
check("CTL_CODE numeric method/access", d.method == 3, f"method={d.method}")

# 2.3a: Python PoC — constant definitions and DeviceIoControl literal
py_src = (
    "IOCTL_READ_PHYS = 0x80006044\n"
    "IOCTL_WRITE_PHYS = 0x80006048\n"
    "SMALL = 42\n"
    "NEGATIVE_IOCTL = -2144337912\n"
    r'hDev = kernel32.CreateFileW(r"\\.\K7AVWScn", 0, 0, None, 3, 0, None)' + "\n"
    "kernel32.DeviceIoControl(hDev, 0x80006050, buf, 8, None, 0, n, None)\n"
)
ioctls, devs = _scan_py_poc_bindings(py_src, "k7_poc.py")
codes = {b.code for b in ioctls}
check("py ioctl 0x80006044", 0x80006044 in codes, str([hex(c) for c in codes]))
check("py ioctl 0x80006048", 0x80006048 in codes, str([hex(c) for c in codes]))
check("py ioctl DeviceIoControl literal", 0x80006050 in codes, str([hex(c) for c in codes]))
check("py small const filtered", 42 not in codes, "42 should be filtered")
neg = (-2144337912) & 0xFFFFFFFF
check("py negative IOCTL", neg in codes, f"missing {hex(neg)}: {[hex(c) for c in codes]}")
check("py device name raw string", "K7AVWScn" in devs, str(devs))

# 2.3b: escaped-string device path "\\\\.\\AnotherDriver"
# Raw Python source text needs 4 backslashes + period + 2 backslashes in the file.
py_src2 = r'hDev = CreateFileW("\\\\.\\AnotherDriver", 0)' + "\n"
_, devs2 = _scan_py_poc_bindings(py_src2, "poc2.py")
check("py device escaped string", "AnotherDriver" in devs2, str(devs2))

print(f"\n{PASS} tests passed.")
