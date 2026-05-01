# TOCTOU / time-of-check time-of-use — C variant

## Brief

`access(path, R_OK)` then `fopen(path, "r")`. Two filesystem
operations on the same path string — and between them the kernel
re-resolves the path. A symlink swap (or junction redirect on
Windows) in the race window points the second resolution at a
different file. The privileged caller reads the swapped target.

The EAC EOS chain is the canonical real-world variant: a privileged
service performs a check on a path, then writes to it; an
unprivileged attacker races the symlink swap to redirect the write
to a SYSTEM-protected target.

**Difficulty:** `1.0.0`.

## Build

```bash
make
python3 poc/trigger.py build/vuln    # races symlink swap; success rate window-dependent
```

## Detection

### Programmatic

Detector: `scripts/analysis/taint.py`. Pattern: two filesystem
operations (`access`, `stat`, `lstat`, `chmod`, `open`, `fopen`,
`unlink`, `rename`) with the same path argument in the same function,
where the second operation is a "use" (open/write/exec) and the
first is a "check" (access/stat/...).

The *path-string* check matters. If both ops use a file descriptor
from a single open, the race is closed (fstat on fd is invariant).

Full manifest: [`expected.json`](expected.json).

### Manual (Binary Ninja UI)

1. **Imports → `access`, `fopen`.** Both present.
2. **Cross-ref both inside `read_user_file`.**
3. **Trace path argument.** Same `path` to both calls; no
   intermediate canonicalisation or open-then-use.
4. **Decision point.** Two filesystem-resolution calls on the same
   path string with the path under attacker influence.

### Reference

- LJM: `[[Memory/Knowledge/eac_eos_arbitrary_write_chain]]` —
  junction-redirect TOCTOU in admin → SYSTEM scenario; the check
  was `IsAuthorisedPath`, the use was a privileged write.

## Exploitation

**Primitive class:** TOCTOU race → file-content swap → privileged
read or write.

**Mitigation considerations.**

- **`O_NOFOLLOW`** — refuses to open symlinks; collapses the race
  window when the attacker only has symlink primitives.
- **`openat(AT_FDCWD, ..., O_NOFOLLOW)` + `fstat`** — single open,
  all checks on the resulting fd; race window is zero.
- **`O_PATH` + verify-then-promote** — open with O_PATH, fstat
  permissions, then re-open via `/proc/self/fd/<n>` if checks pass.

## Chain potential

- [`TOCTOU race → junction redirect → SYSTEM write`](../../../tier2-chains/) —
  the EAC chain.

## Remediation

```c
// before
if (access(path, R_OK) != 0) return -1;
fopen(path, "r");

// after
int fd = open(path, O_RDONLY | O_NOFOLLOW);
fstat(fd, &st);                        /* check the fd, not the path */
fdopen(fd, "r");                       /* use the fd */
```

Stored in [`remediation/vuln.c`](remediation/vuln.c).

### Architectural fix

Project-wide: never check then use a path. Open once with
defensive flags (O_NOFOLLOW, O_CLOEXEC, possibly O_DIRECTORY) and
operate via the resulting fd. On Windows: use NtCreateFile with
OBJ_DONT_REPARSE / FILE_OPEN_REPARSE_POINT and validate the file
ID via fstat-equivalent.

## Operator-validation checklist

- [ ] Build clean
- [ ] Detector flags two filesystem ops on same path string
- [ ] PoC observes `ATTACKER_TARGET` output (race-success dependent)
- [ ] Manual Binja UI walkthrough matches
- [ ] Substrate-coherence check via `jm associate`
