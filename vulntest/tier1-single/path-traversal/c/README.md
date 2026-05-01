# Path traversal — C variant

## Brief

`read_file()` constructs a path by string concatenation:
`/var/data/` + attacker-controlled `name`. A name like
`../../../etc/passwd` resolves outside the intended directory.

**Difficulty:** `1.0.0`.

## Build / Detection

```bash
make
python3 poc/trigger.py build/vuln    # leaks /etc/passwd
```

Detector: `scripts/analysis/taint.py`. Pattern: file-open call where
the path argument is built from concatenation including
attacker-controlled data, with no `realpath` / `canonicalize_file_name`
/ `GetFullPathName` + prefix-check on the path.

## Remediation

```c
// before
fopen(("BASE" + name), "r");

// after
realpath(constructed, resolved);
if (strncmp(resolved, BASE, strlen(BASE)) != 0) error;
fopen(resolved, "r");
```

Stored in [`remediation/vuln.c`](remediation/vuln.c).

### Architectural fix

Open files via `openat(AT_FDCWD)` with a base-directory file
descriptor and `O_NOFOLLOW`; or chroot/sandbox the worker. Avoid
string-concat path construction entirely.

## Operator-validation checklist

- [ ] Build clean
- [ ] Detector flags fopen with tainted concat path
- [ ] PoC reads `/etc/passwd`
- [ ] Manual Binja UI walkthrough matches
- [ ] Substrate-coherence check via `jm associate`
