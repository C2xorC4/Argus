# Command injection — C variant

## Brief

`backup()` builds a shell command via `snprintf("cp %s /tmp/backup/", filename)`
and passes it to `system()`. A filename of `x; touch /tmp/pwn`
expands to `cp x; touch /tmp/pwn /tmp/backup/` — two commands
executed by the shell.

**Difficulty:** `1.0.0`.

## Build / Detection / Exploitation

Detector: `scripts/analysis/taint.py`. Pattern: any `system` /
`popen` / `_wsystem` / `ShellExecute*` family call with a non-literal
first argument tainted by argv / fread / recv.

```bash
make
python3 poc/trigger.py build/vuln
```

### Manual (Binja UI)

1. **Imports → `system`.**
2. **Cross-ref `system`.** Inside `backup`.
3. **Trace the argument.** Built by `snprintf` from `filename` →
   `argv[1]`.

## Remediation

```c
// before
system(cmd);

// after — execl, no shell
execl("/bin/cp", "cp", filename, "/tmp/backup/", (char*)NULL);
```

Stored in [`remediation/vuln.c`](remediation/vuln.c).

### Architectural fix

Project-wide ban on `system` / `popen` / shell. Use
`execve` / `posix_spawn` / `CreateProcess` with explicit argv
arrays. When shell semantics are genuinely needed (rare), allow-list
characters and build a shell-quoted argument explicitly.

## Operator-validation checklist

- [ ] Build clean
- [ ] Detector flags `system()` with tainted argument
- [ ] PoC creates `/tmp/argus_pwn`
- [ ] Manual Binja UI walkthrough matches
- [ ] Substrate-coherence check via `jm associate`
