# Legacy reference scripts

This directory will hold copies of the pre-Argus scripts from
`~/.claude/skills/binary-ninja/scripts/` for reference during the
rebase. Old code is **not deleted** — it's kept here so:

1. Heuristic dicts (`SUSPICIOUS_IMPORTS`, `DANGEROUS_FUNCTIONS`,
   `TAINT_SOURCES`, `TAINT_SINKS`, `ENTRY_SOURCES`, `GADGET_PATTERNS`)
   can be lifted as baseline seeds for the new `heuristics/` modules.
2. The migration is auditable — Phase 1 detection results can be
   compared against legacy outputs to confirm parity-or-better.
3. SARIF output logic in `legacy/sarif_output.py` (whose schema is
   already stable) can be lifted unchanged into `output/sarif.py`
   if the Phase 0 stub turns out to need more.

When this directory is populated, every file should ship with a
header comment in this form:

```
# Source: ~/.claude/skills/binary-ninja/scripts/<name>.py
# Migrated to: <new module path(s)>
# Migration date: YYYY-MM-DD
# Status: reference-only (do not import from this file)
```

Phase 0 leaves this directory empty; Phase 1 populates it as
modules migrate.
