# Argus configuration

Per-host runtime config for Argus tooling: Binary Ninja install
location, jm CLI path, build-toolchain executables, output
directories, budgets.

## Files

| File | Purpose | Committed? |
|---|---|---|
| `argus.toml` | Defaults (multi-platform-aware) | yes |
| `argus.local.toml.example` | Operator template — copy → customise | yes (template) |
| `argus.local.toml` | Per-host overrides | no (gitignored) |

## Resolution order

Settings flow through these layers (last wins):

1. Defaults baked into `scripts/lib/config.py:_DEFAULTS`
2. `config/argus.toml` (committed defaults)
3. `config/argus.local.toml` (per-host)
4. Environment variables (`ARGUS_BINJA_PYTHON_PATH`, `ARGUS_JM_PATH`,
   `ARGUS_FINDINGS_DIR`, `ARGUS_SESSIONS_DIR`, `ARGUS_CRASHES_DIR`,
   `ARGUS_SARIF_OUT`, `ARGUS_REPORT_OUT`)
5. Explicit code args (e.g., `BinjaSession(binja_python_path=...)`)

## Usage

```python
from scripts.lib import (
    load_config,
    resolve_binja_python_path,
    resolve_jm_path,
    resolve_toolchain,
)

cfg = load_config()
print(cfg.hostname, cfg.binja.analysis_mode)
print(resolve_binja_python_path())   # platform-aware
print(resolve_jm_path())              # autodetect
print(resolve_toolchain("c"))         # platform-keyed
```

CLI debug view:

```bash
cd skills/binary-ninja
python -m scripts.lib.config
```

## When to add a new setting

1. Add it to `_DEFAULTS` in `scripts/lib/config.py`.
2. Mirror in `config/argus.toml` with a comment.
3. Mirror as a commented-out example in `config/argus.local.toml.example`.
4. Add a typed field to the appropriate dataclass.
5. Wire any consumer module to read it.

Keep all four in sync — the typed fields are the contract,
`_DEFAULTS` keeps config-less environments working, and the TOML
files document operator intent.

## Operator's host inventory

| Host | OS | Binja install |
|---|---|---|
| windows desktop / laptop | Windows | `C:\Program Files\Vector35\BinaryNinja` |
| legion | Linux | `/opt/binaryninja` |
| strx | Linux | `/opt/binaryninja` |

The default `search_paths` in `argus.toml` covers all three; no
override needed unless a non-standard install location is in play.
