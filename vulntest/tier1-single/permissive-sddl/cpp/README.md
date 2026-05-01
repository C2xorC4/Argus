# Permissive SDDL — C++ / Windows variant

C++ shape is identical at the binary level — the SDDL string and
Win32 API calls are the same regardless of source language. This
cell exists for the matrix; the C variant at
[`../c/`](../c/) is the canonical implementation.

C++-specific note: `CreateNamedPipeW` has no C++ wrapper in WinRT;
ATL's `CSecurityDesc` provides a typed wrapper but the underlying
SDDL parsing and pipe creation are unchanged.

## Build / Detection / Remediation

See [`../c/README.md`](../c/README.md). This cell uses the same
Makefile-driven build with a `.cpp` source that re-includes the C
implementation:

```cpp
extern "C" {
#include "../c/source/vuln.c"
}
```

(In practice the C variant suffices for both columns; the matrix
slot is preserved for INDEX completeness.)
