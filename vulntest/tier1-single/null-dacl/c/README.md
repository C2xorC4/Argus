# NULL DACL on named IPC — C / Windows

## Brief

`SetSecurityDescriptorDacl(sd, TRUE, NULL, FALSE)` — `bDaclPresent`
true, `pDacl` NULL. Microsoft's docs are explicit: "If the DACL is
NULL, a NULL DACL is assigned to the security descriptor, which
allows all access to the object." This is structurally distinct
from the permissive-SDDL pattern (which builds an *explicit* ACE
granting Everyone) — it disables access control entirely.

NULL DACL is the more dangerous shape: ACL editors may not display
NULL-DACL objects as "world writable" the way they would an
explicit Everyone ACE, masking the issue from auditors.

**Difficulty:** `1.0.0`.

## Detection

Detector: `scripts/analysis/surface.py`. Signal: `SetSecurityDescriptorDacl`
import + call site where the third argument (pDacl) is the constant
NULL / 0 and the second (bDaclPresent) is TRUE / 1.

Recoverable from IL — call-site argument literals are visible in
HLIL.

## Reference

- LJM: `[[Memory/Knowledge/gameguard_research_22_findings]]` —
  GameGuard exposed multiple IPC objects with NULL or near-NULL
  DACLs.

See [`../../permissive-sddl/c/README.md`](../../permissive-sddl/c/README.md)
for the broader IPC-protection class. NULL DACL and Everyone-grant
are sister findings; toolchain emits both at the same severity.

## Operator-validation checklist

- [ ] Build clean
- [ ] Detector flags `SetSecurityDescriptorDacl(*, TRUE, NULL, FALSE)`
- [ ] Manual Binja UI walkthrough matches
- [ ] Substrate-coherence check via `jm associate`
