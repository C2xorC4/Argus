# Chain remediation — defence in depth

The chain breaks if **any** link is fixed. Best practice is fix
all of them:

1. **Permissive SDDL** → restrict to authorised principals only
   (Local System + Administrators).
2. **Pre-verification write** → verify input bytes before privileged
   write; or use staging-and-rename.
3. **Missing cleanup** → every write site has explicit DeleteFileW
   on failure paths.
4. **Trusted-path cache load** → loader independently validates
   content (signature check, hash match against allowlist) rather
   than trusting "this file was written by the privileged service."

See per-primitive Tier-1 cells for individual fixes.
