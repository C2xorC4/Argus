# Chain remediation — defence in depth

Fix any link to break the chain; recommended is to fix all:

1. **Weak PRNG** → CSPRNG (`std::random_device` with platform
   verification, or BCryptGenRandom / getrandom directly).
2. **Cookie-forge** → derive HandshakeSecret from server-private
   key, not predictable PRNG; rotate per-session; add server-side
   replay protection.
3. **Size amplification** → checked arithmetic on allocation sizes
   (`__builtin_mul_overflow`); cap maximum packet size at the
   protocol layer.
