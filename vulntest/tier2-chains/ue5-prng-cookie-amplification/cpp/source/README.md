# Composed source — Phase 1 build target

Demonstrates all three chain primitives:

1. Server seeds a PRNG from low-entropy time source; uses output
   to derive HandshakeSecret.
2. Cookie generation HMACs connection state with HandshakeSecret;
   attacker who recovered HandshakeSecret forges cookies.
3. Server allocates packet buffers from attacker-controllable
   length fields; integer multiplication wraps to small-alloc, copy
   uses original large length → DoS via heap exhaustion or crash.

Phase 0 commits this README; Phase 1 fills in the composed source.
