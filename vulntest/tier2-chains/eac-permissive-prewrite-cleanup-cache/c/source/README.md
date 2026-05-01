# Composed source — Phase 1 build target

The composed program demonstrates all four chain primitives in a
single binary:

1. Service starts with permissive-SDDL named pipe.
2. On client message, performs WriteFile to a trusted path with
   payload from message body.
3. Verification check on the written content; on fail, returns
   without DeleteFileW.
4. A separate "loader" code path reads the trusted path and treats
   its bytes as authenticated.

Phase 0 commits this README; Phase 1 fills in the composed source.
