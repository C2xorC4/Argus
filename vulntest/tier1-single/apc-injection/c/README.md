# APC injection — C / Windows

## Brief

`QueueUserAPC` queues a user-mode APC against a thread. When the
thread enters an alertable wait (`SleepEx(_, TRUE)`,
`WaitForSingleObjectEx(_, _, TRUE)`, `MsgWaitForMultipleObjectsEx`,
etc.), pending APCs fire — jumping into the attacker-supplied
function pointer.

The cross-process variant (Early Bird, classic APC injection)
opens a handle to a target thread (`OpenThread`) and queues against
it; the local-thread variant in this cell is the simplest
demonstration.

**Difficulty:** `1.0.0`.

## Detection

Detector: `scripts/analysis/taint.py`. Pattern: `QueueUserAPC` /
`NtQueueApcThread` import paired with alertable-wait family in the
same process.

For cross-process: pair `OpenThread` with `QueueUserAPC` and trace
the thread-handle argument flow.

### Reference

- LJM: `[[Memory/Knowledge/em_advanced_injection_variants]]`
- LJM: `[[Memory/Knowledge/bhg_process_injection_fundamentals]]`

## Operator-validation checklist

- [ ] Build clean
- [ ] Detector flags QueueUserAPC + alertable-wait pair
- [ ] PoC confirms imports
- [ ] Manual Binja UI walkthrough matches
- [ ] Substrate-coherence check via `jm associate`
