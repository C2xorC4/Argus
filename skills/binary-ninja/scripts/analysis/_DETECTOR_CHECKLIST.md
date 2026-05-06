# Detector Authoring Checklist

Every new detector module in `analysis/` must satisfy the items below
before it lands. The checklist exists to encode lessons learned from
prior detector work — most importantly Run 14's visited-key fix and
the daydream-surfaced traps for the Tier 2 detector family.

This is not a style guide. It is a correctness substrate.

---

## 1. Visited-key state completeness

The Run 14 lesson, generalised: **the visited key must encode every
state component that affects per-node emission downstream of that
node.** Otherwise the first-arriving path's state masks all subsequent
paths' states, producing path-dependent (i.e. non-deterministic)
output.

For each detector, before writing the recursive walk:

- [ ] List every state component that influences whether this detector
      will emit a Finding *at or below* the current node.
- [ ] Confirm each component is in the visited key.
- [ ] If a component is monotonic (e.g. boolean that only flips one
      direction), encode it as that single bit, not the raw count.
- [ ] If a component is non-monotonic (e.g. "is variable initialised"),
      encode it explicitly; you will need both true-and-false visit
      slots.

Reference cases:

- Taint analyzer (Run 14): key includes `crossed_load = via_load_count >= 1`.
- TOCTOU detector (Tier 2 #7): key MUST include "has check been seen
  on this path" (otherwise a path that bypasses the check entirely
  is masked by a path that goes through it).
- Uninit-mem detector (Tier 2 #5): key MUST include "is target
  initialised at this point" (otherwise a path that initialises is
  masked by a path that doesn't).
- Type-confusion detector (Tier 2 #6): key MUST include "has type
  check been seen on this path" — same shape as TOCTOU.

---

## 2. Per-seed isolation

If your detector seeds from multiple sources and walks the def-use
or CFG graph from each, **per-seed visited tracking is mandatory**.
Instance-level visited sets cause Run-13-class nondeterminism — seed
iteration order (hash-randomised) determines which paths fire.

- [ ] Each top-level seed call creates a fresh visited set.
- [ ] The visited set is threaded through recursive descent.
- [ ] No instance-level visited state.
- [ ] Cross-seed dedup happens at `Finding.id` level (content-
      addressed via `compute_id()`) — not by suppressing duplicate
      visits across seeds.

---

## 3. Signal declaration

Every Finding emission must declare its driving signals via
`lib.scoring.apply_signals_to_finding(finding, [signal_names])`.

- [ ] Signals registered in `lib/scoring.py:_HUB_SIGNALS` /
      `_SPECIFIC_SIGNALS` (one canonical place; do not register in
      detector modules).
- [ ] Each signal is classified HUB or SPECIFIC honestly. A HUB
      signal whose `participating_categories` is one entry is a
      red flag — fix the classification.
- [ ] On emission, the detector calls `apply_signals_to_finding`
      before appending to the finding list.
- [ ] If a finding's confidence falls below your detector's floor
      (default 0.30), suppress the finding rather than emit it. The
      floor is detector-specific; document it.

---

## 4. Architectural-blindspot awareness

Daydream-surfaced traps that apply to multiple detectors:

### 4a. Compiler-erased evidence (integer-OF, similar)

Per `ec_undefined_behavior_taxonomy`: GCC/Clang/MSVC exploit signed-
overflow UB to dead-code-eliminate present-but-redundant guard
checks. The binary may contain zero evidence of a guard that the
source code clearly had.

- [ ] If your detector keys on the *presence* of a defensive
      pattern, sanity-check whether the compiler may have erased it.
      If yes, key on the *absence* of the defensive pattern instead
      (CFG dominance: no comparison on the target var dominates the
      sink).
- [ ] Document this in the detector docstring so future maintainers
      don't "fix" it back to presence-keying.

### 4b. ABI-split structural shapes (type-confusion, similar)

vtable shape differs by ABI: MSVC `__thiscall` / ECX vs GCC explicit-
first-parameter. RTTI layouts differ. Template instantiation
produces legitimate vtable diversity.

- [ ] If your detector keys on a structural shape, confirm it
      handles the ABI variants present in your target corpus.
- [ ] Either two extractors (MSVC + GCC) or one with ABI dispatch.
- [ ] Distinguish legitimate diversity (template instantiation)
      from confusion (downcast without check).

### 4c. Compiler-codegen-hidden allocation (stack-OF)

Per `hw_stack_overflow_mechanics`:

- Compiler reorders locals for alignment — source-level adjacency
  is wrong.
- Canary padding inflates the buffer-to-return-address distance.
- Leaf functions on x86_64 SysV use the 128-byte red zone with no
  `sub rsp, N` instruction.

- [ ] Detector does not assume `sub rsp, N` is present.
- [ ] Detector accounts for canary padding when computing
      buffer-to-RA distance.
- [ ] Detector reads post-codegen layout (Binja stack-frame map),
      not source-level adjacency.

---

## 5. Tier-1 VulnTest cell first

Before merging a new detector:

- [ ] Build at least one Tier-1 VulnTest cell at
      `vulntest/tier1-single/<class>-<lang>/` covering the canonical
      shape your detector targets.
- [ ] `expected.json` lists the category your detector emits.
- [ ] Detector fires on that cell.
- [ ] Detector does NOT fire on the corresponding clean control
      (sibling cell with the bug fixed) — proves the signal isn't
      structural noise.

---

## 6. Knowledge citation

- [ ] Each Finding category has a non-empty `knowledge_refs` list
      pointing to the LJM Knowledge entry / entries that drove the
      detection logic.
- [ ] If the citation doesn't exist, raise it as a documentation gap
      rather than emitting an unsourced Finding.

---

## 7. Phase-1 detector documentation

- [ ] `manual_workflows/analysis-<module>.md` companion doc exists
      and covers: programmatic invocation, manual UI sequence,
      reference Knowledge entries, divergence policy.
- [ ] Detector docstring lists its emission categories, the signals
      that anchor each, and the expected confidence floor.

---

## Appendix — non-determinism red flags

If any of these surface during testing:

- Finding count varies between runs on the same binary in the same
  process
- Finding ordering varies between runs
- A finding present in run N is absent in run N+1 with no code change

**Stop and audit the visited key.** Do not "fix" by sorting findings
or deduping more aggressively — those are symptoms, not causes.

If the analyser's count fluctuates, you cannot tell whether a
finding-count change is a regression or just a different run.
Determinism is load-bearing for the Run-N validation chronicle.
