# Type confusion — C variant

## Brief

C lacks RTTI; the equivalent type-confusion class is the
**unguarded tagged union**. `value_t` carries a `tag_t` discriminator
plus a union of `int` and `char*`. `process()` accesses `v->u.p`
without checking the tag — when the producer set the union to
`TAG_INT`, the consumer reinterprets those bytes as a pointer and
dereferences.

This is the C-shape of type confusion. Real-world examples include
glibc's `obstack` family and many state-machine implementations
where one path mutates a tagged enum but a sibling path forgot to
re-check.

**Difficulty:** `1.0.0`.

## Build

```bash
make
```

## Detection

### Programmatic

Detector: `scripts/analysis/taint.py`. Pattern: union access where
the discriminator field is not read on the same control-flow path.
Recoverable from IL via struct-shape recognition (Binja's type
inference recovers the union layout from member offsets when
multiple access patterns appear at the same offset).

Full manifest: [`expected.json`](expected.json).

### Manual (Binary Ninja UI)

1. **Identify struct with discriminator.** Field at low offset is
   read for switch / branch.
2. **Find functions accessing union members.** If the access is not
   preceded by a discriminator check on the same path, type
   confusion.

### Reference

- LJM: `[[Memory/Knowledge/ec_undefined_behavior_taxonomy]]` —
  type-rules UB.

## Exploitation

**Primitive class:** type-confusion → wrong-type read / wrong-type
write. In the canonical case, `int` value 0xdeadbeef interpreted as
`char*` produces a wild dereference (likely crash). With control of
the int value, attacker influences the dereferenced address —
arbitrary read.

## Chain potential

- [`type-confusion → arbitrary-read → deref-anywhere`](../../../tier2-chains/)

## Remediation

```c
// before
void process(value_t *v) {
    printf("ptr len=%zu\n", strlen(v->u.p));   // unchecked
}

// after
void process(value_t *v) {
    switch (v->tag) {
    case TAG_PTR: printf("ptr len=%zu\n", v->u.p ? strlen(v->u.p) : 0); break;
    case TAG_INT: printf("int=%d\n", v->u.i); break;
    }
}
```

Stored in [`remediation/vuln.c`](remediation/vuln.c).

### Architectural fix

Encapsulate tagged unions behind getters that take the tag and
return the matching member. Reject mismatched access at the API.

## Operator-validation checklist

- [ ] Build clean
- [ ] Detector flags untagged union access
- [ ] PoC produces wild-dereference crash
- [ ] Manual Binja UI walkthrough matches
- [ ] Substrate-coherence check via `jm associate`
