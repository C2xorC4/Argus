# Double-free — C++ variant

## Brief

`Owner` holds a raw owning pointer (`std::string* data_`) and
declares a destructor that `delete`s it. It does **not** declare a
copy constructor or copy assignment — the compiler-generated default
shallow-copies the pointer. Two `Owner` objects then point to the
same heap allocation; both destructors run, freeing it twice.

This is a textbook Rule-of-Three violation
(C++03) / Rule-of-Five (C++11+). It's also one of the most common
real-world C++ memory bugs, because the copy is implicit and silent.

**Difficulty:** `1.0.0`.

## Build

```bash
make
make asan
```

## Detection

### Programmatic

Detector: `scripts/analysis/heap.py` — Rule-of-Three checker.
Pattern: a class declares a destructor that calls `operator delete`
on a member, but no user-declared copy ctor / op= / move ctor / move
op=. Compiler-generated copy = double-free risk.

This is structurally detectable in IL (vtable / RTTI inspection
gives the destructor; member offsets give the freed field; absence
of copy-ctor symbol confirms compiler-generated default).

Full manifest: [`expected.json`](expected.json).

### Manual (Binary Ninja UI)

1. **Functions → `Owner` constructors / destructors.** Look for
   compiler-generated copy ctor symbol (e.g., gcc: `Owner::Owner(Owner const&)`
   without explicit `_GLOBAL_*` annotation).
2. **Inspect destructor.** `delete data_` — confirms field is
   freed.
3. **Find Owner copy sites.** `Owner b = a` decomposes to copy ctor
   call. If only the implicit one exists, both Owners point to the
   same heap memory.

### Reference

- LJM: `[[Memory/Knowledge/wnapi_heap_internals]]`
- C++ Core Guidelines C.20 (Rule of Zero), C.21 (Rule of Five).

## Exploitation

Same primitives as C variant — tcache poisoning, free-list overlap,
arbitrary-write.

## Chain potential

- [`heap-OF → vtable-hijack → ROP`](../../../tier2-chains/) — a
  follow-on allocation reuses the doubly-freed chunk; if the type
  has a vtable, vtable-hijack chain follows.

## Remediation

```cpp
// before — Rule-of-Three violation
class Owner {
    std::string* data_;
    ~Owner() { delete data_; }
};

// after — Rule of Zero via unique_ptr
class Owner {
    std::unique_ptr<std::string> data_;
};
```

Stored in [`remediation/vuln.cpp`](remediation/vuln.cpp).

### Compiler / linker mitigations

- `-Wdeprecated-copy` (gcc), `-Wuser-defined-warning` for misuse.
- clang-tidy `cppcoreguidelines-special-member-functions`.

### Architectural fix

Rule of Zero: prefer types whose special member functions can be
compiler-generated (i.e., own through smart pointers, not raw
pointers). Where ownership is shared, use `std::shared_ptr`.

## Operator-validation checklist

- [ ] Build clean
- [ ] Detector flags Rule-of-Three violation in `Owner`
- [ ] ASan run reports double-free
- [ ] Manual Binja UI walkthrough matches
- [ ] Substrate-coherence check via `jm associate`
