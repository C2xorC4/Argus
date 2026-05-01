# Use-after-free — C++ variant

## Brief

Owning raw pointer (`Resource* res_`) is `delete`d in `close()`
without nulling. A subsequent `heartbeat()` invokes a method on the
dangling pointer. Because `Resource::log()` is called via a normal
(non-virtual) method, the symptom is a read of freed memory; if
`log()` were virtual, the vtable pointer would be the deref site —
yielding a controlled-vtable primitive when the chunk is reused.

This shape (raw owning pointer + manual delete + lingering reference)
is the dominant C++ UAF pattern in production codebases.

**Difficulty:** `1.0.0`.

## Build

```bash
make
make asan
```

## Detection

### Programmatic

Detector: `scripts/analysis/heap.py` — class-field-aware variant of
the C UAF pattern. Looks for `operator delete` / `delete` on a class
field, no follow-up null assignment to that field, and any later
member access through the same field.

Full manifest: [`expected.json`](expected.json).

### Manual (Binary Ninja UI)

1. **Find `operator delete` cross-refs.** Hits inside
   `Manager::close`.
2. **Inspect `Manager::close`.** `delete res_` then function returns;
   `res_` not nulled.
3. **Find reads of `Manager::res_`.** `Manager::heartbeat` reads
   `res_` and dispatches `log()` on it.
4. **Decision point.** Field deleted on one method, used on another,
   no clearing in between.

### Reference

- LJM: `[[Memory/Knowledge/wnapi_heap_internals]]`

## Exploitation

**Primitive class:** UAF method-dispatch → vtable hijack (when
`log()` is virtual; non-virtual reduces to read-of-freed-memory).

**Mitigation considerations.** Same as C variant. Additionally:
- **CFG / CET IBT** — vtable hijack to non-validated target blocked.
- **MS Type Isolation Heap** — chunk reuse limited to same C++ type.

## Chain potential

- [`info-leak → UAF → ROP`](../../../tier2-chains/)

## Remediation

```cpp
// before
Resource* res_ = nullptr;
void close() { delete res_; /* dangling */ }

// after
std::unique_ptr<Resource> res_;
void close() { res_.reset(); }   // guaranteed-null after reset
```

Stored in [`remediation/vuln.cpp`](remediation/vuln.cpp).

### Architectural fix

Replace raw owning pointers with smart pointers (`unique_ptr` for
single ownership, `shared_ptr` for shared, `weak_ptr` for non-owning
references that need to detect destruction). C++ Core Guidelines
R.20 / R.21.

## Operator-validation checklist

- [ ] Build clean
- [ ] Detector finds the bug at `Manager::heartbeat`
- [ ] ASan run reports use-after-free
- [ ] Manual reproduction in Binja UI matches
- [ ] Substrate-coherence check via `jm associate`
