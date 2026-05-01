# TOCTOU — C++ variant

## Brief

`std::filesystem::exists(p)` check followed by `std::ifstream(p)`
open. Two filesystem-resolution calls on the same path; the race
window is between them.

**Difficulty:** `1.0.0`.

See [`../c/README.md`](../c/README.md) for the full mechanics.

## Remediation

C++ standard library lacks O_NOFOLLOW; drop to platform open():

```cpp
int fd = open(path, O_RDONLY | O_NOFOLLOW);
struct stat st; fstat(fd, &st);
FILE* fp = fdopen(fd, "r");
```

Stored in [`remediation/vuln.cpp`](remediation/vuln.cpp).

## Operator-validation checklist

- [ ] Build clean
- [ ] Detector flags fs::exists + ifstream open of same path
- [ ] PoC observes `ATTACKER_TARGET` output
- [ ] Manual Binja UI walkthrough matches
- [ ] Substrate-coherence check via `jm associate`
