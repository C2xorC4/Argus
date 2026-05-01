# Command injection — C++ variant

## Brief

C++ shape uses `std::string` concatenation but the sink is the same
`std::system`. Detection difference: the format-string-style
construction is replaced by a `std::string operator+` chain, so
heuristics must follow std::string-build patterns.

**Difficulty:** `1.0.0`.

## Build / Detection / Remediation

See [`../c/README.md`](../c/README.md). C++-specific architectural
fix:

```cpp
// before
std::system(("cp " + filename + " /tmp/backup/").c_str());

// after — explicit argv via posix_spawn / fork+execl
execl("/bin/cp", "cp", filename.c_str(), "/tmp/backup/", nullptr);
```

Stored in [`remediation/vuln.cpp`](remediation/vuln.cpp).

## Operator-validation checklist

- [ ] Build clean
- [ ] Detector flags `std::system` with tainted concatenated argument
- [ ] PoC creates `/tmp/argus_pwn`
- [ ] Manual Binja UI walkthrough matches
- [ ] Substrate-coherence check via `jm associate`
