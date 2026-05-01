# Path traversal — C++ variant

## Brief

`std::filesystem::path operator/` does **not** canonicalise; `base /
"../etc/passwd"` is preserved literally. The sink (`std::ifstream`)
opens whatever the OS resolves the path to, including outside `base`.

**Difficulty:** `1.0.0`.

## Build / Detection / Remediation

See [`../c/README.md`](../c/README.md). C++-specific remediation:

```cpp
// before
fs::path full = base / name;
std::ifstream in(full);

// after
fs::path full = base / name;
fs::path resolved = fs::weakly_canonical(full);
if (fs::relative(resolved, base).begin()->string() == "..") error;
std::ifstream in(resolved);
```

Stored in [`remediation/vuln.cpp`](remediation/vuln.cpp).

## Operator-validation checklist

- [ ] Build clean
- [ ] Detector flags fs::path / operator path-build without canonicalise
- [ ] PoC reads `/etc/passwd`
- [ ] Manual Binja UI walkthrough matches
- [ ] Substrate-coherence check via `jm associate`
