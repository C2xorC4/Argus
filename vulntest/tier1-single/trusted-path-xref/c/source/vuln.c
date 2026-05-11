/*
 * Tier 1 — trusted-path-cache-load (xref / v2 variant).
 *
 * Two distinct attacker-writable load patterns:
 *   1) LoadLibraryW from a fixed C:\Users\Public path (Windows
 *      attacker-writable token: \users\public\)
 *   2) fopen from /tmp/ (POSIX attacker-writable token)
 *
 * v2 detector (`analysis.trusted_path` →
 * `find_trusted_path_xref_to_load`) walks SSA defs back from
 * each load call's path argument to a constant pointer, looks
 * up the resolved string, and emits HIGH severity when the
 * literal contains an attacker-writable token. Both patterns
 * here resolve to a single ConstPtr def → the v2 reachability
 * model fires.
 *
 * Build: MSVC via vulntest/build_all.sh (UNICODE on, /MD).
 *
 * Knowledge: [[Memory/Knowledge/eac_eos_arbitrary_write_chain]]
 * CWE-345 (insufficient verification of authenticity), CWE-426
 * (untrusted search path). MITRE T1574.
 */
#include <stdio.h>
#include <windows.h>

static int load_plugin(void) {
    /* attacker-writable Windows path token: \users\public\
       Resolves directly via ConstPtr in MLIL — v2 should fire on
       this LoadLibraryW callsite. */
    HMODULE h = LoadLibraryW(L"C:\\Users\\Public\\plugins\\fast_loader.dll");
    if (!h) return -1;
    FreeLibrary(h);
    return 0;
}

static int read_cache(void) {
    /* attacker-writable POSIX token: /tmp/
       fopen path argument is a const char* literal — v2 should
       fire. */
    FILE *fp = fopen("/tmp/eac/eac_cache.bin", "rb");
    if (!fp) return -1;
    char buf[64];
    fread(buf, 1, sizeof(buf), fp);
    fclose(fp);
    return 0;
}

int main(void) {
    int rc = load_plugin();
    rc |= read_cache();
    return rc;
}
