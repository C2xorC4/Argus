/*
 * Tier 1 — trusted-path-cache-load remediation.
 *
 * Same shape as `source/vuln.c` but with trusted, system-owned
 * load paths. v2 should NOT fire — neither path string contains
 * an attacker-writable token.
 */
#include <stdio.h>
#include <windows.h>

static int load_plugin(void) {
    HMODULE h = LoadLibraryW(L"C:\\Windows\\System32\\version.dll");
    if (!h) return -1;
    FreeLibrary(h);
    return 0;
}

static int read_cache(void) {
    FILE *fp = fopen("C:\\Program Files\\eac\\eac_cache.bin", "rb");
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
