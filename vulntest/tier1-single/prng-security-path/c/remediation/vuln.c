/*
 * Tier 1 — PRNG / C — remediation.
 *
 * Replace rand() with /dev/urandom (POSIX) or BCryptGenRandom
 * (Windows). Both are CSPRNGs.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
  #include <windows.h>
  #include <bcrypt.h>
  static int csprng_bytes(void *buf, size_t n) {
      NTSTATUS s = BCryptGenRandom(NULL, (PUCHAR)buf, (ULONG)n,
                                   BCRYPT_USE_SYSTEM_PREFERRED_RNG);
      return s == 0 ? 0 : -1;
  }
#else
  #include <fcntl.h>
  #include <unistd.h>
  static int csprng_bytes(void *buf, size_t n) {
      int fd = open("/dev/urandom", O_RDONLY);
      if (fd < 0) return -1;
      ssize_t r = read(fd, buf, n);
      close(fd);
      return ((size_t)r == n) ? 0 : -1;
  }
#endif

void issue_token(char *out, size_t n) {
    unsigned char raw[64];
    if (n > sizeof(raw) / 2 + 1) n = sizeof(raw) / 2 + 1;
    if (csprng_bytes(raw, (n - 1) / 2) != 0) { out[0] = 0; return; }
    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < (n - 1) / 2; ++i) {
        out[i * 2]     = hex[raw[i] >> 4];
        out[i * 2 + 1] = hex[raw[i] & 0xF];
    }
    out[n - 1] = 0;
}

int main(void) {
    char token[33];
    issue_token(token, sizeof(token));
    printf("session=%s\n", token);
    return 0;
}
