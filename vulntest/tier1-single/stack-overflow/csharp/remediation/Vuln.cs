// Tier 1 — stack-overflow / C# — remediation.
//
// Stay out of `unsafe`. Use Span<byte> stackalloc form which is
// bounds-checked, or System.Buffers / managed arrays.

using System;

class Vuln {
    static void Greet(string name) {
        Span<byte> buf = stackalloc byte[64];
        int n = Math.Min(name.Length, buf.Length);
        for (int i = 0; i < n; i++) buf[i] = (byte)name[i];   // span access bounds-checked
    }

    static int Main(string[] args) {
        if (args.Length < 1) return 1;
        Greet(args[0]);
        return 0;
    }
}
