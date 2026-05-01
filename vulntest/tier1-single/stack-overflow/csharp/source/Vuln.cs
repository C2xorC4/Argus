// Tier 1 — stack-overflow (C# / .NET variant).
//
// `unsafe` block + `stackalloc` + raw pointer write past the end of
// the buffer. The CLR does not bounds-check raw pointer arithmetic
// inside an unsafe block — it's identical to C semantics, just
// scoped within the unsafe region.
//
// Knowledge: [[Memory/Knowledge/hw_stack_overflow_mechanics]]
// CWE-121.
//
// Build: csc Vuln.cs /unsafe
// Run:   Vuln.exe AAAAAAAA...

using System;

class Vuln {
    static unsafe void Greet(string name) {
        byte* buf = stackalloc byte[64];
        int i = 0;
        foreach (char c in name) {
            buf[i++] = (byte)c;          // sink: no bound on i
        }
    }

    static int Main(string[] args) {
        if (args.Length < 1) { Console.Error.WriteLine("usage"); return 1; }
        Greet(args[0]);
        return 0;
    }
}
