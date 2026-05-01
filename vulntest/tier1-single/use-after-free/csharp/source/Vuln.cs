// Tier 1 — use-after-free analog (C# / .NET).
//
// CLR objects are GC-managed, so classical UAF (free + use) doesn't
// happen in pure managed code. The C# UAF analog is "use after
// Dispose": IDisposable.Dispose() releases unmanaged resources;
// any subsequent method call on the disposed object operates on
// freed unmanaged state.
//
// Knowledge: [[Memory/Knowledge/wnapi_heap_internals]]
// CWE-416 (analog).

using System;
using System.IO;

class Vuln {
    static void Main(string[] args) {
        var fs = new FileStream("/tmp/argus_demo.txt", FileMode.OpenOrCreate);
        fs.Dispose();
        // sink: use after dispose — calls into freed unmanaged
        // resources (file handle is closed)
        try {
            fs.WriteByte(0x41);
        } catch (ObjectDisposedException) {
            Console.Error.WriteLine("ODE — runtime caught");
        }
    }
}
