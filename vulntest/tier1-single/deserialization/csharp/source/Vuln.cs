// Tier 1 — insecure deserialisation (C# / .NET).
//
// BinaryFormatter on attacker-controlled stream. BinaryFormatter is
// notorious for gadget-chain RCE — Microsoft has formally
// deprecated it (NetCore3.0+ marked obsolete; .NET 5+ disabled by
// default but still present).
//
// Knowledge: deserialisation gadget-chain class.
// CWE-502.

using System;
using System.IO;
#pragma warning disable SYSLIB0011  // BinaryFormatter obsolete
using System.Runtime.Serialization.Formatters.Binary;

class Vuln {
    static void Main(string[] args) {
        if (args.Length < 1) { Console.Error.WriteLine("usage"); return; }
        using var fs = File.OpenRead(args[0]);
        var bf = new BinaryFormatter();
        var obj = bf.Deserialize(fs);     // sink: untrusted deserialise
        Console.WriteLine(obj);
    }
}
