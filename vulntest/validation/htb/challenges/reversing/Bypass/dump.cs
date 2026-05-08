using System;
using System.Reflection;

class Dump {
    static void Main(string[] args) {
        var asm = Assembly.LoadFile(System.IO.Path.GetFullPath(args[0]));
        // Find class '5' and call its static '0' method (the cctor that decrypts and stores strings)
        var t5 = asm.GetType("5");
        if (t5 == null) {
            // Anonymous type names use raw bytes, try alternatives
            foreach (var t in asm.GetTypes()) {
                Console.WriteLine($"type: {t.Name}");
            }
            return;
        }
        var init = t5.GetMethod("0", BindingFlags.Public | BindingFlags.Static);
        Console.WriteLine($"Calling 5.0() ...");
        init.Invoke(null, null);
        // Now read each static field from class 5
        foreach (var f in t5.GetFields(BindingFlags.NonPublic | BindingFlags.Public | BindingFlags.Static)) {
            var val = f.GetValue(null);
            Console.WriteLine($"  5.{f.Name} = {val}");
        }
        // Also read 0.2 (initialized from 5.8 by 0.cctor)
        var t0 = asm.GetType("0");
        if (t0 != null) {
            foreach (var f in t0.GetFields(BindingFlags.NonPublic | BindingFlags.Public | BindingFlags.Static)) {
                var val = f.GetValue(null);
                Console.WriteLine($"  0.{f.Name} = {val}");
            }
        }
    }
}
