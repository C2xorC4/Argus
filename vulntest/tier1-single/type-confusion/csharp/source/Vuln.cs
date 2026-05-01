// Tier 1 — type confusion (C# / .NET variant).
//
// Unsafe pointer reinterpretation across types. C# `unsafe` blocks
// allow Marshal.PtrToStructure or raw pointer cast between layouts
// that are not interconvertible — the CLR doesn't validate beyond
// the cast.
//
// Knowledge: [[Memory/Knowledge/ec_undefined_behavior_taxonomy]]
// CWE-843.

using System;
using System.Runtime.InteropServices;

[StructLayout(LayoutKind.Sequential)]
struct A { public int x; public int y; }

[StructLayout(LayoutKind.Sequential)]
struct B { public IntPtr ptr; }

class Vuln {
    static unsafe void Confused(byte[] buf) {
        fixed (byte* p = buf) {
            // sink: reinterpret byte* as B* — pointer comes from int data
            B* b = (B*)p;
            Console.WriteLine($"reinterpreted ptr = {b->ptr.ToInt64():X}");
        }
    }

    static void Main() {
        var a = new A { x = unchecked((int)0xDEADBEEF), y = 0x41414141 };
        byte[] bytes = new byte[Marshal.SizeOf(a)];
        unsafe {
            fixed (byte* dst = bytes) {
                *(A*)dst = a;
            }
        }
        Confused(bytes);
    }
}
