
Unhandled Exception:
System.InvalidOperationException: Operation is not valid due to the current state of the object.
  at IKVM.Reflection.Metadata.ConstantTable.GetRawConstantValue (IKVM.Reflection.Module module, System.Int32 parent) [0x0019a] in <c5505d5636384aba85504c391449e469>:0 
  at IKVM.Reflection.Reader.FieldDefImpl.GetRawConstantValue () [0x00017] in <c5505d5636384aba85504c391449e469>:0 
  at Ildasm.Disassembler.WriteField (Ildasm.LineWriter lw, IKVM.Reflection.FieldInfo field) [0x00203] in <c5505d5636384aba85504c391449e469>:0 
  at Ildasm.Disassembler.WriteType (Ildasm.LineWriter lw, IKVM.Reflection.Type type) [0x004f8] in <c5505d5636384aba85504c391449e469>:0 
  at Ildasm.Disassembler.WriteTypes (Ildasm.LineWriter lw) [0x00043] in <c5505d5636384aba85504c391449e469>:0 
  at Ildasm.Disassembler.Save (System.IO.TextWriter writer) [0x0008b] in <c5505d5636384aba85504c391449e469>:0 
  at Ildasm.Program.Main (System.String[] args) [0x00480] in <c5505d5636384aba85504c391449e469>:0 
[ERROR] FATAL UNHANDLED EXCEPTION: System.InvalidOperationException: Operation is not valid due to the current state of the object.
  at IKVM.Reflection.Metadata.ConstantTable.GetRawConstantValue (IKVM.Reflection.Module module, System.Int32 parent) [0x0019a] in <c5505d5636384aba85504c391449e469>:0 
  at IKVM.Reflection.Reader.FieldDefImpl.GetRawConstantValue () [0x00017] in <c5505d5636384aba85504c391449e469>:0 
  at Ildasm.Disassembler.WriteField (Ildasm.LineWriter lw, IKVM.Reflection.FieldInfo field) [0x00203] in <c5505d5636384aba85504c391449e469>:0 
  at Ildasm.Disassembler.WriteType (Ildasm.LineWriter lw, IKVM.Reflection.Type type) [0x004f8] in <c5505d5636384aba85504c391449e469>:0 
  at Ildasm.Disassembler.WriteTypes (Ildasm.LineWriter lw) [0x00043] in <c5505d5636384aba85504c391449e469>:0 
  at Ildasm.Disassembler.Save (System.IO.TextWriter writer) [0x0008b] in <c5505d5636384aba85504c391449e469>:0 
  at Ildasm.Program.Main (System.String[] args) [0x00480] in <c5505d5636384aba85504c391449e469>:0 
                               00 ) 
  .custom instance void [mscorlib]System.Reflection.AssemblyCopyrightAttribute::.ctor(string) = ( 01 00 12 43 6F 70 79 72 69 67 68 74 20 C2 A9 20   // ...Copyright .. 
                                                                                                  20 32 30 31 39 00 00 )                            //  2019..
  .custom instance void [mscorlib]System.Runtime.CompilerServices.RuntimeCompatibilityAttribute::.ctor() = ( 01 00 01 00 54 02 16 57 72 61 70 4E 6F 6E 45 78   // ....T..WrapNonEx
                                                                                                             63 65 70 74 69 6F 6E 54 68 72 6F 77 73 01 )       // ceptionThrows.
  .custom instance void [mscorlib]System.Runtime.InteropServices.GuidAttribute::.ctor(string) = ( 01 00 24 35 30 38 39 32 32 36 66 2D 31 32 62 36   // ..$5089226f-12b6
                                                                                                  2D 34 30 35 30 2D 39 63 65 33 2D 66 37 63 34 33   // -4050-9ce3-f7c43
                                                                                                  37 32 31 61 35 61 32 00 00 )                      // 721a5a2..
  .custom instance void [mscorlib]System.Reflection.AssemblyFileVersionAttribute::.ctor(string) = ( 01 00 07 31 2E 30 2E 30 2E 30 00 00 )             // ...1.0.0.0..
  .custom instance void [mscorlib]System.Reflection.AssemblyTitleAttribute::.ctor(string) = ( 01 00 0C 48 54 42 43 68 61 6C 6C 61 6E 67 65 00   // ...HTBChallange.
                                                                                              00 ) 
  .hash algorithm 0x00008004
  .ver 1:0:0:0
}
.mresource private '0'
{
  // Offset: 0x00000000 Length: 0x00000650
  // WARNING: managed resource file '0' created
}
.module HTBChallange.exe
// MVID: {4B13835A-6F14-4740-B5E0-426A4B735535}
.imagebase 0x00400000
.file alignment 0x00000200
.stackreserve 0x00100000
.subsystem 0x0003       // WINDOWS_CUI
.corflags 0x00020003    //  ILONLY 32BITREQUIRED


// ================== GLOBAL METHODS =========================

.method privatescope specialname rtspecialname static 
        void  '.cctor$PST06000001'() cil managed
{
  // Code size       6 (0x6)
  .maxstack  8
  IL_0000:  call       void '5'::'0'()
  IL_0005:  ret
} // end of global method .cctor


// =============================================================


// =============== CLASS MEMBERS DECLARATION ===================

.class public auto ansi beforefieldinit '0'
       extends [mscorlib]System.Object
{
  .field public static string '0'
  .field public static string '1'
  .field public static string '2'
  .method public hidebysig static void  '0'() cil managed
  {
    .entrypoint
    // Code size       42 (0x2a)
    .maxstack  1
    .locals init (bool V_0,
             bool V_1)
    IL_0000:  nop
    IL_0001:  call       bool '0'::'1'()
    IL_0006:  stloc.0
    IL_0007:  ldloc.0
    IL_0008:  stloc.1
    IL_0009:  ldloc.1
    IL_000a:  brfalse.s  IL_0016

    IL_000c:  nop
    IL_000d:  call       void '0'::'2'()
    IL_0012:  nop
    IL_0013:  nop
    IL_0014:  br.s       IL_0029

    IL_0016:  nop
    IL_0017:  ldsfld     string '5'::'0'
    IL_001c:  call       void [mscorlib]System.Console::WriteLine(string)
    IL_0021:  nop
    IL_0022:  call       void '0'::'0'()
    IL_0027:  nop
    IL_0028:  nop
    IL_0029:  ret
  } // end of method '0'::'0'

  .method public hidebysig static bool  '1'() cil managed
  {
    // Code size       41 (0x29)
    .maxstack  1
    .locals init (string V_0,
             string V_1,
             bool V_2)
    IL_0000:  nop
    IL_0001:  ldsfld     string '5'::'1'
    IL_0006:  call       void [mscorlib]System.Console::Write(string)
    IL_000b:  nop
    IL_000c:  call       string [mscorlib]System.Console::ReadLine()
    IL_0011:  stloc.0
    IL_0012:  ldsfld     string '5'::'2'
    IL_0017:  call       void [mscorlib]System.Console::Write(string)
    IL_001c:  nop
    IL_001d:  call       string [mscorlib]System.Console::ReadLine()
    IL_0022:  stloc.1
    IL_0023:  ldc.i4.0
    IL_0024:  stloc.2
    IL_0025:  br.s       IL_0027

    IL_0027:  ldloc.2
    IL_0028:  ret
  } // end of method '0'::'1'

  .method public hidebysig static void  '2'() cil managed
  {
    // Code size       85 (0x55)
    .maxstack  3
    .locals init (string V_0,
             string V_1,
             bool V_2)
    IL_0000:  nop
    IL_0001:  ldsfld     string '5'::'3'
    IL_0006:  stloc.0
    IL_0007:  ldsfld     string '5'::'4'
    IL_000c:  call       void [mscorlib]System.Console::Write(string)
    IL_0011:  nop
    IL_0012:  call       string [mscorlib]System.Console::ReadLine()
    IL_0017:  stloc.1
    IL_0018:  ldloc.0
    IL_0019:  ldloc.1
    IL_001a:  call       bool [mscorlib]System.String::op_Equality(string,
                                                                   string)
    IL_001f:  stloc.2
    IL_0020:  ldloc.2
    IL_0021:  brfalse.s  IL_0041

    IL_0023:  nop
    IL_0024:  ldsfld     string '5'::'5'
    IL_0029:  ldsfld     string '0'::'2'
    IL_002e:  ldsfld     string '5'::'6'
    IL_0033:  call       string [mscorlib]System.String::Concat(string,
                                                                string,
                                                                string)
    IL_0038:  call       void [mscorlib]System.Console::Write(string)
    IL_003d:  nop
    IL_003e:  nop
    IL_003f:  br.s       IL_0054

    IL_0041:  nop
    IL_0042:  ldsfld     string '5'::'7'
    IL_0047:  call       void [mscorlib]System.Console::WriteLine(string)
    IL_004c:  nop
    IL_004d:  call       void '0'::'2'()
    IL_0052:  nop
    IL_0053:  nop
    IL_0054:  ret
  } // end of method '0'::'2'

  .method public hidebysig specialname rtspecialname 
          instance void  .ctor() cil managed
  {
    // Code size       8 (0x8)
    .maxstack  8
    IL_0000:  ldarg.0
    IL_0001:  call       instance void [mscorlib]System.Object::.ctor()
    IL_0006:  nop
    IL_0007:  ret
  } // end of method '0'::.ctor

  .method private hidebysig specialname rtspecialname static 
          void  .cctor() cil managed
  {
    // Code size       11 (0xb)
    .maxstack  8
    IL_0000:  ldsfld     string '5'::'8'
    IL_0005:  stsfld     string '0'::'2'
    IL_000a:  ret
  } // end of method '0'::.cctor

} // end of class '0'

.class public auto ansi '1'
       extends [mscorlib]System.Attribute
{
  .custom instance void [mscorlib]System.AttributeUsageAttribute::.ctor([mscorlib]System.AttributeTargets) = ( 01 00 05 00 00 00 00 00 ) 
  .field public string '0'
  .method public specialname rtspecialname 
          instance void  .ctor() cil managed
  {
    // Code size       20 (0x14)
    .maxstack  8
    IL_0000:  ldarg.0
    IL_0001:  call       instance void [mscorlib]System.Object::.ctor()
    IL_0006:  nop
    IL_0007:  ldarg.0
    IL_0008:  ldsfld     string '5'::'9'
    IL_000d:  stfld      string '1'::'0'
    IL_0012:  nop
    IL_0013:  ret
  } // end of method '1'::.ctor

} // end of class '1'

.class public auto ansi '2'
       extends [mscorlib]System.Attribute
{
  .custom instance void [mscorlib]System.AttributeUsageAttribute::.ctor([mscorlib]System.AttributeTargets) = ( 01 00 05 00 00 00 00 00 ) 
  .field public string '0'
  .method public specialname rtspecialname 
          instance void  .ctor() cil managed
  {
    // Code size       20 (0x14)
    .maxstack  8
    IL_0000:  ldarg.0
    IL_0001:  call       instance void [mscorlib]System.Object::.ctor()
    IL_0006:  nop
    IL_0007:  ldarg.0
    IL_0008:  ldsfld     string '5'::a
    IL_000d:  stfld      string '2'::'0'
    IL_0012:  nop
    IL_0013:  ret
  } // end of method '2'::.ctor

} // end of class '2'

.class public auto ansi '3'
       extends [mscorlib]System.Attribute
{
  .custom instance void [mscorlib]System.AttributeUsageAttribute::.ctor([mscorlib]System.AttributeTargets) = ( 01 00 05 00 00 00 00 00 ) 
  .field public string '0'
  .method public specialname rtspecialname 
          instance void  .ctor() cil managed
  {
    // Code size       20 (0x14)
    .maxstack  8
    IL_0000:  ldarg.0
    IL_0001:  call       instance void [mscorlib]System.Object::.ctor()
    IL_0006:  nop
    IL_0007:  ldarg.0
    IL_0008:  ldsfld     string '5'::b
    IL_000d:  stfld      string '3'::'0'
    IL_0012:  nop
    IL_0013:  ret
  } // end of method '3'::.ctor

} // end of class '3'

.class public auto ansi '4'
       extends [mscorlib]System.Attribute
{
  .custom instance void [mscorlib]System.AttributeUsageAttribute::.ctor([mscorlib]System.AttributeTargets) = ( 01 00 05 00 00 00 00 00 ) 
  .field public string '0'
  .method public specialname rtspecialname 
          instance void  .ctor() cil managed
  {
    // Code size       20 (0x14)
    .maxstack  8
    IL_0000:  ldarg.0
    IL_0001:  call       instance void [mscorlib]System.Object::.ctor()
    IL_0006:  nop
    IL_0007:  ldarg.0
    IL_0008:  ldsfld     string '5'::c
    IL_000d:  stfld      string '4'::'0'
    IL_0012:  nop
    IL_0013:  ret
  } // end of method '4'::.ctor

} // end of class '4'

.class private abstract auto ansi sealed '5'
       extends [mscorlib]System.Object
{
  .field static assembly string '0'
  .field static assembly string '1'
  .field static assembly string '2'
  .field static assembly string '3'
  .field static assembly string '4'
  .field static assembly string '5'
  .field static assembly string '6'
  .field static assembly string '7'
  .field static assembly string '8'
  .field static assembly string '9'
  .field static assembly string a
  .field static assembly string b
  .field static assembly string c
  .method public static void  '0'() cil managed
  {
    // Code size       170 (0xaa)
    .maxstack  2
    IL_0000:  call       [mscorlib]System.Reflection.Assembly [mscorlib]System.Reflection.Assembly::GetExecutingAssembly()
    IL_0005:  ldstr      "0"
    IL_000a:  callvirt   instance [mscorlib]System.IO.Stream [mscorlib]System.Reflection.Assembly::GetManifestResourceStream(string)
    IL_000f:  call       uint8[] '7'::'3'([mscorlib]System.IO.Stream)
    IL_0014:  newobj     instance void '6'::.ctor(uint8[])
    IL_0019:  dup
    IL_001a:  call       instance string '6'::'6'()
    IL_001f:  stsfld     string '5'::'0'
    IL_0024:  dup
    IL_0025:  call       instance string '6'::'6'()
    IL_002a:  stsfld     string '5'::'1'
    IL_002f:  dup
    IL_0030:  call       instance string '6'::'6'()
    IL_0035:  stsfld     string '5'::'2'
    IL_003a:  dup
    IL_003b:  call       instance string '6'::'6'()
    IL_0040:  stsfld     string '5'::'3'
    IL_0045:  dup
    IL_0046:  call       instance string '6'::'6'()
    IL_004b:  stsfld     string '5'::'4'
    IL_0050:  dup
    IL_0051:  call       instance string '6'::'6'()
    IL_0056:  stsfld     string '5'::'5'
    IL_005b:  dup
    IL_005c:  call       instance string '6'::'6'()
    IL_0061:  stsfld     string '5'::'6'
    IL_0066:  dup
    IL_0067:  call       instance string '6'::'6'()
    IL_006c:  stsfld     string '5'::'7'
    IL_0071:  dup
    IL_0072:  call       instance string '6'::'6'()
    IL_0077:  stsfld     string '5'::'8'
    IL_007c:  dup
    IL_007d:  call       instance string '6'::'6'()
    IL_0082:  stsfld     string '5'::'9'
    IL_0087:  dup
    IL_0088:  call       instance string '6'::'6'()
    IL_008d:  stsfld     string '5'::a
    IL_0092:  dup
    IL_0093:  call       instance string '6'::'6'()
    IL_0098:  stsfld     string '5'::b
    IL_009d:  dup
    IL_009e:  call       instance string '6'::'6'()
    IL_00a3:  stsfld     string '5'::c
    IL_00a8:  pop
    IL_00a9:  ret
  } // end of method '5'::'0'

} // end of class '5'

.class private auto ansi beforefieldinit '6'
       extends [mscorlib]System.Object
{
  .field private initonly [mscorlib]System.IO.BinaryReader '0'
  .method public hidebysig specialname rtspecialname 
          instance void  .ctor([mscorlib]System.IO.Stream '0') cil managed
  {
    // Code size       24 (0x18)
    .maxstack  8
    IL_0000:  ldarg.0
    IL_0001:  call       instance void [mscorlib]System.Object::.ctor()
    IL_0006:  ldarg.0
    IL_0007:  ldarg.1
    IL_0008:  call       [mscorlib]System.Text.Encoding [mscorlib]System.Text.Encoding::get_Unicode()
    IL_000d:  newobj     instance void [mscorlib]System.IO.BinaryReader::.ctor([mscorlib]System.IO.Stream,
                                                                               [mscorlib]System.Text.Encoding)
    IL_0012:  stfld      [mscorlib]System.IO.BinaryReader '6'::'0'
    IL_0017:  ret
  } // end of method '6'::.ctor

  .method public hidebysig specialname rtspecialname 
          instance void  .ctor(uint8[] '0') cil managed
  {
    // Code size       13 (0xd)
    .maxstack  8
    IL_0000:  ldarg.0
    IL_0001:  ldarg.1
    IL_0002:  newobj     instance void [mscorlib]System.IO.MemoryStream::.ctor(uint8[])
    IL_0007:  call       instance void '6'::.ctor([mscorlib]System.IO.Stream)
    IL_000c:  ret
  } // end of method '6'::.ctor

  .method public hidebysig instance string 
          '6'() cil managed
  {
    // Code size       12 (0xc)
    .maxstack  8
    IL_0000:  ldarg.0
    IL_0001:  ldfld      [mscorlib]System.IO.BinaryReader '6'::'0'
    IL_0006:  callvirt   instance string [mscorlib]System.IO.BinaryReader::ReadString()
    IL_000b:  ret
  } // end of method '6'::'6'

  .method public hidebysig instance int8 
          '7'() cil managed
  {
    // Code size       12 (0xc)
    .maxstack  8
    IL_0000:  ldarg.0
    IL_0001:  ldfld      [mscorlib]System.IO.BinaryReader '6'::'0'
    IL_0006:  callvirt   instance int8 [mscorlib]System.IO.BinaryReader::ReadSByte()
    IL_000b:  ret
  } // end of method '6'::'7'

  .method public hidebysig instance int32 
          '8'() cil managed
  {
    // Code size       12 (0xc)
    .maxstack  8
    IL_0000:  ldarg.0
    IL_0001:  ldfld      [mscorlib]System.IO.BinaryReader '6'::'0'
    IL_0006:  callvirt   instance int32 [mscorlib]System.IO.BinaryReader::ReadInt32()
    IL_000b:  ret
  } // end of method '6'::'8'

  .method public hidebysig instance int64 
          '9'() cil managed
  {
    // Code size       12 (0xc)
    .maxstack  8
    IL_0000:  ldarg.0
    IL_0001:  ldfld      [mscorlib]System.IO.BinaryReader '6'::'0'
    IL_0006:  callvirt   instance int64 [mscorlib]System.IO.BinaryReader::ReadInt64()
    IL_000b:  ret
  } // end of method '6'::'9'

  .method public hidebysig instance float32 
          a() cil managed
  {
    // Code size       12 (0xc)
    .maxstack  8
    IL_0000:  ldarg.0
    IL_0001:  ldfld      [mscorlib]System.IO.BinaryReader '6'::'0'
    IL_0006:  callvirt   instance float32 [mscorlib]System.IO.BinaryReader::ReadSingle()
    IL_000b:  ret
  } // end of method '6'::a

  .method public hidebysig instance float64 
          b() cil managed
  {
    // Code size       12 (0xc)
    .maxstack  8
    IL_0000:  ldarg.0
    IL_0001:  ldfld      [mscorlib]System.IO.BinaryReader '6'::'0'
    IL_0006:  callvirt   instance float64 [mscorlib]System.IO.BinaryReader::ReadDouble()
    IL_000b:  ret
  } // end of method '6'::b

} // end of class '6'

.class public abstract auto ansi sealed beforefieldinit '7'
       extends [mscorlib]System.Object
{
