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
