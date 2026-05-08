import struct
import sys

data = open(sys.argv[1], 'rb').read()
i = 0
def u2():
    global i; v = struct.unpack('>H', data[i:i+2])[0]; i += 2; return v
def u1():
    global i; v = data[i]; i += 1; return v
def u4():
    global i; v = struct.unpack('>I', data[i:i+4])[0]; i += 4; return v

u4(); u2(); u2()
cp_count = u2()
cp = [None]
j = 1
while j < cp_count:
    tag = u1()
    if tag == 1:
        length = u2()
        s = data[i:i+length].decode('utf-8', errors='replace'); i += length
        cp.append(('UTF8', s))
    elif tag == 7: cp.append(('Class', u2()))
    elif tag == 9: cp.append(('Fieldref', u2(), u2()))
    elif tag == 10: cp.append(('Methodref', u2(), u2()))
    elif tag == 11: cp.append(('IfMethodref', u2(), u2()))
    elif tag == 8: cp.append(('String', u2()))
    elif tag == 3: cp.append(('Integer', u4()))
    elif tag == 4: cp.append(('Float', u4()))
    elif tag == 5: cp.append(('Long', u4(), u4())); cp.append(None); j += 1
    elif tag == 6: cp.append(('Double', u4(), u4())); cp.append(None); j += 1
    elif tag == 12: cp.append(('NameAndType', u2(), u2()))
    elif tag == 15: cp.append(('MethodHandle', u1(), u2()))
    elif tag == 16: cp.append(('MethodType', u2()))
    elif tag == 18: cp.append(('InvokeDynamic', u2(), u2()))
    j += 1

u2(); u2(); u2()
n_ifs = u2()
for _ in range(n_ifs): u2()
n_fields = u2()
for _ in range(n_fields):
    u2(); u2(); u2()
    n_attrs = u2()
    for _ in range(n_attrs):
        u2(); attr_len = u4(); i += attr_len

opnames = {0x00: 'nop', 0x01: 'aconst_null',
           0x02: 'iconst_m1', 0x03: 'iconst_0', 0x04: 'iconst_1', 0x05: 'iconst_2',
           0x06: 'iconst_3', 0x07: 'iconst_4', 0x08: 'iconst_5',
           0x10: 'bipush', 0x11: 'sipush', 0x12: 'ldc', 0x13: 'ldc_w', 0x14: 'ldc2_w',
           0x15: 'iload', 0x19: 'aload', 0x1a: 'iload_0', 0x1b: 'iload_1', 0x1c: 'iload_2', 0x1d: 'iload_3',
           0x2a: 'aload_0', 0x2b: 'aload_1', 0x2c: 'aload_2', 0x2d: 'aload_3',
           0x36: 'istore', 0x3a: 'astore', 0x3b: 'istore_0', 0x3c: 'istore_1', 0x3d: 'istore_2', 0x3e: 'istore_3',
           0x4b: 'astore_0', 0x4c: 'astore_1', 0x4d: 'astore_2', 0x4e: 'astore_3',
           0x60: 'iadd', 0x64: 'isub', 0x68: 'imul', 0x6c: 'idiv',
           0x82: 'ixor', 0x80: 'ior', 0x7e: 'iand',
           0x91: 'i2b', 0x93: 'i2s', 0x92: 'i2c', 0x84: 'iinc',
           0x99: 'ifeq', 0x9a: 'ifne', 0x9b: 'iflt', 0x9c: 'ifge', 0x9d: 'ifgt', 0x9e: 'ifle',
           0x9f: 'if_icmpeq', 0xa0: 'if_icmpne', 0xa1: 'if_icmplt', 0xa2: 'if_icmpge', 0xa3: 'if_icmpgt', 0xa4: 'if_icmple',
           0xa7: 'goto', 0xac: 'ireturn', 0xad: 'lreturn', 0xae: 'freturn', 0xaf: 'dreturn', 0xb0: 'areturn', 0xb1: 'return',
           0xb6: 'invokevirtual', 0xb7: 'invokespecial', 0xb8: 'invokestatic', 0xb9: 'invokeinterface',
           0xba: 'invokedynamic', 0xbb: 'new', 0xbc: 'newarray', 0xbd: 'anewarray',
           0xb2: 'getstatic', 0xb5: 'putfield', 0xb3: 'putstatic', 0xb4: 'getfield',
           0xc6: 'ifnull', 0xc7: 'ifnonnull',
           0x59: 'dup', 0x57: 'pop', 0x32: 'aaload', 0x53: 'aastore', 0x33: 'baload', 0x54: 'bastore',
           0xbe: 'arraylength', 0xc0: 'checkcast'}

n_methods = u2()
for _ in range(n_methods):
    flags = u2(); name_idx = u2(); desc_idx = u2()
    name = cp[name_idx][1]; desc = cp[desc_idx][1]
    print(f'\n=== method {name} {desc} ===')
    n_attrs = u2()
    for _ in range(n_attrs):
        attr_name_idx = u2()
        attr_len = u4()
        attr_name = cp[attr_name_idx][1]
        if attr_name == 'Code':
            max_stack = u2(); max_locals = u2()
            code_len = u4()
            code = data[i:i+code_len]
            i += code_len
            ci = 0
            while ci < code_len:
                op = code[ci]
                opname = opnames.get(op, f'op_{op:02x}')
                if op == 0x10:
                    arg = struct.unpack('>b', code[ci+1:ci+2])[0]
                    print(f'    {ci:4d}: {opname} {arg}')
                    ci += 2
                elif op == 0x12:
                    arg = code[ci+1]
                    extra = ''
                    if arg < len(cp) and cp[arg]:
                        ent = cp[arg]
                        if ent[0] == 'String':
                            extra = f" -> {cp[ent[1]][1]!r}"
                        elif ent[0] == 'Integer':
                            extra = f" = {ent[1]}"
                    print(f'    {ci:4d}: {opname} {arg}{extra}')
                    ci += 2
                elif op == 0x11:
                    arg = struct.unpack('>h', code[ci+1:ci+3])[0]
                    print(f'    {ci:4d}: {opname} {arg}')
                    ci += 3
                elif op in (0xb6, 0xb7, 0xb8, 0xbb, 0xbd, 0xb2, 0xb3, 0xb4, 0xb5, 0x13, 0x14, 0x9f, 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0xa7, 0xc6, 0xc7, 0xc0):
                    arg = struct.unpack('>H', code[ci+1:ci+3])[0]
                    extra = ''
                    if op in (0xb6, 0xb7, 0xb8) and arg < len(cp) and cp[arg]:
                        ent = cp[arg]
                        if ent[0] == 'Methodref':
                            cls = cp[cp[ent[1]][1]][1]
                            nat = cp[ent[2]]
                            extra = f' -> {cls}.{cp[nat[1]][1]}{cp[nat[2]][1]}'
                    elif op == 0xb2 and arg < len(cp) and cp[arg]:
                        ent = cp[arg]
                        if ent[0] == 'Fieldref':
                            cls = cp[cp[ent[1]][1]][1]
                            nat = cp[ent[2]]
                            extra = f' -> {cls}.{cp[nat[1]][1]}{cp[nat[2]][1]}'
                    elif op == 0x13 and arg < len(cp) and cp[arg]:
                        ent = cp[arg]
                        if ent[0] == 'String':
                            extra = f" -> {cp[ent[1]][1]!r}"
                    print(f'    {ci:4d}: {opname} {arg}{extra}')
                    ci += 3
                elif op == 0xb9:
                    arg = struct.unpack('>H', code[ci+1:ci+3])[0]
                    extra = ''
                    if arg < len(cp) and cp[arg]:
                        ent = cp[arg]
                        if ent[0] == 'IfMethodref':
                            cls = cp[cp[ent[1]][1]][1]
                            nat = cp[ent[2]]
                            extra = f' -> {cls}.{cp[nat[1]][1]}{cp[nat[2]][1]}'
                    print(f'    {ci:4d}: {opname} {arg}{extra}')
                    ci += 5
                elif op == 0xba:
                    arg = struct.unpack('>H', code[ci+1:ci+3])[0]
                    print(f'    {ci:4d}: {opname} {arg}')
                    ci += 5
                elif op == 0x84:
                    print(f'    {ci:4d}: iinc {code[ci+1]} {struct.unpack(">b", code[ci+2:ci+3])[0]}')
                    ci += 3
                elif op in (0x15, 0x19, 0x36, 0x3a):
                    print(f'    {ci:4d}: {opname} {code[ci+1]}')
                    ci += 2
                elif op == 0xbc:
                    print(f'    {ci:4d}: newarray {code[ci+1]}')
                    ci += 2
                else:
                    print(f'    {ci:4d}: {opname}')
                    ci += 1
            n_excs = u2(); i += n_excs * 8
            n_code_attrs = u2()
            for _ in range(n_code_attrs):
                u2(); a = u4(); i += a
        else:
            i += attr_len
