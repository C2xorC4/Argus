#!/usr/bin/env python3
"""Simulate the vvm bytecode interpreter to recover the password."""

import struct
import sys
from pathlib import Path

BINARY = Path(r"D:\Repos\Security\Argus\vulntest\validation\htb\challenges\reversing\vvm\rev_vvm\vvm")
IMAGE_BASE = 0x400000
BC_BASE_VA = 0x405540


def vfo(va):
    return va - IMAGE_BASE - 0x4d70 + 0x3d70


def load_bytecode():
    data = BINARY.read_bytes()
    off = vfo(BC_BASE_VA)
    words = []
    sz = 0x4000
    for i in range(sz // 4):
        if off + i * 4 + 4 > len(data):
            break
        w = struct.unpack_from("<i", data, off + i * 4)[0]
        words.append(w)
    return words


# Stack values are 64-bit. Strings are represented as bytes objects.

def to_signed64(v):
    v &= (1 << 64) - 1
    if v & (1 << 63):
        v -= (1 << 64)
    return v


def to_uint64(v):
    return v & ((1 << 64) - 1)


class VM:
    def __init__(self, bytecode_words, input_str: bytes = b"", trace=False):
        self.bc = bytecode_words
        self.pc = 0  # word index, not byte offset (each instr/imm is 1 word)
        self.stack = []  # python list as stack of values (ints or bytes)
        self.input_buf = input_str
        self.input_pos = 0  # how much consumed
        self.output = []
        self.trace = trace
        self.steps = 0
        self.max_steps = 5_000_000

    def fetch(self):
        v = self.bc[self.pc]
        self.pc += 1
        return v

    def push(self, v):
        self.stack.append(v)

    def pop(self):
        return self.stack.pop()

    def peek(self, depth=1):
        return self.stack[-depth]

    def t(self, msg):
        if self.trace:
            print(f"  [pc={self.pc:4} sp={len(self.stack):3}] {msg}")

    def run(self, until_halt=True):
        while True:
            if self.steps >= self.max_steps:
                raise RuntimeError("step limit")
            self.steps += 1
            if self.pc >= len(self.bc):
                if self.trace: print(" ... ran off end")
                return
            op = self.fetch()
            if op == 0x1c:  # HALT
                if self.trace: print(f"  HALT @pc={self.pc-1}")
                return
            self.exec_op(op)

    def exec_op(self, op):
        s = self.stack
        if op == 25:  # PUSH_IMM (zero-extended via mov edi)
            imm = self.fetch() & 0xffffffff
            self.t(f"PUSH_IMM {imm} (=0x{imm:x})")
            s.append(imm)
        elif op == 23:  # DUP
            self.t("DUP")
            s.append(s[-1])
        elif op == 14:  # POP_ZERO (clear top, sp--)
            self.t("POP")
            s.pop()
        elif op == 16:  # PUSH_REL  (DUP from depth)
            imm = self.fetch()
            # eax = sp; eax = sp-1-imm; rax = stack[sp-1-imm]; stack[sp] = rax; sp++
            depth = imm + 1  # 1-based: imm=0 -> top
            v = s[-depth]
            self.t(f"PUSH_REL[{imm}] -> {v!r}")
            s.append(v)
        elif op == 5:  # ADD
            b = s.pop(); a = s.pop()
            r = to_uint64(to_signed64(a) + to_signed64(b))
            self.t(f"ADD {a}+{b}={r}")
            s.append(r)
        elif op == 24:  # SUB
            b = s.pop(); a = s.pop()
            r = to_uint64(to_signed64(a) - to_signed64(b))
            self.t(f"SUB {a}-{b}={r}")
            s.append(r)
        elif op == 6:  # MUL
            b = s.pop(); a = s.pop()
            # imul rsi, [rdx+rax-8]; signed multiply
            r = to_uint64(to_signed64(a) * to_signed64(b))
            self.t(f"MUL {a}*{b}={r}")
            s.append(r)
        elif op == 4:  # DIV (signed quotient)
            b = s.pop(); a = s.pop()
            sa, sb = to_signed64(a), to_signed64(b)
            q = abs(sa) // abs(sb)
            if (sa < 0) ^ (sb < 0): q = -q
            r = to_uint64(q)
            self.t(f"DIV {sa}/{sb}={q}")
            s.append(r)
        elif op == 2:  # MOD (signed remainder)
            b = s.pop(); a = s.pop()
            sa, sb = to_signed64(a), to_signed64(b)
            # x86 idiv: remainder has sign of dividend
            q = abs(sa) // abs(sb)
            if (sa < 0) ^ (sb < 0): q = -q
            rem = sa - q * sb
            r = to_uint64(rem)
            self.t(f"MOD {sa}%{sb}={rem}")
            s.append(r)
        elif op == 8:  # OR (32-bit-ish)
            b = s.pop(); a = s.pop()
            r = (a | b) & 0xffffffff  # esi op then mov rax, esi (zero-extend)
            self.t(f"OR {a}|{b}={r}")
            s.append(r)
        elif op == 1:  # SHL
            b = s.pop(); a = s.pop()
            r = (a << (b & 0x1f)) & 0xffffffff  # shl edx, cl  -> 32-bit
            self.t(f"SHL {a}<<{b}={r}")
            s.append(r)
        elif op == 26:  # SHR
            b = s.pop(); a = s.pop()
            r = ((a & 0xffffffff) >> (b & 0x1f)) & 0xffffffff
            self.t(f"SHR {a}>>{b}={r}")
            s.append(r)
        elif op == 19:  # EQ
            b = s.pop(); a = s.pop()
            r = 1 if a == b else 0
            self.t(f"EQ {a}=={b} -> {r}")
            s.append(r)
        elif op == 20:  # NEQ
            b = s.pop(); a = s.pop()
            r = 1 if a != b else 0
            self.t(f"NEQ {a}!={b} -> {r}")
            s.append(r)
        elif op == 21:  # MULBY8_PLUS24:  x = x*8 + 0x18
            v = s.pop()
            r = to_uint64((to_signed64(v) * 8) + 0x18)
            self.t(f"MUL8+24 -> {r}")
            s.append(r)
        elif op == 12:  # TRIPLE_MINUS6_DOUBLE: (3x - 6) * 2
            v = s.pop()
            sv = to_signed64(v)
            # lea rax, [rax+rax*2-6]; add rax, rax  -> (3v-6)+(3v-6) = 6v-12
            # Actually: lea rax, [rax + rax*2 - 6] is rax = 3v - 6, then add rax, rax -> 2*(3v-6) = 6v - 12
            r = to_uint64(sv * 6 - 12)
            self.t(f"TRIPLE_DBL {sv} -> {r}")
            s.append(r)
        elif op == 9:  # MOD3_PLUS17: (x + 17) mod 3
            v = s.pop()
            sv = to_signed64(v)
            x = sv + 0x11
            # signed mod 3
            q = abs(x) // 3
            if x < 0: q = -q
            r = to_uint64(x - q * 3)
            self.t(f"MOD3+17 ({sv}+17)%3 -> {r}")
            s.append(r)
        elif op == 0:  # STRLEN-ish: returns (len + 1) basically... let me re-read
            # rax = stack[sp-1] (pointer); rsi = &stack[sp-1]
            # if *rax == 0: stack[sp-1] = 0  (but `mov eax, 0; jmp 0x28` then cdqe; mov [rsi]=rax)
            #   So if first byte is 0, store 0.
            # else: walk rax until *rax == 0; rdx = (rax_end - rax_start); rax = rdx + 1
            # So result = strlen + 1 if non-empty, else 0.
            v = s[-1]
            if isinstance(v, (bytes, bytearray)):
                if len(v) == 0 or v[0] == 0:
                    r = 0
                else:
                    # Find first NUL or end -- returns true strlen
                    nul = v.find(b'\x00')
                    if nul < 0: nul = len(v)
                    r = nul
            else:
                # Treat as integer "string at address" - shouldn't happen in our sim
                r = 0
            self.t(f"STRLEN+1 {v!r} -> {r}")
            s[-1] = r
        elif op == 11:  # PC_JUMP_BY_IMM_TIMES_4 -- unconditional relative jump
            # rax = pc; rdx = *pc; pc = pc + rdx*4 (in BYTES, but we use word index)
            imm_pos = self.pc
            imm = self.bc[self.pc]
            # In byte addressing, pc was advanced by reading imm? Let me re-check:
            # `mov rax, [rsi]; movsxd rdx, [rax]; lea rax, [rax + rdx*4]; mov [rsi], rax`
            # Here rax was loaded BEFORE reading imm, and never advanced past it.
            # The new pc = (old pc, pointing AT imm) + imm*4 bytes = old pc + imm dwords.
            # So our `self.pc` (which already advanced past op) is the imm position;
            # bc[self.pc] is imm; new pc (in word units) = self.pc + imm
            new_pc = self.pc + imm  # NOT pc+1+imm (as if we'd consumed imm)
            self.t(f"JMP_FWD imm={imm} pc:{self.pc}->{new_pc}")
            self.pc = new_pc
        elif op == 27:  # JUMP_BACK
            # rax = pc (still pointing at imm); rdx = *pc; pc = pc - rdx*4
            imm = self.bc[self.pc]
            new_pc = self.pc - imm
            self.t(f"JMP_BACK imm={imm} pc:{self.pc}->{new_pc}")
            self.pc = new_pc
        elif op == 22:  # JNZ
            # `mov rax, [rsi]; mov edx, [rax]; rax+=4; [rsi]=rax`  (advance pc past imm)
            # `mov eax, *sp; rdi = stack[sp-1]; sub eax, 1; *sp = sp-1`  (pop)
            # `if rdi == 0 ret`
            # `else: rdx*=4; [rsi] += rdx`
            imm = self.fetch()
            cond = s.pop()
            if cond != 0:
                # advance pc by imm-1 more words (we already consumed 1 word for imm)
                # Actually in byte terms, the running pc is at "after imm" (rax += 4 after read).
                # Then it adds rdx*4 bytes = rdx words to rsi (current pc). So pc += imm (in words).
                # Wait: `mov rax, [rsi]` loads pc (pointer to imm). `add rax, 4` -> pc points after imm.
                # Then later: `rdx*=4 (shl rdx,2 actually no -- actually `shl rdx, 2` then add [rsi], rdx)
                # so pc (already past imm) += imm*4 bytes = imm dwords.
                # BUT our self.pc just incremented past imm, so:
                new_pc = self.pc + imm
                self.t(f"JNZ imm={imm} cond={cond} pc:{self.pc}->{new_pc}")
                self.pc = new_pc
            else:
                self.t(f"JNZ imm={imm} cond=0 (no jump)")
        elif op == 18:  # LOAD_SBYTE_AT_IDX: stack[top] = signed_byte( top_value[imm] )
            imm = self.fetch()
            v = s[-1]
            # v is a pointer; [v + imm] read as signed byte
            if isinstance(v, (bytes, bytearray)):
                # imm interpreted as signed via movsxd
                b = v[imm] if 0 <= imm < len(v) else 0
                if b >= 0x80: b -= 0x100  # signed
            else:
                b = 0
            self.t(f"LOADB[{imm}] {v!r} -> {b}")
            s[-1] = to_uint64(b)
        elif op == 13:  # TRIM_NEWLINES (strip trailing/internal newlines, see disasm)
            v = s[-1]
            if isinstance(v, (bytes, bytearray)):
                # The blob walks string and replaces 0x0a with 0x00 in certain conditions.
                # Read the disasm: keep first byte, then for subsequent: if byte == 0x0a -> set to 0.
                # Actually read carefully:
                # rax = stack[top]; if *rax==0 ret;
                # ecx=0 (cur_replace_state), esi=1; loop:
                #  jmp to check
                #  fall in: *rax = 0; ecx = esi(1); rax++
                #  check: if *rax == 0 done
                #         if dl == 0xa then jmp to (replace... but only if ecx was 0?)
                #           actually: `cmp dl,0xa je 0x1f` -> goto replace
                #           else: `test ecx, ecx; je 0x24` -> if ecx==0 skip replace, just rax++
                #                                          else jmp 0x1f -> replace
                # Hmm tricky. Simpler interpretation: strip trailing newlines from input.
                # For getline result, the string ends with '\n\0'. So the obvious purpose is
                # to convert trailing '\n' to '\0'. Let's emulate that by simply replacing
                # the FIRST '\n' (after position 0) with NUL.
                ba = bytearray(v)
                if len(ba) > 0 and ba[0] != 0:
                    for i in range(1, len(ba)):
                        if ba[i] == 0x0a:
                            ba[i] = 0
                            break
                self.t(f"TRIM_NL {v!r} -> {bytes(ba)!r}")
                s[-1] = bytes(ba)
        elif op == 3:  # READLINE (getline from stdin)
            imm = self.fetch()  # imm*8 was passed to malloc but getline reallocates
            # Take next line from input buffer; getline keeps the trailing '\n'
            nl = self.input_buf.find(b'\n', self.input_pos)
            if nl < 0:
                line = self.input_buf[self.input_pos:] + b'\x00'
                self.input_pos = len(self.input_buf)
            else:
                line = self.input_buf[self.input_pos:nl + 1] + b'\x00'
                self.input_pos = nl + 1
            self.t(f"GETLINE size_hint={imm} -> {line!r}")
            s.append(line)
        elif op == 10:  # PRINTF "%s"
            v = s.pop()
            if isinstance(v, (bytes, bytearray)):
                if b'\x00' in v:
                    s2 = v.split(b'\x00', 1)[0]
                else:
                    s2 = v
                self.output.append(s2)
                if self.trace: print(f"   [out] {s2!r}")
            else:
                self.output.append(str(v).encode())
                if self.trace: print(f"   [out int] {v}")
        elif op == 7:  # ANTI-DEBUG (ptrace check)
            self.t("PTRACE_CHECK (skipped)")
            # ptrace(0,0,0,0) returns 0 normally; non-debugger -> ok; we just pass.
        elif op == 15:  # PACK_BYTES: pop N values, build buffer from low byte of each
            n = self.fetch()
            if n <= 0:
                self.t(f"PACK_BYTES n={n} (no-op)")
                return
            buf = bytearray(n)
            # bottom of region is stack[sp - n], top is stack[sp - 1]
            # buf[i] = low_byte( stack[sp - n + i] )  for i in 0..n-1
            for i in range(n):
                v = s[-(n - i)]
                if isinstance(v, int):
                    buf[i] = v & 0xff
                elif isinstance(v, (bytes, bytearray)):
                    buf[i] = v[0] if v else 0
            # remove top n entries, push buffer
            for _ in range(n):
                s.pop()
            self.t(f"PACK_BYTES n={n} -> {bytes(buf)!r}")
            s.append(bytes(buf))
        elif op == 17:  # CALL: imm1 = target word offset, imm2 = n_args (locals to keep at end)
            imm1 = self.fetch()
            imm2 = self.fetch()
            saved_pc = self.pc
            target_pc = imm1  # pc = bytecode_base + imm1 (in dwords) since rdi+rax*4
            self.t(f"CALL target={target_pc} n_consume={imm2} (saved={saved_pc})")
            self.pc = target_pc
            # Run until we hit HALT
            self.run(until_halt=True)
            # Take top of stack as return value
            ret = s[-1]
            # Pop n_consume entries below the result, leave result at new top.
            # Per disasm: `eax=*sp; rdx=stack[sp-1]; eax-=1; eax-=r15; cdqe; stack[sp-1-r15]=rdx; *sp -= r15`
            # So: result = stack[sp-1]; new_pos = sp - 1 - r15 (the slot below the consumed args);
            # stack[new_pos] = result; sp -= r15.
            # Effectively: pop r15 items beneath the result.
            if imm2 > 0:
                # remove imm2 items from BELOW the top
                # current stack: [..., a1, a2, ..., a_imm2, ret]
                # We want: [..., ret]
                top_val = s[-1]
                del s[-1]  # remove ret
                for _ in range(imm2):
                    s.pop()
                s.append(top_val)
            self.t(f"  CALL returned {ret}")
            self.pc = saved_pc
        else:
            raise RuntimeError(f"Unknown opcode {op} at pc={self.pc-1}")


def main():
    bc = load_bytecode()
    print(f"Loaded {len(bc)} bytecode words.")
    print("First 30 words:", bc[:30])

    # Try empty input first to see prompt
    print("\n--- Run with empty input ---")
    vm = VM(bc, input_str=b"\n", trace=False)
    try:
        vm.run()
    except Exception as e:
        print(f"  exc: {e}")
    print(f"  output: {b''.join(vm.output)!r}")
    print(f"  steps: {vm.steps}, sp={len(vm.stack)}")


if __name__ == "__main__":
    main()
