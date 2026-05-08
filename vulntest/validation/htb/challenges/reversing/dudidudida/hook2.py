"""Spawn dudidudida.exe via subprocess (stdin pipe), attach Frida by PID."""
import frida, subprocess, time, threading, os

EXE = r"D:\Repos\Security\Argus\vulntest\validation\htb\challenges\reversing\dudidudida\rev_dudidudida\dudidudida.exe"

JS = r"""
const mod = Process.getModuleByName('dudidudida.exe');
console.log('mod base ' + mod.base);
const lookup = mod.base.add(0x4aee0);

Interceptor.attach(lookup, {
    onEnter: function (args) {
        this.idx = args[0].toInt32();
    },
    onLeave: function (retval) {
        try {
            // D string is { size_t length; void* ptr; }
            // retval points to length, +8 to ptr
            const length = retval.readU64().toNumber();
            const dataPtr = retval.add(8).readPointer();
            const b = new Uint8Array(dataPtr.readByteArray(Math.min(length, 4)));
            send({type:'pair', idx: this.idx, length: length, b1: b[0], b2: b[1]});
        } catch (e) {
            send({type:'err', msg: 'idx=' + this.idx + ' err=' + e.message});
        }
    }
});
"""

pairs = {}
def msg(m, d):
    if m['type'] == 'send':
        p = m['payload']
        if p.get('type') == 'pair':
            ch1 = chr(p['b1']) if 32 <= p['b1'] <= 126 else f"\\x{p['b1']:02x}"
            ch2 = chr(p['b2']) if 32 <= p['b2'] <= 126 else f"\\x{p['b2']:02x}"
            print(f"  idx={p['idx']:3d}  ({p['b1']:3d},{p['b2']:3d}) = {ch1}{ch2}")
            pairs[p['idx']] = (p['b1'], p['b2'])
        elif p.get('type') == 'err':
            print(f"[err] {p['msg']}")

# Spawn via subprocess — stdin pipe ready
proc = subprocess.Popen(
    [EXE],
    stdin=subprocess.PIPE,
    stdout=subprocess.PIPE,
    stderr=subprocess.STDOUT,
    cwd=os.path.dirname(EXE),
)
print(f"[*] spawned pid={proc.pid}")

# Attach Frida by pid
time.sleep(0.3)
session = frida.attach(proc.pid)
script = session.create_script(JS)
script.on('message', msg)
script.load()
print("[*] hook installed")

# Send 32-char dummy input — the program will iterate through its
# internal table to compare each chunk. Each iteration triggers our hook.
# We just need ANY 32-char input to keep the program alive long enough.
# But if any chunk matches (unlikely with random input), it terminates.
# Also a 3s timeout — we need to enter input within 3s.
time.sleep(0.5)
inp = b"a" * 64 + b"\n"
proc.stdin.write(inp)
proc.stdin.flush()

# Let program run a moment to capture all hooks
time.sleep(2)
try:
    proc.terminate()
except: pass

session.detach()
print(f"\n[+] collected {len(pairs)} pairs")
if pairs:
    sorted_pairs = sorted(pairs.items())
    flag_bytes = b''.join(bytes([b1, b2]) for _, (b1, b2) in sorted_pairs)
    try:
        flag = flag_bytes.decode('latin-1')
        print(f"flag content: {flag!r}")
    except Exception as e:
        print(f"raw bytes: {flag_bytes.hex()}")
