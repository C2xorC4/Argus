"""Frida hook for dudidudida.exe to dump the expected 2-byte pairs."""
import frida, sys, time

EXE = r"D:\Repos\Security\Argus\vulntest\validation\htb\challenges\reversing\dudidudida\rev_dudidudida\dudidudida.exe"

JS = r"""
const mod = Process.getModuleByName('dudidudida.exe');
console.log('mod base ' + mod.base);
// sub_14004aee0 -> RVA 0x4aee0
const lookup = mod.base.add(0x4aee0);
console.log('lookup at ' + lookup);

Interceptor.attach(lookup, {
    onEnter: function (args) {
        this.idx = args[0].toInt32();
        this.aa = args[1];
    },
    onLeave: function (retval) {
        // retval is a pointer that, when dereferenced, gives the value
        // Per disasm: rax_3[1]+8 is returned, which is value pointer
        try {
            const valPtr = retval;
            // Read 2 bytes at valPtr
            const b = valPtr.readByteArray(2);
            const bytes = new Uint8Array(b);
            const ch1 = String.fromCharCode(bytes[0]);
            const ch2 = String.fromCharCode(bytes[1]);
            send({type:'pair', idx: this.idx, b1: bytes[0], b2: bytes[1], chars: ch1+ch2});
        } catch (e) {
            send({type:'err', msg: 'idx=' + this.idx + ' err=' + e.message});
        }
    }
});
console.log('hook installed');
"""

pairs = {}
def msg(m, d):
    if m['type'] == 'send':
        p = m['payload']
        if p.get('type') == 'pair':
            print(f"  idx={p['idx']:3d}  bytes=({p['b1']:3d},{p['b2']:3d}) chars={p['chars']!r}")
            pairs[p['idx']] = p['chars']
        elif p.get('type') == 'err':
            print(f"[err] {p['msg']}")
    elif m['type'] == 'error':
        print(f"[script err] {m.get('description', m)}")

print(f"[*] spawning")
pid = frida.spawn([EXE], cwd=r"D:\Repos\Security\Argus\vulntest\validation\htb\challenges\reversing\dudidudida\rev_dudidudida")
session = frida.attach(pid)
script = session.create_script(JS)
script.on('message', msg)
script.load()
frida.resume(pid)
# Send 32-char input
import os
# Wait for prompt then write to stdin via Frida... actually frida doesn't pipe stdin.
# Instead: spawn with proper stdin redirected. Use subprocess approach later.
# For now, just wait for the prompt and let user type or auto-submit
time.sleep(5)

# Send input via a different approach — write to stdin handle
# Frida doesn't directly support this for spawned process. Use Win32.

# Actually: dudidudida has a 3-second timeout, so we need to send input fast.
# Easier: just attach to a manually-spawned process.

session.detach()
try: frida.kill(pid)
except: pass

print(f"\n[+] collected {len(pairs)} pairs")
if pairs:
    sorted_pairs = sorted(pairs.items())
    flag = ''.join(p for _, p in sorted_pairs)
    print(f"flag content: {flag!r}")
