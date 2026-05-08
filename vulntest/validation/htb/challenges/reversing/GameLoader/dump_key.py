"""Frida-based key extraction for Godot 4 encrypted PCK.

Strategy: spawn the Godot EXE under Frida, let it initialize (the PCK
gets decrypted on startup since the title 'Sys Information' line appears
in stderr — meaning project.godot was parsed), then scan all rw memory
for high-entropy 32-byte windows and emit candidates ranked by entropy.

Each candidate gets test-decrypted against the PCK with gdre_tools to
find the right one.
"""
import frida
import sys
import math
import time

EXE = r"D:\Repos\Security\Argus\vulntest\validation\htb\challenges\reversing\GameLoader\rev_gameloader\Platformer 2D.exe"

JS = r"""
function shannon(data) {
    const counts = new Array(256).fill(0);
    for (let i = 0; i < data.length; i++) counts[data[i]]++;
    let e = 0;
    const n = data.length;
    for (let i = 0; i < 256; i++) {
        if (counts[i] > 0) {
            const p = counts[i] / n;
            e -= p * Math.log2(p);
        }
    }
    return e;
}

setTimeout(function () {
    // Focus on the EXE module's R/W ranges (script_encryption_key is a static data symbol).
    const mod = Process.getModuleByName('Platformer 2D.exe');
    send({type: 'log', msg: `module base ${mod.base} size 0x${mod.size.toString(16)}`});
    const ranges = mod.enumerateRanges('r--').concat(mod.enumerateRanges('rw-'));
    send({type: 'log', msg: `module ranges: ${ranges.length}`});
    let cands = [];
    for (const r of ranges) {
        try {
            const buf = new Uint8Array(r.base.readByteArray(r.size));
            for (let i = 0; i < buf.length - 32; i += 4) {
                const chunk = buf.subarray(i, i + 32);
                let nzero = 0, allsame = true;
                const first = chunk[0];
                for (let j = 0; j < 32; j++) {
                    if (chunk[j] === 0) nzero++;
                    if (chunk[j] !== first) allsame = false;
                }
                if (allsame || nzero > 6) continue;
                const e = shannon(chunk);
                if (e >= 4.5) {
                    let hex = '';
                    for (let j = 0; j < 32; j++) hex += chunk[j].toString(16).padStart(2, '0');
                    cands.push({addr: r.base.add(i).toString(), e: e, hex: hex});
                }
            }
        } catch (err) { /* skip */ }
    }
    cands.sort((a, b) => b.e - a.e);
    send({type: 'log', msg: `found ${cands.length} candidates`});
    for (let i = 0; i < Math.min(500, cands.length); i++) {
        send({type: 'cand', e: cands[i].e, addr: cands[i].addr, hex: cands[i].hex});
    }
    send({type: 'done'});
}, 4000);
"""

def on_message(message, data):
    if message['type'] == 'send':
        p = message['payload']
        if p.get('type') == 'log':
            print(f"[log] {p['msg']}")
        elif p.get('type') == 'cand':
            print(f"  e={p['e']:.2f}  {p['addr']}: {p['hex']}")
        elif p.get('type') == 'done':
            print("[+] done")
    elif message['type'] == 'error':
        print(f"[err] {message.get('description')}")

print(f"[*] spawning {EXE}")
pid = frida.spawn([EXE], cwd=r"D:\Repos\Security\Argus\vulntest\validation\htb\challenges\reversing\GameLoader\rev_gameloader")
session = frida.attach(pid)
script = session.create_script(JS)
script.on('message', on_message)
script.load()
frida.resume(pid)
time.sleep(20)
session.detach()
try:
    frida.kill(pid)
except: pass
