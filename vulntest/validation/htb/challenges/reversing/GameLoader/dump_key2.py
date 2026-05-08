"""Frida-based key extraction for Godot 4 - streaming version."""
import frida, sys, time

EXE = r"D:\Repos\Security\Argus\vulntest\validation\htb\challenges\reversing\GameLoader\rev_gameloader\Platformer 2D.exe"

JS = r"""
function shannon(data) {
    const c = new Array(256).fill(0);
    for (let i = 0; i < data.length; i++) c[data[i]]++;
    let e = 0;
    for (let i = 0; i < 256; i++) {
        if (c[i] > 0) {
            const p = c[i] / data.length;
            e -= p * Math.log2(p);
        }
    }
    return e;
}

setTimeout(function () {
    const mod = Process.getModuleByName('Platformer 2D.exe');
    // Only RW ranges (script_encryption_key is in .data, writable)
    // include RW + RX ranges. .rdata is r-x pages on PE.
    const ranges = mod.enumerateRanges('rw-').concat(mod.enumerateRanges('r-x')).concat(mod.enumerateRanges('r--'));
    send({type:'log', msg: `${ranges.length} ranges in EXE module`});
    let total = 0, kept = 0;
    for (const r of ranges) {
        try {
            const buf = new Uint8Array(r.base.readByteArray(r.size));
            for (let i = 0; i < buf.length - 32; i += 8) {
                total++;
                const chunk = buf.subarray(i, i + 32);
                let nzero = 0;
                const first = chunk[0];
                let allsame = true;
                for (let j = 0; j < 32; j++) {
                    if (chunk[j] === 0) nzero++;
                    if (chunk[j] !== first) allsame = false;
                }
                if (allsame || nzero > 4) continue;
                const e = shannon(chunk);
                if (e >= 4.6) {
                    let hex = '';
                    for (let j = 0; j < 32; j++) hex += chunk[j].toString(16).padStart(2, '0');
                    send({type:'cand', addr: r.base.add(i).toString(), e: e, hex: hex});
                    kept++;
                }
            }
        } catch (e) { /* skip */ }
    }
    send({type:'log', msg: `scanned ${total} windows, kept ${kept}`});
    send({type:'done'});
}, 4000);
"""

cands = []
done = [False]
def msg(m, d):
    if m['type'] == 'send':
        p = m['payload']
        if p.get('type') == 'log':
            sys.stderr.write(f"[log] {p['msg']}\n")
            sys.stderr.flush()
        elif p.get('type') == 'cand':
            cands.append((p['e'], p['addr'], p['hex']))
        elif p.get('type') == 'done':
            done[0] = True

pid = frida.spawn([EXE], cwd=r"D:\Repos\Security\Argus\vulntest\validation\htb\challenges\reversing\GameLoader\rev_gameloader")
session = frida.attach(pid)
script = session.create_script(JS)
script.on('message', msg)
script.load()
frida.resume(pid)
t0 = time.time()
while not done[0] and time.time() - t0 < 60:
    time.sleep(0.5)
session.detach()
try: frida.kill(pid)
except: pass

cands.sort(reverse=True)
print(f"# {len(cands)} candidates collected")
for e, addr, hex_ in cands[:300]:
    print(f"{hex_}\t{addr}\t{e:.2f}")
