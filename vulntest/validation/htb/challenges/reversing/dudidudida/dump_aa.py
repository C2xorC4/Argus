"""Dump the D associative array at data_1400f29a0 directly from memory."""
import frida, subprocess, time, os

EXE = r"D:\Repos\Security\Argus\vulntest\validation\htb\challenges\reversing\dudidudida\rev_dudidudida\dudidudida.exe"

JS = r"""
const mod = Process.getModuleByName('dudidudida.exe');
const aaAddr = mod.base.add(0xf29a0);
console.log('AA at ' + aaAddr);

// data_1400f29a0 stores Impl* (D AA pointer)
const impl = aaAddr.readPointer();
console.log('  impl ptr ' + impl);
if (impl.isNull()) { send({type:'err', msg:'null AA impl'}); }
else {
    // Impl struct: { BB* bb; }
    // BB struct: { Bucket[] buckets; size_t used; size_t deleted; TypeInfo* keyTI; TypeInfo* valueTI; Bucket* firstUsed; }
    // Bucket struct: { size_t hash; void* entry; }
    // Buckets[] is { length: size_t, ptr: Bucket* } — D slice
    const bb = impl.readPointer();
    console.log('  bb ptr ' + bb);

    // BB layout:
    // 0: buckets.length (size_t)
    // 8: buckets.ptr (Bucket*)
    // 16: used (size_t)
    // 24: deleted (size_t)
    const bucketsLen = bb.readU64().toNumber();
    const bucketsPtr = bb.add(8).readPointer();
    const used = bb.add(16).readU64().toNumber();
    console.log('  buckets.len ' + bucketsLen + ' .ptr ' + bucketsPtr + ' used ' + used);

    // Walk buckets
    for (let i = 0; i < bucketsLen; i++) {
        const bk = bucketsPtr.add(i * 16);
        const hash = bk.readU64().toNumber();
        const entry = bk.add(8).readPointer();
        if (hash === 0 || entry.isNull()) continue;

        // entry: key (int = 4 bytes) + value (string = length + ptr = 16 bytes)
        // Aligned: typically key at offset 0 (4 bytes) padded to 8, then value at offset 8.
        // But D uses tightly-packed structs unless aligned. Let's try a few layouts.
        try {
            const key = entry.readS32();
            // After key, padding to 8-byte boundary, then value (length, ptr)
            const valueStart = entry.add(8);
            const length = valueStart.readU64().toNumber();
            const dataPtr = valueStart.add(8).readPointer();
            if (length > 0 && length < 100 && !dataPtr.isNull()) {
                const bytes = new Uint8Array(dataPtr.readByteArray(length));
                let s = '';
                for (let j = 0; j < length; j++) s += String.fromCharCode(bytes[j]);
                send({type:'entry', i:i, key:key, length:length, str:s});
            }
        } catch (e) {
            send({type:'err', msg: 'bucket ' + i + ': ' + e.message});
        }
    }
    send({type:'done'});
}
"""

entries = []
def msg(m, d):
    if m['type'] == 'send':
        p = m['payload']
        if p.get('type') == 'entry':
            print(f"  bucket {p['i']:3d}  key={p['key']:3d}  len={p['length']}  str={p['str']!r}")
            entries.append((p['key'], p['str']))
        elif p.get('type') == 'err':
            print(f"[err] {p['msg']}")
        elif p.get('type') == 'done':
            print("[+] done")

# Spawn via subprocess so we can keep stdin open
proc = subprocess.Popen([EXE], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                        cwd=os.path.dirname(EXE))
print(f"[*] spawned pid={proc.pid}")
time.sleep(0.5)
session = frida.attach(proc.pid)
script = session.create_script(JS)
script.on('message', msg)
script.load()
time.sleep(2)

# Don't terminate too quickly; let messages drain
try:
    proc.terminate()
except: pass

session.detach()

print(f"\n[+] {len(entries)} entries collected")
sorted_entries = sorted(entries)
for k, s in sorted_entries:
    print(f"  key={k:3d}  {s!r}")

if sorted_entries:
    flag = ''.join(s for _, s in sorted_entries)
    print(f"\nflag content (concatenated): {flag!r}")
