"""Probe AA structure layout."""
import frida, subprocess, time, os

EXE = r"D:\Repos\Security\Argus\vulntest\validation\htb\challenges\reversing\dudidudida\rev_dudidudida\dudidudida.exe"

JS = r"""
function hexdump(addr, len) {
    const buf = new Uint8Array(addr.readByteArray(len));
    let lines = [];
    for (let i = 0; i < len; i += 16) {
        let hex = '', txt = '';
        for (let j = 0; j < 16 && i+j < len; j++) {
            hex += buf[i+j].toString(16).padStart(2, '0') + ' ';
            txt += (buf[i+j] >= 0x20 && buf[i+j] < 0x7f) ? String.fromCharCode(buf[i+j]) : '.';
        }
        lines.push(`+${i.toString(16).padStart(4,'0')}: ${hex}  ${txt}`);
    }
    return lines.join('\n');
}

const mod = Process.getModuleByName('dudidudida.exe');
const aaAddr = mod.base.add(0xf29a0);
send({type:'dump', label:'data@aaAddr', text: hexdump(aaAddr, 32)});
const implPtr = aaAddr.readPointer();
send({type:'dump', label:'data@implPtr', text: hexdump(implPtr, 128)});

// Try reading slice (length, ptr) at impl+0
const len0 = implPtr.readU64().toNumber();
const ptr0 = implPtr.add(8).readPointer();
send({type:'log', msg: `impl[0]=len ${len0}, impl[8]=ptr ${ptr0}`});
if (len0 > 0 && len0 < 1024 && !ptr0.isNull()) {
    send({type:'dump', label:'@bucket-array', text: hexdump(ptr0, Math.min(256, len0 * 16))});
}
"""

def msg(m, d):
    if m['type'] == 'send':
        p = m['payload']
        if p.get('type') == 'dump':
            print(f"\n--- {p['label']} ---")
            print(p['text'])
        elif p.get('type') == 'log':
            print(f"[log] {p['msg']}")
        elif p.get('type') == 'err':
            print(f"[err] {p['msg']}")

proc = subprocess.Popen([EXE], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                        cwd=os.path.dirname(EXE))
time.sleep(0.5)
session = frida.attach(proc.pid)
script = session.create_script(JS)
script.on('message', msg)
script.load()
time.sleep(2)
try: proc.terminate()
except: pass
session.detach()
