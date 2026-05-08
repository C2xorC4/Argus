"""Hook sub_14004aee0 onLeave to dump full string pointer + content,
then send a long input that walks through all 32 chunks via the trie
by trying every 2-byte input pair."""
import frida, subprocess, time, os, sys

EXE = r"D:\Repos\Security\Argus\vulntest\validation\htb\challenges\reversing\dudidudida\rev_dudidudida\dudidudida.exe"

# JS hooks sub_14004aee0, dumps the value at returned pointer + offsets to
# inspect the D AA Bucket entry layout. Each call gives us a (key, value) pair.
JS = r"""
const mod = Process.getModuleByName('dudidudida.exe');
const lookup = mod.base.add(0x4aee0);

Interceptor.attach(lookup, {
    onEnter: function (args) {
        this.idx = args[0].toInt32();
    },
    onLeave: function (retval) {
        if (retval.isNull()) {
            send({type:'pair', idx: this.idx, str: null});
            return;
        }
        // retval points to the value. D string {length: size_t, ptr: char*}
        try {
            const length = retval.readU64().toNumber();
            if (length > 32) {
                send({type:'pair', idx: this.idx, str: '<bad-len ' + length + '>'});
                return;
            }
            const dataPtr = retval.add(8).readPointer();
            const bytes = new Uint8Array(dataPtr.readByteArray(length));
            let s = '';
            for (let j = 0; j < length; j++) s += String.fromCharCode(bytes[j]);
            send({type:'pair', idx: this.idx, str: s});
        } catch (e) {
            send({type:'pair', idx: this.idx, str: '<err: ' + e.message + '>'});
        }
    }
});
"""

# Strategy: we need to walk through the trie. But targets are unknown.
# A simpler approach: hook the comparison BEFORE the branch, force success.
# Then iterate ALL chunks and collect the targets we observe.
#
# Even simpler: since each function (sub_14000b180, sub_14001cfa0, etc) does
# 4 lookups and 4 memcmps, the program may always do all 4 lookups regardless
# of input match. Let me verify by sending a simple input.
#
# Wait — looking back at the disasm, each lookup is followed by memcmp,
# and on match it tail-calls (success path). On NO match across all 4,
# the function falls through to error. So all 4 lookups should fire.
#
# Let me run with input that won't match and just dump all (idx, target) tuples.

def send_input_and_capture(input_str):
    pairs = {}
    seen_idx = set()
    def msg(m, d):
        if m['type'] == 'send':
            p = m['payload']
            if p.get('type') == 'pair':
                key = (p['idx'], p['str'])
                if key not in seen_idx:
                    seen_idx.add(key)
                    print(f"  idx={p['idx']:3d} -> {p['str']!r}")
                    pairs.setdefault(p['idx'], []).append(p['str'])

    proc = subprocess.Popen([EXE], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, cwd=os.path.dirname(EXE))
    time.sleep(0.4)
    session = frida.attach(proc.pid)
    script = session.create_script(JS)
    script.on('message', msg)
    script.load()
    time.sleep(0.3)
    proc.stdin.write(input_str.encode() + b'\n')
    proc.stdin.flush()
    time.sleep(2.5)
    try: proc.terminate()
    except: pass
    session.detach()
    return pairs

print(f"[*] Input: 'a'*64")
pairs = send_input_and_capture('a' * 64)

print(f"\n[+] {sum(len(v) for v in pairs.values())} unique pairs across {len(pairs)} indices")
