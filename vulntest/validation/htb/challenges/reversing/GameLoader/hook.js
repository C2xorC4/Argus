// Frida script to find Godot script_encryption_key
// Approach: scan all R/W memory for 32-byte high-entropy regions that
// match known patterns (next to or referenced by typical PCK strings)

function shannon(bytes) {
    const counts = new Array(256).fill(0);
    for (let i = 0; i < bytes.length; i++) counts[bytes[i] & 0xff]++;
    let e = 0;
    const n = bytes.length;
    for (let i = 0; i < 256; i++) {
        if (counts[i] > 0) {
            const p = counts[i] / n;
            e -= p * Math.log2(p);
        }
    }
    return e;
}

// Look for the key by scanning the binary's data sections.
// Godot stores the 32-byte key as static data; it's typically in
// .data section, surrounded by known runtime structures.
const moduleName = 'Platformer 2D.exe';
const mod = Process.getModuleByName(moduleName);
console.log(`module base: ${mod.base}, size: ${mod.size}`);

// Scan .data section (writable) for high-entropy 32-byte regions.
// First let's enumerate ranges.
const ranges = mod.enumerateRanges('rw-');
console.log(`Found ${ranges.length} rw- ranges`);

let found = [];
for (const r of ranges) {
    // Skip large ranges (likely heap), focus on .data-sized ones
    if (r.size > 0x100000) continue;
    try {
        const buf = r.base.readByteArray(r.size);
        const data = new Uint8Array(buf);
        // Slide a 32-byte window with 8-byte stride
        for (let i = 0; i < data.length - 32; i += 8) {
            const chunk = data.subarray(i, i + 32);
            // Skip if mostly null or repeating
            const nzero = chunk.filter(b => b === 0).length;
            if (nzero > 8) continue;
            const uniq = new Set(chunk).size;
            if (uniq < 20) continue;
            const e = shannon(chunk);
            if (e > 4.5) {
                const addr = r.base.add(i);
                found.push({ addr: addr.toString(), entropy: e, hex: Array.from(chunk).map(b => b.toString(16).padStart(2, '0')).join('') });
            }
        }
    } catch (e) {
        // skip unreadable
    }
}
console.log(`Found ${found.length} high-entropy 32-byte candidates`);
// Print top 20
found.sort((a, b) => b.entropy - a.entropy);
for (let i = 0; i < Math.min(50, found.length); i++) {
    console.log(`  ${found[i].entropy.toFixed(2)}  ${found[i].addr}: ${found[i].hex}`);
}

console.log("done");
