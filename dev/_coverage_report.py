import re
from collections import defaultdict

log = open('dev/vulntest_run.log', encoding='utf-8', errors='replace').read()

results = []
for m in re.finditer(r'^\s+(PASS|FAIL|WARN)\s+(\S+)\s+(\S+):\s+(\S+)', log, re.MULTILINE):
    results.append(m.groups())


def classify(cell):
    c = cell.replace('\\', '/')
    if c.endswith('/go') or c.endswith('/rust') or c.endswith('/csharp'):
        return 'multi-lang (go/rust/csharp)'
    if 'known-positive/CVE-2021-21551' in c:
        return 'real-world Windows driver (.sys)'
    if 'known-positive/CVE-2026-31431' in c:
        return 'real-world Linux kernel module (.ko)'
    if 'known-positive/dirty-frag' in c:
        return 'real-world Linux kernel module (.ko)'
    if c.endswith('/c'):
        return 'C exe (tier-1)'
    if c.endswith('/cpp'):
        return 'C++ exe (tier-1)'
    if 'tier2-chains' in c:
        return 'C exe (tier-2 chain)'
    if 'tier3-obfuscated' in c:
        return 'C exe (stripped/tier-3)'
    return 'other'


buckets = defaultdict(lambda: {'PASS': 0, 'FAIL': 0, 'WARN': 0,
                               'cells': set(), 'fail_details': []})
for status, cell, cat, reason in results:
    b = classify(cell)
    buckets[b][status] += 1
    buckets[b]['cells'].add(cell)
    if status == 'FAIL':
        buckets[b]['fail_details'].append((cell, cat, reason))


print(f'{"bucket":<42s}  PASS  WARN  FAIL  pass%  cells')
print('-' * 82)
for b in sorted(buckets):
    st = buckets[b]
    total = st['PASS'] + st['FAIL'] + st['WARN']
    pct = 100 * st['PASS'] / total if total else 0
    print(
        f'{b:<42s}  {st["PASS"]:>4}  {st["WARN"]:>4}  {st["FAIL"]:>4}'
        f'  {pct:5.1f}%  {len(st["cells"]):>3}'
    )

print()
print('=== Per-bucket FAILs (excluding multi-lang) ===')
for b in sorted(buckets):
    if 'multi-lang' in b:
        continue
    if not buckets[b]['fail_details']:
        continue
    print(f'[{b}]')
    for cell, cat, reason in buckets[b]['fail_details']:
        print(f'  {cell}  {cat}: {reason}')
