"""Summarise Phase-4 local-verify results from a runner log."""
from collections import Counter, defaultdict
import re

log = open('dev/verify_run.log', encoding='utf-8', errors='replace').read()

# Verify events: `      [verify] {category} @ {function} → IMPACT_VERIFIED`
events = []
for m in re.finditer(r'\[verify\]\s+(\S+)\s+@\s+(\S+)\s+\S+\s+IMPACT_VERIFIED', log):
    events.append((m.group(1), m.group(2)))

# Cell counters
cells_verified = set()
for m in re.finditer(r'^=== (tier\d-\w+\\\S+) ===$', log, re.MULTILINE):
    cells_verified.add(m.group(1))

by_cat = Counter(e[0] for e in events)
print('Verify events by category:')
for cat, n in by_cat.most_common():
    print(f'  {cat:<35s} {n}')
print(f'\nTotal IMPACT_VERIFIED transitions: {len(events)}')
print(f'Cells scanned: {len(cells_verified)}')

# Final summary line
m = re.search(r'(\d+) pass, (\d+) warn, (\d+) fail', log)
if m:
    print(f'\nRunner verdict: {m.group(0)}')
