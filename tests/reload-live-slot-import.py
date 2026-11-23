#!/usr/bin/env python3
from pathlib import Path
root = Path(__file__).resolve().parents[1]
s = (root / 'tests/upstream/fstack/tests/unit/test_ff_dpdk_if.c').read_bytes()
a = s.index(b'static void\np1_directory_conflict(')
b = s.index(b'\nstatic void test_p1_directory_full', a)
assert (root / 'tests/fstack-reload-live-slot-source.inc').read_bytes() == s[a:b]
print('PASS: complete original P1 live-slot helper and source assertions')

a = s.index(b'/* P2 (C-P2-6a): a reaped child')
b = s.index(b'/* RX-15:', a)
c = s.index(b'/* Set up "old master gone')
d = s.index(b'\nint\nmain(void)', c)
assert (root / 'tests/fstack-reload-slot-window-source.inc').read_bytes() == s[a:b] + s[c:d]
print('PASS: complete original P2 transient-slot helpers and both source tests')
