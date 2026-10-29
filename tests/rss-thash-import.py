#!/usr/bin/env python3
"""Compare complete thash tests and transitive arithmetic helpers to the pin."""
from pathlib import Path

root = Path(__file__).resolve().parents[1]
source = (root / 'tests/upstream/fstack/tests/unit/test_ff_dpdk_if.c').read_bytes()
parts = []
a = source.index(b'static const uint8_t test_rsskey_40[40]')
b = source.index(b'/* Build a single-rule RSS config', a)
parts.append(source[a:b])
a = source.index(b'#define EQUIV_N ')
b = source.index(b'/* rte_thash_init_ctx() needs', a)
parts.append(source[a:b])
for name in ['run_equiv_for_reta', 'test_ff_rss_thash_equivalence_hitrate',
             'run_equiv6_for_reta', 'test_ff_rss_thash6_equivalence_hitrate']:
    a = source.index(b'static void\n' + name.encode() + b'(')
    b = source.index(b'\n}\n', a) + 3
    parts.append(source[a:b])
if (root / 'tests/fstack-rss-thash-source.inc').read_bytes() != b'\n'.join(parts):
    raise SystemExit('FAIL: thash source excerpt differs from pinned upstream')
print('PASS: unchanged complete IPv4/IPv6 thash cases, key, PRNG seeds and software oracle helpers')
