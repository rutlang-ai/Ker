#!/usr/bin/env python3
"""Verify full unchanged pool sources and exact compiled memory-only excerpts."""
import hashlib
import json
from pathlib import Path

root = Path(__file__).resolve().parents[1]
source = root / 'third_party/fstack-pools'
manifest = json.loads((source / 'UPSTREAM.json').read_text())
assert manifest['revision'] == '646a641cfff77f4815e1e29829a09e1ed15a2999'
assert set(manifest['files']) == {'ff_dpdk_if.c', 'ff_memory.h'}
for name, record in manifest['files'].items():
    data = (source / name).read_bytes()
    assert hashlib.sha256(data).hexdigest() == record['sha256']
    assert hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest() == record['git_blob']
c, h = (source / 'ff_dpdk_if.c').read_bytes(), (source / 'ff_memory.h').read_bytes()
chunks = [c[:c.index(b'*/') + 2] + b'\n']
for key in ['MEMPOOL_CACHE_SIZE', 'MSG_RING_SIZE', 'FF_MBUF_GEN_MAX', 'FREE_RING_SIZE', 'NB_SOCKETS']:
    chunks.append(next(line for line in h.splitlines(keepends=True) if line.startswith(b'#define ' + key.encode() + b' ')))
for name, declaration in [('ff_shared_pool_cache_size', b'static inline unsigned\r\n'),
                          ('ff_mbuf_gen_pool_name', b'static inline int\r\n')]:
    start = h.index(declaration + name.encode() + b'(')
    end = h.index(b'\r\n}\r\n', start) + 5
    chunks.append(h[start:end])
chunks.append(next(line for line in c.splitlines(keepends=True) if line.startswith(b'struct rte_mempool *pktmbuf_pool[')))
start = c.index(b'/* per-generation application-side mbuf pools')
end = c.index(b'\nstatic void\ninit_app_mem_pool', start)
chunks.append(c[start:end])
assert (source / 'pool-runtime.inc').read_bytes() == b'\n'.join(chunks)
original = (root / 'tests/upstream/fstack/tests/unit/test_ff_dpdk_if.c').read_bytes()
parts = []
for name in ['test_ut_nr_18_gen_pool_config', 'test_ut_nr_21_shared_pool_cache_size']:
    start = original.index(b'static void\n' + name.encode() + b'(')
    end = original.index(b'\n}\n', start) + 3
    parts.append(original[start:end])
assert (root / 'tests/fstack-pool-source.inc').read_bytes() == b'\n'.join(parts)
print('PASS: unchanged full sources, compiled pool excerpts and complete NR18/NR21 assertions')
