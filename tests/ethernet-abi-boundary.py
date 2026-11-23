#!/usr/bin/env python3
"""Guard ethdev tests against mixing host and pinned Linux Ethernet headers."""
from pathlib import Path
import sys

root = Path(sys.argv[1])
sources = (
    'ethdev-rx.c',
    'ethdev-external-lifetime.c',
    'ethdev-rx-metadata.c',
    'ethdev-rx-fanout.c',
    'ethdev-duplex.c',
    'ethdev-rx-capacity.c',
    'ethdev-rebind.c',
    'ethdev-multiqueue.c',
)
for name in sources:
    text = (root / 'tests' / name).read_text()
    assert '#include "compat/ethernet-abi.h"' in text, name
    assert '#include <linux/if_ether.h>' not in text, name
    assert '#include "linux/if_ether.h"' not in text, name

abi = (root / 'src/compat/ethernet-abi.h').read_text()
for check in (
    '#include "ker/linux_ethernet.h"',
    'sizeof(struct ethhdr) == ETH_HLEN',
    'offsetof(struct ethhdr, h_dest) == 0',
    'offsetof(struct ethhdr, h_source) == ETH_ALEN',
    'offsetof(struct ethhdr, h_proto) == 2 * ETH_ALEN',
):
    assert check in abi, check

print('ethdev tests use only the pinned Linux Ethernet ABI')
