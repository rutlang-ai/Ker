"""Run all seven retained generation directory cases with actual EAL secondaries."""
import argparse
import os
from pathlib import Path
import re
import signal
import subprocess
import tempfile

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--app', type=Path, required=True)
parser.add_argument('--pmd-root', type=Path, required=True)
args = parser.parse_args()
huge = Path(os.environ.get('KER_FSTACK_HUGEPAGE_DIR', '/dev/hugepages'))
info = Path('/proc/meminfo').read_text()
free = re.search(r'^HugePages_Free:\s*(\d+)', info, re.MULTILINE)
if not free or int(free[1]) < 64 or not os.access(huge, os.W_OK):
    print('SKIP: need a writable hugetlbfs mount and at least 128 MiB of free 2 MiB pages')
    raise SystemExit(77)
if not list(args.pmd_root.glob('dpdk/pmds-*/librte_net_null.so')):
    print('SKIP: the selected DPDK installation needs its original net_null PMD')
    raise SystemExit(77)

expected = {
    'test_it_a14_primary_precreates_all_slots', 'test_it_a14_secondary_looks_up_own_slot',
    'test_it_a14_two_masters_single_consumer', 'test_it_a14_epoch_liveness_after_exit',
    'test_it_a14_probe_roundtrip_tools_contract', 'test_it_a14_usr2_drain_peer_semantics',
    'test_it_a14_usr2_chain_slot_recycle',
}
with tempfile.TemporaryDirectory(prefix='ker-a14-runtime-') as runtime, tempfile.TemporaryDirectory(prefix='ker-a14-pages-', dir=huge) as pages:
    env = dict(os.environ, RUNTIME_DIRECTORY=runtime, KER_FSTACK_HUGEPAGE_DIR=pages)
    # The unmodified source fixture launches exact executable paths for
    # primary, master and secondary. Keep failure cleanup in its own group.
    with subprocess.Popen([str(args.app.resolve())], env=env, text=True,
                          stdout=subprocess.PIPE, stderr=subprocess.STDOUT, start_new_session=True) as child:
        try:
            output = child.communicate(timeout=140)[0]
        finally:
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        print(output, end='')
        markers = re.findall(r'^A14_SOURCE_CASE (\w+)$', output, re.MULTILINE)
        if child.returncode or len(markers) != len(expected) or set(markers) != expected:
            raise RuntimeError('The real EAL A14 run did not complete every retained assertion')
