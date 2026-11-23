#!/usr/bin/env python3
"""Exact live-slot collision must preserve a real owner's PMD/IPC service."""
import argparse
import ctypes
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from hugepage_preflight import hugepage_capacity_error

spec = importlib.util.spec_from_file_location('directory_fixture', Path(__file__).with_name('fstack-reload-directory.py'))
fixture = importlib.util.module_from_spec(spec); spec.loader.exec_module(fixture)
Process, Master, Actor, require = fixture.Process, fixture.Master, fixture.Actor, fixture.require


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('app', 'unit-app', 'pmd-root'): parser.add_argument('--'+name, type=Path, required=True)
    parser.add_argument('--huge-dir', type=Path, default=Path('/dev/hugepages'))
    parser.add_argument('--evidence', type=Path)
    args = parser.parse_args()
    reason = hugepage_capacity_error(args.huge_dir, 64*1024*1024)
    if reason: print('SKIP: '+reason+'; no host settings changed'); return 77
    modules = []
    for name in ('mempool_ring', 'net_ring'):
        found = list(args.pmd_root.glob('dpdk/pmds-*/librte_'+name+'.so'))
        require(len(found) == 1, 'one original '+name+' module required'); modules += ['-d', str(found[0])]
    libc = ctypes.CDLL(None, use_errno=True); prior = ctypes.c_int()
    require(libc.prctl(37, ctypes.byref(prior), 0, 0, 0) == 0 and libc.prctl(36, 1, 0, 0, 0) == 0, 'subreaper setup')
    nonce = format(int.from_bytes(os.urandom(7), 'big') or 1, 'x')
    with tempfile.TemporaryDirectory(prefix='ker-live-slot-') as temporary:
        root = Path(temporary); huge = args.huge_dir/('ker-live-slot-'+nonce); huge.mkdir(mode=0o700)
        masters = []; actors = []; primary = None
        env = dict(os.environ, KER_DIRECTORY_NONCE=nonce, RUNTIME_DIRECTORY=str(root),
                   LD_LIBRARY_PATH=str(args.pmd_root)+':'+os.environ.get('LD_LIBRARY_PATH', ''))
        common = [f'--lcores=0@{min(os.sched_getaffinity(0))}', '--no-pci', '--no-telemetry', '--iova-mode=va',
                  '--file-prefix=live-slot-'+nonce, '--huge-dir='+str(huge), *modules]
        try:
            checked = subprocess.run([str(args.unit_app)], env=env, text=True, capture_output=True, timeout=30)
            require(checked.returncode == 0 and 'PASS: complete original P1 live-slot assertions' in checked.stdout,
                    'full original source assertions failed: '+checked.stdout+checked.stderr)
            primary = Process([str(args.app), 'primary', '--proc-type=primary', '-m', '64', *common], env, root, 'primary')
            require(primary.record('READY') == {'pid': primary.child.pid, 'nonce': nonce, 'available': 63, 'driver': 'net_ring'}, 'actual primary')
            worker_env = dict(env, KER_DIRECTORY_PRIMARY_PID=str(primary.child.pid))

            def group(gen, index, slot, name, fails=False):
                plan = {'root': str(root), 'workers': [(slot, [str(args.app), 'worker', str(gen), str(slot), '--proc-type=secondary', *common])],
                        'expected_exits': {str(slot): 1 if fails else 0}}
                master = Master(plan, dict(worker_env, KER_DIRECTORY_STATE_INDEX=str(index)), root, name); masters.append(master)
                require(master.record('MASTER') == {'pid': master.child.pid}, 'actual master')
                metadata, fds = master.receive(); actor = Actor(master, metadata, fds); actors.append(actor)
                if not fails:
                    r = actor.record('ATTACHED')
                    require(r['pid'] == actor.child.pid and r['parent'] == master.child.pid and r['primary'] == primary.child.pid
                            and r['generation'] == gen and r['slot'] == slot, 'actual secondary identity')
                    actor.epoch, actor.directory_slot = r['epoch'], r['directory_slot']
                return master, actor

            ma, a = group(0, 0, 0, 'master-a')
            mb, b = group(1, 1, 2, 'master-b')
            require((a.epoch, a.directory_slot, b.epoch, b.directory_slot) == (2, 2, 3, 3), 'initial exact epoch slots')
            b.close(); mb.close()
            primary.command('wait-stale 3', 'STALE')
            require(primary.command('live 3', 'LIVE') == {'epoch': 3, 'live': 0}, 'alternate slot not reclaimable')
            require(primary.command('init-state 1 1', 'RESULT') == {'result': 0}, 'reinitialize departed caller block')
            mc, c = group(1, 1, 2, 'master-c')
            require((c.epoch, c.directory_slot) == (4, 1), 'wrap must use epoch4 exact slot1')
            require(primary.command('names 2', 'NAMES')['count'] == 88, 'original owner IPC rings missing')

            def service(sequence):
                require(primary.command('inject '+str(sequence), 'INJECTED') == {'sequence': sequence, 'available': 62}, 'allocate frame')
                require(a.command('poll', 'POLL') == {'result': 1, 'callbacks': sequence, 'received': sequence, 'completed': sequence}, 'owner PMD service')
                require(primary.command('collect', 'COLLECTED') == {'sequence': sequence, 'available': 63}, 'exact frame/census')
                require(primary.command(f'send 2 0 127 10 {sequence}', 'SENT') == {'epoch': 2, 'generation': 0, 'process': 127, 'type': 10, 'sequence': sequence, 'available': 62}, 'original IPC input')
                require(a.command('serve 127 0 10', 'SERVED') == {'epoch': 2, 'generation': 0, 'process': 127, 'type': 10, 'sequence': sequence}, 'original owner IPC reply')
                require(primary.command('receive', 'RECEIVED') == {'sequence': sequence, 'available': 63}, 'message identity/payload/cookie reclaim')

            service(1)
            before = primary.command('view', 'VIEW')
            md, d = group(1, 1, 3, 'master-d', True)
            d.reap(); md.close()
            failed_stdout = d.child.stdout.read().decode(errors='replace')
            failure = (root/'worker-3.stderr').read_text(errors='replace')
            require('ATTACHED ' not in failed_stdout and 'cannot register this process' in failure
                    and 'cross-master epoch isolation' in failure, 'not the exact original live-slot rejection')
            require(primary.command('view', 'VIEW') == before, 'failed secondary mutated owner/primary view')
            require(c.command('poll', 'POLL') == {'result': 0, 'callbacks': 0, 'received': 0, 'completed': 0}, 'foreign callback stole PMD')
            require(primary.command('live 3', 'LIVE') == {'epoch': 3, 'live': 0}, 'failed secondary used free alternate slot')
            service(2)
            after = primary.command('view', 'VIEW')
            require(after == before and after['owner_epoch'] == 2 and after['stopped'] == 0, 'owner lost publication')
            require(primary.command('drop 2', 'NAMES')['count'] == 88, 'owner original rings changed or leaked')
            c.close(); mc.close(); a.close(); ma.close()
            primary.command('wait-stale 2', 'STALE'); primary.command('wait-stale 4', 'STALE')
            final = primary.command('status', 'STATUS')
            require(final == {'available': 63, 'rx': 0, 'tx': 0, 'drain': 0, 'inflight': [0, 0],
                              'callbacks': [2, 0, 0, 0], 'received': [2, 0, 0, 0], 'ipackets': 2, 'opackets': 2}, 'final owner pipeline/census')
            require(primary.command('quit', 'CLOSED') == {'available': 63, 'outstanding': 0}
                    and primary.child.wait(timeout=20) == 0, 'primary cleanup')
            evidence = {'cases': ['test_p1_directory_live_slot'], 'primary_pid': primary.child.pid,
                        'master_pids': [m.child.pid for m in masters], 'secondary_pids': [a.child.pid for a in actors],
                        'epochs': [2, 3, 4], 'collision_epoch': 5, 'collision_slot': 2, 'alternate_slot': 3,
                        'failed_exit': 1, 'failure': failure, 'before': before, 'after': after, 'final': final,
                        'pool_reclaimed': True, 'original_ipc_roundtrips': 2, 'named_ring_lifetimes': 88,
                        'events': {'primary': primary.log, 'masters': [m.log for m in masters], 'workers': [a.log for a in actors]}}
            if args.evidence:
                with args.evidence.open('x') as output: json.dump(evidence, output, indent=2); output.write('\n')
            print('PASS: P1 exact live-slot collision, reclaimable alternate untouched; original owner PMD2/2+IPC2, all pools63/63')
            return 0
        except BaseException:
            for path in root.glob('*.stderr'): print(str(path)+':\n'+path.read_text(errors='replace'), flush=True)
            raise
        finally:
            for master in masters:
                if master.child.poll() is None: master.kill()
            for actor in actors: actor.dispose()
            for master in masters: master.dispose()
            if primary: primary.stop()
            for path in huge.iterdir():
                if path.is_file(): path.unlink()
            huge.rmdir(); require(libc.prctl(36, prior.value, 0, 0, 0) == 0, 'subreaper restore')


if __name__ == '__main__': sys.exit(main())
