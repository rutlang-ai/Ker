#!/usr/bin/env python3
"""Source-shaped P1 queue detach retention through real EAL session owners."""
import argparse
import errno
import importlib.util
import json
import os
from pathlib import Path
import select
import selectors
import signal
import subprocess
import sys
import tempfile
import time

from hugepage_preflight import hugepage_capacity_error


def require(value, message):
    if not value:
        raise RuntimeError(message)


def record(process, prefix, timeout=30):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            if not selector.select(max(0, deadline - time.monotonic())):
                break
        line = process.stdout.readline().decode(errors='replace').strip()
        if line.startswith(prefix + ' '):
            return json.loads(line[len(prefix) + 1:])
        if not line and process.poll() is not None:
            break
    try:
        _out, err = process.communicate(timeout=1)
    except subprocess.TimeoutExpired:
        err = b''
    raise RuntimeError(prefix + ' missing; rc=' + str(process.poll()) + ' stderr=' + err.decode(errors='replace'))


def write_control(worker, command, capability=None):
    worker.stdin.write(command)
    if capability is not None:
        worker.stdin.write(int(capability).to_bytes(8, byteorder=sys.byteorder, signed=False))
    worker.stdin.flush()


def capture_pidfd(process):
    process.pidfd = os.pidfd_open(process.pid, 0)
    return process


def close_pidfd(process):
    fd = getattr(process, 'pidfd', -1)
    if fd >= 0:
        os.close(fd)
        process.pidfd = -1


def stop_worker(worker):
    if worker.poll() is None:
        worker.stdin.write(b'x'); worker.stdin.flush()
    out, err = worker.communicate(timeout=20)
    require(worker.returncode == 0, 'secondary exit=' + str(worker.returncode) +
            ' stdout=' + out.decode(errors='replace') + ' stderr=' + err.decode(errors='replace'))
    require_pidfd_exit(worker, worker.pidfd, 'orderly secondary')
    close_pidfd(worker)


def require_pidfd_exit(process, pidfd, label, timeout=10):
    poller = select.poll()
    poller.register(pidfd, select.POLLIN | select.POLLHUP | select.POLLERR)
    events = poller.poll(int(timeout * 1000))
    require(bool(events), label + ' exact pidfd did not become readable')
    require(any(flags & (select.POLLIN | select.POLLHUP | select.POLLERR) for _, flags in events),
            label + ' pidfd returned unexpected readiness')
    process.wait(timeout=1)
    require(process.returncode is not None, label + ' remained alive after pidfd readiness')
    return process.returncode


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--worker', type=Path, required=True)
    parser.add_argument('--tool', type=Path, required=True)
    parser.add_argument('--huge-dir', type=Path, default=Path('/dev/hugepages'))
    args = parser.parse_args()
    reason = hugepage_capacity_error(args.huge_dir, 64 * 1024 * 1024)
    if reason:
        print('SKIP: ' + reason + '; no host settings changed')
        return 77
    spec = importlib.util.spec_from_file_location('ker_session_tool', args.tool)
    api = importlib.util.module_from_spec(spec); spec.loader.exec_module(api)
    run_id = f'{os.getpid()}-{os.urandom(6).hex()}'
    cpu = min(os.sched_getaffinity(0))
    eal = (f'--lcores=0@{cpu} --no-pci --no-telemetry --iova-mode=va -m 64 '
           f'--huge-dir={args.huge_dir} --file-prefix=gendetach-{run_id}')
    workers, masters = [], []
    resident = None
    resident_pidfd = -1
    expected_fatal_exit = False
    with tempfile.TemporaryDirectory(prefix='ker-generation-detach-') as temporary:
        root = Path(temporary); socket_path = root / 'control.sock'
        environment = dict(os.environ, RUNTIME_DIRECTORY=str(root))
        common = ['--socket', str(socket_path), '--worker', str(args.worker), '--eal', eal]
        resident = subprocess.Popen([sys.executable, str(args.tool), 'serve', '--generation-rings',
            '--ring-pmd', *common], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, env=environment, bufsize=0)
        resident_pidfd = os.pidfd_open(resident.pid, 0)

        def start_master():
            master = api.Connection(socket_path); masters.append(master)
            ticket = master.request(api.MASTER)
            return master, ticket

        def start_worker(master, ticket, generation, *, peer_only=False, standby=False):
            read_fd, write_fd = os.pipe2(os.O_CLOEXEC)
            try:
                command = [str(args.worker), '--role', 'secondary', '--socket', str(socket_path),
                    '--control-fd', '0', '--ticket-fd', str(read_fd), '--generation', str(generation),
                    '--process', '0', '--generation-rings', '--generation-detach-test', '--ring-pmd']
                if standby:
                    command.append('--standby')
                command += ['--', *api.role_arguments(eal, 'secondary', ring_pmd=True)]
                child = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE, pass_fds=(read_fd,), env=environment, bufsize=0)
                capture_pidfd(child)
                workers.append(child)
                delivered = dict(ticket)
                if peer_only:
                    deadline = time.monotonic() + 5
                    while True:
                        try:
                            grant = master.request(api.PEER_RESERVE, session=ticket['session'],
                                epoch=ticket['epoch'], token=ticket['token'], slot=ticket['slot'],
                                generation=generation, process=0, capability=child.pid)
                            delivered['capability'] = grant['capability']
                            break
                        except OSError as error:
                            if error.errno != errno.EAGAIN or time.monotonic() >= deadline:
                                raise
                            time.sleep(0.01)
                blob = api.encode(delivered)
                require(os.write(write_fd, blob) == len(blob), 'short ticket write')
                return child
            finally:
                os.close(read_fd); os.close(write_fd)

        def spawn_waiting_worker(generation):
            read_fd, write_fd = os.pipe2(os.O_CLOEXEC)
            try:
                command = [str(args.worker), '--role', 'secondary', '--socket', str(socket_path),
                    '--control-fd', '0', '--ticket-fd', str(read_fd), '--generation', str(generation),
                    '--process', '0', '--generation-rings', '--generation-detach-test', '--ring-pmd',
                    '--', *api.role_arguments(eal, 'secondary', ring_pmd=True)]
                child = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE, pass_fds=(read_fd,), env=environment, bufsize=0)
                capture_pidfd(child)
                workers.append(child)
                return child, write_fd
            finally:
                os.close(read_fd)

        def reserve_peer(master, ticket, child_pid):
            deadline = time.monotonic() + 5
            while True:
                try:
                    return master.request(api.PEER_RESERVE, session=ticket['session'],
                        epoch=ticket['epoch'], token=ticket['token'], slot=ticket['slot'],
                        generation=0, process=0, capability=child_pid)['capability']
                except OSError as error:
                    if error.errno != errno.EAGAIN or time.monotonic() >= deadline:
                        raise
                    time.sleep(0.01)

        def deliver_ticket(write_fd, ticket, capability):
            delivered = dict(ticket, capability=capability)
            blob = api.encode(delivered)
            require(os.write(write_fd, blob) == len(blob), 'short negative-test ticket write')
            os.close(write_fd)

        def require_failed_reservation(child):
            out, err = child.communicate(timeout=10)
            require(child.returncode != 0 and b'KER_SESSION_ATTACHED' not in out and
                    b'ker session reserve: -1' in err,
                    'invalid peer reservation was accepted: rc=' + str(child.returncode) +
                    ' stdout=' + out.decode(errors='replace') + ' stderr=' + err.decode(errors='replace'))
            require_pidfd_exit(child, child.pidfd, 'rejected reservation child')
            close_pidfd(child)

        def require_rejected_child_exit(child):
            out, err = child.communicate(timeout=10)
            require(child.returncode != 0 and b'KER_SESSION_ATTACHED' not in out and
                    b'ker session reserve: -1' in err,
                    'wrong child consumed another child capability: rc=' + str(child.returncode) +
                    ' stdout=' + out.decode(errors='replace') + ' stderr=' + err.decode(errors='replace'))
            require_pidfd_exit(child, child.pidfd, 'wrong-child reservation process')
            close_pidfd(child)

        def reject_peer_reservation(*, wrong_child):
            master, ticket = start_master()
            before = status(); before_pmd = pmd_status()
            target, target_fd = spawn_waiting_worker(0)
            if wrong_child:
                recipient, recipient_fd = spawn_waiting_worker(0)
                capability = reserve_peer(master, ticket, target.pid)
                deliver_ticket(recipient_fd, ticket, capability)
                require_rejected_child_exit(recipient)
                # The exact intended child still owns the one-shot grant and
                # can consume it once after the sibling's failed attempt.
                deliver_ticket(target_fd, ticket, capability)
                require(record(target, 'KER_SESSION_ATTACHED')['peer_only'] is True,
                        'wrong-child attempt consumed the intended child reservation')
                stop_worker(target)
                replay, replay_fd = spawn_waiting_worker(0)
                deliver_ticket(replay_fd, ticket, capability)
                require_failed_reservation(replay)
            else:
                capability = reserve_peer(master, ticket, target.pid)
                deliver_ticket(target_fd, ticket, capability ^ 1)
                require_failed_reservation(target)
            release(master, ticket)
            after = status(); after_pmd = pmd_status()
            require(after['generation'] == before['generation'] and after_pmd['token'] == before_pmd['token'] and
                    after_pmd['slot'] == before_pmd['slot'] and after_pmd['epoch'] == before_pmd['epoch'],
                    'rejected peer reservation changed pool or PMD lease')
            master.close()
            if not wrong_child:
                reused_master, reused_ticket = start_master()
                recycled, recycled_fd = spawn_waiting_worker(0)
                deliver_ticket(recycled_fd, reused_ticket, capability)
                require_failed_reservation(recycled)
                release(reused_master, reused_ticket)
                reused_master.close()

        def release(master, ticket):
            deadline = time.monotonic() + 10
            while True:
                try:
                    master.request(api.RELEASE, session=ticket['session'], epoch=ticket['epoch'],
                        token=ticket['token'], slot=ticket['slot'])
                    return
                except OSError as error:
                    if error.errno != errno.EBUSY or time.monotonic() >= deadline:
                        raise
                    time.sleep(0.05)

        def status():
            conn = api.Connection(socket_path)
            try:
                return conn.request(api.STATUS)
            finally:
                conn.close()

        def pmd_status():
            conn = api.Connection(socket_path)
            try:
                return conn.request(api.PMD_STATUS)
            finally:
                conn.close()

        def require_same_pmd_owner(before, after, message):
            require(after['token'] == before['token'] and after['slot'] == before['slot'] and
                    after['epoch'] == before['epoch'], message)

        def require_source_pmd(owner, source_ready, message):
            require(owner['token'] > 0 and owner['slot'] == source_ready['slot'] and
                    owner['epoch'] == source_ready['epoch'], message)

        def probe(worker, generation, step):
            write_control(worker, b'G')
            found = record(worker, 'KER_GENERATION_PROBED')
            require(found == {'generation': generation, 'step': step},
                    'generation test stage mismatch: ' + repr(found))

        def arm(master, ticket, generation=0):
            return master.request(api.RING_DETACH_ARM, session=ticket['session'],
                epoch=ticket['epoch'], token=ticket['token'], slot=ticket['slot'],
                generation=generation, process=0)['capability']

        def expect_arm_status(master, ticket, generation, expected):
            try:
                arm(master, ticket, generation)
            except OSError as error:
                require(error.errno == expected,
                        'ARM returned unexpected status ' + repr(error.errno))
                return
            raise RuntimeError('ARM unexpectedly succeeded for an unrelated master')

        try:
            ready = record(resident, 'KER_SESSION_READY')
            require(ready['ring_pmd'] is True and ready['session'] > 0,
                    'resident did not configure the original ring PMD')
            reject_peer_reservation(wrong_child=True)
            reject_peer_reservation(wrong_child=False)
            data_master, data_ticket = start_master()
            source = start_worker(data_master, data_ticket, 0)
            source_ready = record(source, 'KER_SESSION_ATTACHED')
            require(source_ready['peer_only'] is False and source_ready['pid'] == source.pid,
                    'source was not the normal attached generation owner')
            granted = record(source, 'KER_SESSION_PMD_GRANTED')
            require(granted['queue_owner_key'] > 0, 'source did not retain the exact PMD owner lease')
            peer_data = start_worker(data_master, data_ticket, 1, standby=True)
            peer_data_ready = record(peer_data, 'KER_SESSION_ATTACHED')
            require(peer_data_ready['slot'] == source_ready['slot'] and
                    peer_data_ready['epoch'] == source_ready['epoch'] and
                    peer_data_ready['peer_only'] is False, 'generation owners did not share one master slot')
            record(peer_data, 'KER_SESSION_PMD_STANDBY')
            peer_master, peer_ticket = start_master()
            selector = start_worker(peer_master, peer_ticket, 0, peer_only=True)
            selector_ready = record(selector, 'KER_SESSION_ATTACHED')
            require(selector_ready['peer_only'] is True and selector_ready['validated_rings'] == 0 and
                    selector_ready['generation'] == 0 and selector_ready['slot'] != source_ready['slot'] and
                    selector_ready['epoch'] != source_ready['epoch'],
                    'peer-only client did not receive exact foreign same-generation role')
            write_control(selector, b'X')
            denied = record(selector, 'KER_SESSION_PEER_ONLY_DENIED')
            require(denied['generation_ring_handle'] is False and denied['pmd_status'] == -errno.EPERM and
                    denied['detach_status'] == -errno.EPERM, 'peer-only capabilities were not rejected')
            write_control(source, b'X')
            require(record(source, 'KER_SESSION_CAPABILITY_DENIED')['status'] == -errno.EINVAL,
                    'normal attached client accepted a forged capability field')

            # An armed foreign-peer decision is bound to the exact peer
            # snapshot. Losing that peer before DETACH must leave all journals
            # and the hardware-owner lease untouched.
            disappearance_capability = arm(data_master, data_ticket)
            before_peer_exit = status(); before_peer_exit_pmd = pmd_status()
            stop_worker(selector)
            # The peer-only worker's own registration lease returns at exit;
            # compare DETACH against the post-exit baseline so its normal
            # reclamation is not confused with a detach side effect.
            before_disappearance = status(); before_pmd = pmd_status()
            require(before_disappearance['generation'] == before_peer_exit['generation'] + 1 and
                    before_pmd['token'] == before_peer_exit_pmd['token'] and
                    before_pmd['slot'] == before_peer_exit_pmd['slot'] and
                    before_pmd['epoch'] == before_peer_exit_pmd['epoch'],
                    'peer-only exit did not release exactly its control lease')
            write_control(source, b'a', disappearance_capability)
            require(record(source, 'KER_SESSION_RING_DETACH_SNAPSHOT_REJECTED') ==
                    {'status': -errno.ESTALE}, 'detach accepted a disappeared peer snapshot')
            write_control(source, b'b', disappearance_capability)
            require(record(source, 'KER_SESSION_RING_DETACH_OLD_CAP_REJECTED') ==
                    {'status': -errno.EPERM}, 'a stale detach capability became reusable')
            after_disappearance = status(); after_pmd = pmd_status()
            require(after_disappearance['generation'] == before_disappearance['generation'] and
                    after_pmd['token'] == before_pmd['token'] and
                    after_pmd['slot'] == before_pmd['slot'] and
                    after_pmd['epoch'] == before_pmd['epoch'],
                    'stale peer rejection changed ring ownership or PMD lease')
            release(peer_master, peer_ticket)
            peer_master.close()
            peer_master, peer_ticket = start_master()
            selector = start_worker(peer_master, peer_ticket, 0, peer_only=True)
            selector_ready = record(selector, 'KER_SESSION_ATTACHED')
            require(selector_ready['peer_only'] is True and selector_ready['generation'] == 0,
                    'replacement foreign selector did not attach')
            write_control(selector, b'X')
            record(selector, 'KER_SESSION_PEER_ONLY_DENIED')

            foreign_baseline = status()['generation']
            foreign_baseline_pmd = pmd_status()
            require_source_pmd(foreign_baseline_pmd, source_ready,
                    'foreign phase lost the source PMD owner before seeding')
            first_capability = arm(data_master, data_ticket)
            probe(source, 0, 3); probe(peer_data, 1, 3)
            probe(source, 0, 4); probe(peer_data, 1, 4)
            require(status()['generation'] == foreign_baseline - 8, 'eight NR19 sentinels were not journaled')
            write_control(source, b'd', first_capability)
            detached = record(source, 'KER_SESSION_RING_DETACHED')
            resident_detach = record(resident, 'KER_SESSION_RING_DETACH')
            require(detached == {'foreign_peer': True, 'rx_reclaimed': 1, 'tx_reclaimed': 0} and
                    resident_detach['source_slot'] == source_ready['slot'] and
                    resident_detach['source_epoch'] == source_ready['epoch'] and
                    resident_detach['foreign_peer'] is True and
                    resident_detach['peer_slot'] == selector_ready['slot'] and
                    resident_detach['peer_epoch'] == selector_ready['epoch'] and
                    resident_detach['peer_client'] != resident_detach['peer_slot'] and
                    resident_detach['rx_reclaimed'] == 1 and resident_detach['tx_reclaimed'] == 0,
                    'foreign detach did not preserve the exact TX journal and peer coordinate')
            require(status()['generation'] == foreign_baseline - 7, 'foreign detach did not reclaim exactly one object')
            write_control(peer_data, b'F')
            probe(source, 0, 5); probe(peer_data, 1, 5)
            require(status()['generation'] == foreign_baseline, 'foreign retained journal entries did not clean to baseline')

            before_foreign_selector_exit = status(); before_foreign_selector_pmd = pmd_status()
            stop_worker(selector)
            after_foreign_selector_exit = status(); after_foreign_selector_pmd = pmd_status()
            require(after_foreign_selector_exit['generation'] ==
                    before_foreign_selector_exit['generation'] + 1,
                    'foreign selector exit did not release exactly one control lease')
            require_same_pmd_owner(before_foreign_selector_pmd, after_foreign_selector_pmd,
                    'foreign selector exit changed the PMD owner')
            release(peer_master, peer_ticket)
            # The same data owner, PMD lease, queues, EAL instance and identity
            # exercise the no-foreign-peer control after an explicit rearm.
            stale_capability = arm(data_master, data_ticket)
            changed_master, changed_ticket = start_master()
            changed_peer = start_worker(changed_master, changed_ticket, 0, peer_only=True)
            changed_ready = record(changed_peer, 'KER_SESSION_ATTACHED')
            require(changed_ready['peer_only'] is True and changed_ready['generation'] == 0,
                    'snapshot-change peer did not attach as the expected same-generation selector')
            # ATTACHED is logged before its initial heartbeat; the denial
            # marker confirms the heartbeat and both peer-only requests have
            # completed before testing the appeared-peer snapshot.
            write_control(changed_peer, b'X')
            record(changed_peer, 'KER_SESSION_PEER_ONLY_DENIED')
            write_control(source, b'a', stale_capability)
            stale = record(source, 'KER_SESSION_RING_DETACH_SNAPSHOT_REJECTED')
            require(stale == {'status': -errno.ESTALE},
                    'detach did not reject a peer that appeared after ARM')
            write_control(source, b'b', stale_capability)
            require(record(source, 'KER_SESSION_RING_DETACH_OLD_CAP_REJECTED') ==
                    {'status': -errno.EPERM}, 'appearance-invalidated detach capability became reusable')
            before_changed_exit = status(); before_changed_pmd = pmd_status()
            stop_worker(changed_peer)
            after_changed_exit = status(); after_changed_pmd = pmd_status()
            require(after_changed_exit['generation'] == before_changed_exit['generation'] + 1,
                    'replacement selector exit did not release exactly one control lease')
            require_same_pmd_owner(before_changed_pmd, after_changed_pmd,
                    'replacement selector exit changed the PMD owner')
            release(changed_master, changed_ticket)
            control_baseline = status()['generation']
            control_baseline_pmd = pmd_status()
            require_source_pmd(control_baseline_pmd, source_ready,
                    'control phase lost the source PMD owner before seeding')
            second_capability = arm(data_master, data_ticket)
            write_control(source, b'T'); write_control(peer_data, b'T')
            probe(source, 0, 3); probe(peer_data, 1, 3)
            probe(source, 0, 4); probe(peer_data, 1, 4)
            require(status()['generation'] == control_baseline - 8, 'control phase did not seed eight sentinels')
            write_control(source, b'd', second_capability)
            controlled = record(source, 'KER_SESSION_RING_DETACHED')
            resident_control = record(resident, 'KER_SESSION_RING_DETACH')
            require(controlled == {'foreign_peer': False, 'rx_reclaimed': 1, 'tx_reclaimed': 1} and
                    resident_control['source_slot'] == source_ready['slot'] and
                    resident_control['source_epoch'] == source_ready['epoch'] and
                    resident_control['foreign_peer'] is False and resident_control['peer_slot'] == 0 and
                    resident_control['peer_epoch'] == 0 and resident_control['peer_client'] == 4294967295 and
                    resident_control['rx_reclaimed'] == 1 and
                    resident_control['tx_reclaimed'] == 1,
                    'same-owner control did not drain exactly RX plus configured TX')
            require(status()['generation'] == control_baseline - 6, 'control detach did not reclaim exactly two objects')
            write_control(peer_data, b'N')
            probe(source, 0, 5); probe(peer_data, 1, 5)
            require(status()['generation'] == control_baseline, 'control retained entries did not clean to baseline')

            stop_worker(source); stop_worker(peer_data)
            release(data_master, data_ticket)
            data_master.close(); peer_master.close(); changed_master.close()
            workers.clear(); masters.clear()
            positive_final = status(); positive_final_pmd = pmd_status()
            require(positive_final['generation'] == 511 and positive_final['token'] == 0 and
                    positive_final['slot'] == 0 and positive_final['process'] == 0,
                    'positive P1 cleanup did not restore the exact 511-object pool and empty registry: ' +
                    repr(positive_final))
            require(positive_final_pmd['token'] == 0 and positive_final_pmd['epoch'] == 0 and
                    positive_final_pmd['slot'] == 0 and positive_final_pmd['generation'] == 0 and
                    positive_final_pmd['process'] == 0,
                    'positive P1 cleanup retained a PMD owner or lease: ' + repr(positive_final_pmd))
            print('PASS: real EAL P1 foreign-peer detach retained journaled TX/other rings, exact replay, re-admission, same-owner control, and full 511-object cleanup')

            # Mode 1: a registered generation-0 standby is detached while the
            # same authenticated master slot's generation-1 worker owns the
            # actual PMD lease. This must reclaim only RX q0/g0 and retain the
            # generation-0 TX sentinel and every unrelated ring entry.
            mode1_pool_start = status()['generation']
            require(mode1_pool_start == 511, 'mode-1 resident did not start from the full pool')
            mode1_master, mode1_ticket = start_master()
            mode1_owner = start_worker(mode1_master, mode1_ticket, 1)
            mode1_owner_ready = record(mode1_owner, 'KER_SESSION_ATTACHED')
            mode1_grant = record(mode1_owner, 'KER_SESSION_PMD_GRANTED')
            require(mode1_grant['queue_owner_key'] > 0 and mode1_owner_ready['generation'] == 1,
                    'generation-1 did not acquire the real PMD lease first')
            mode1_source = start_worker(mode1_master, mode1_ticket, 0, standby=True)
            mode1_source_ready = record(mode1_source, 'KER_SESSION_ATTACHED')
            mode1_standby = record(mode1_source, 'KER_SESSION_PMD_STANDBY')
            require(mode1_source_ready['slot'] == mode1_owner_ready['slot'] and
                    mode1_source_ready['epoch'] == mode1_owner_ready['epoch'] and
                    mode1_source_ready['generation'] == 0 and mode1_standby['queue_owner_key'] == 0,
                    'mode-1 source was not the same-master registered non-owner generation')
            mode1_before = status(); mode1_before_pmd = pmd_status()
            require(mode1_before['generation'] == mode1_pool_start - 3 and mode1_before_pmd['token'] > 0 and
                    mode1_before_pmd['slot'] == mode1_owner_ready['slot'] and
                    mode1_before_pmd['epoch'] == mode1_owner_ready['epoch'] and
                    mode1_before_pmd['generation'] == 1 and mode1_before_pmd['process'] == 0,
                    'mode-1 did not begin with a clean pool and exact generation-1 PMD owner')
            wrong_mode1_master, wrong_mode1_ticket = start_master()
            expect_arm_status(wrong_mode1_master, mode1_ticket, 0, errno.EPERM)
            require(status()['generation'] == mode1_before['generation'] and
                    pmd_status()['token'] == mode1_before_pmd['token'],
                    'wrong-master ARM changed the owner or pool state')
            release(wrong_mode1_master, wrong_mode1_ticket); wrong_mode1_master.close()
            mode1_old_owner_pid = mode1_owner.pid
            mode1_capability = arm(mode1_master, mode1_ticket, generation=0)
            stop_worker(mode1_owner)
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline and status()['generation'] != mode1_before['generation'] + 2:
                time.sleep(0.01)
            mode1_ownerless_pmd = pmd_status()
            require(status()['generation'] == mode1_before['generation'] + 2 and
                    mode1_ownerless_pmd['token'] == 0,
                    'exact old owner death did not release the owner and PMD leases')
            mode1_owner = start_worker(mode1_master, mode1_ticket, 1)
            mode1_replacement_ready = record(mode1_owner, 'KER_SESSION_ATTACHED')
            mode1_replacement_grant = record(mode1_owner, 'KER_SESSION_PMD_GRANTED')
            require(mode1_owner.pid != mode1_old_owner_pid and mode1_replacement_ready['generation'] == 1 and
                    mode1_replacement_grant['queue_owner_key'] > 0,
                    'generation-1 replacement did not become the exact live PMD owner')
            before_stale_owner = status(); before_stale_owner_pmd = pmd_status()
            write_control(mode1_source, b'a', mode1_capability)
            require(record(mode1_source, 'KER_SESSION_RING_DETACH_SNAPSHOT_REJECTED') ==
                    {'status': -errno.ESTALE}, 'detach accepted the departed PMD owner snapshot')
            write_control(mode1_source, b'b', mode1_capability)
            require(record(mode1_source, 'KER_SESSION_RING_DETACH_OLD_CAP_REJECTED') ==
                    {'status': -errno.EPERM}, 'owner-invalidated detach capability was reusable')
            require(status()['generation'] == before_stale_owner['generation'] and
                    pmd_status()['token'] == before_stale_owner_pmd['token'] and
                    before_stale_owner_pmd['generation'] == 1 and
                    before_stale_owner_pmd['slot'] == mode1_owner_ready['slot'] and
                    before_stale_owner_pmd['epoch'] == mode1_owner_ready['epoch'],
                    'stale owner capability changed rings or replacement PMD ownership')
            mode1_capability = arm(mode1_master, mode1_ticket, generation=0)
            mode1_before = status(); mode1_before_pmd = pmd_status()
            write_control(mode1_source, b'T'); write_control(mode1_owner, b'T')
            probe(mode1_source, 0, 3); probe(mode1_owner, 1, 3)
            probe(mode1_source, 0, 4); probe(mode1_owner, 1, 4)
            require(status()['generation'] == mode1_before['generation'] - 8,
                    'mode-1 NR19 source-shaped seed did not journal all eight sentinel objects')
            write_control(mode1_source, b'd', mode1_capability)
            mode1_detached = record(mode1_source, 'KER_SESSION_RING_DETACHED')
            mode1_resident = record(resident, 'KER_SESSION_RING_DETACH')
            require(mode1_detached == {'foreign_peer': False, 'rx_reclaimed': 1, 'tx_reclaimed': 0} and
                    mode1_resident['source_generation'] == 0 and
                    mode1_resident['owner_slot'] == mode1_owner_ready['slot'] and
                    mode1_resident['owner_epoch'] == mode1_owner_ready['epoch'] and
                    mode1_resident['owner_generation'] == 1 and mode1_resident['owner_process'] == 0 and
                    mode1_resident['owner_pid'] == mode1_owner.pid and
                    mode1_resident['foreign_peer'] is False and mode1_resident['rx_reclaimed'] == 1 and
                    mode1_resident['tx_reclaimed'] == 0,
                    'mode-1 detach did not derive RX-only cleanup from the exact different-generation PMD owner')
            require(status()['generation'] == mode1_before['generation'] - 7,
                    'mode-1 detach did not reclaim exactly RX q0/g0 while retaining TX q1/g0')
            mode1_after_pmd = pmd_status()
            require_same_pmd_owner(mode1_before_pmd, mode1_after_pmd,
                    'mode-1 detach changed the live generation-1 PMD owner')
            write_control(mode1_source, b'M'); write_control(mode1_owner, b'M')
            probe(mode1_source, 0, 5); probe(mode1_owner, 1, 5)
            require(status()['generation'] == mode1_before['generation'],
                    'mode-1 retained sentinels were not released back to the live-worker pool baseline')
            stop_worker(mode1_source); stop_worker(mode1_owner)
            release(mode1_master, mode1_ticket); mode1_master.close()
            mode1_final = status(); mode1_final_pmd = pmd_status()
            require(mode1_final['generation'] == 511 and mode1_final['token'] == 0 and
                    mode1_final['slot'] == 0 and mode1_final['process'] == 0 and
                    mode1_final_pmd['token'] == 0 and mode1_final_pmd['slot'] == 0,
                    'mode-1 teardown did not restore the exact 511-object pool and release PMD owner')
            print('PASS: real EAL mode-1 detach preserved the generation-1 PMD owner and retained generation-0 TX ownership')

            # Last, isolate the post-gate failure path. A real generation-0
            # RX dequeue is held active after it has removed a journaled mbuf;
            # DETACH must close admission, time out its bounded active wait,
            # and terminate the resident without acknowledging/reopening.
            fatal_master, fatal_ticket = start_master()
            fatal_source = start_worker(fatal_master, fatal_ticket, 0)
            fatal_source_ready = record(fatal_source, 'KER_SESSION_ATTACHED')
            require(fatal_source_ready['peer_only'] is False and fatal_source_ready['pid'] == fatal_source.pid,
                    'fatal-path source was not a normal attached generation owner')
            fatal_grant = record(fatal_source, 'KER_SESSION_PMD_GRANTED')
            require(fatal_grant['queue_owner_key'] > 0, 'fatal-path source did not own the PMD lease')
            fatal_peer = start_worker(fatal_master, fatal_ticket, 1, standby=True)
            fatal_peer_ready = record(fatal_peer, 'KER_SESSION_ATTACHED')
            require(fatal_peer_ready['slot'] == fatal_source_ready['slot'] and
                    fatal_peer_ready['epoch'] == fatal_source_ready['epoch'] and
                    fatal_peer_ready['peer_only'] is False,
                    'fatal-path generation owners did not share the authenticated master slot')
            record(fatal_peer, 'KER_SESSION_PMD_STANDBY')
            fatal_capability = arm(fatal_master, fatal_ticket)
            fatal_baseline = status()['generation']
            write_control(fatal_source, b'T'); write_control(fatal_peer, b'T')
            probe(fatal_source, 0, 3); probe(fatal_peer, 1, 3)
            probe(fatal_source, 0, 4); probe(fatal_peer, 1, 4)
            require(status()['generation'] == fatal_baseline - 8,
                    'fatal path did not seed eight production-journaled ring objects')
            write_control(fatal_source, b'H')
            record(fatal_source, 'KER_GENERATION_ACTIVE_DEQUEUE_HELD')
            write_control(fatal_source, b'd', fatal_capability)
            try:
                resident.wait(timeout=5)
            except subprocess.TimeoutExpired as error:
                raise RuntimeError('resident did not fail closed within the bounded active wait') from error
            require(resident.returncode == 125,
                    'post-gate active-operation failure did not terminate resident with status 125')
            expected_fatal_exit = True
            resident_stdout, resident_stderr = resident.communicate(timeout=5)
            require(b'orderly generation detach failed -16' in resident_stderr,
                    'resident did not report bounded active-operation timeout')
            require(b'KER_SESSION_RING_DETACH {' not in resident_stdout,
                    'resident reported a successful detach after the active-operation timeout')
            source_return = require_pidfd_exit(fatal_source, fatal_source.pidfd, 'fatal source worker')
            peer_return = require_pidfd_exit(fatal_peer, fatal_peer.pidfd, 'fatal peer worker')
            close_pidfd(fatal_source); close_pidfd(fatal_peer)
            fatal_source_stdout, fatal_source_stderr = fatal_source.communicate(timeout=5)
            fatal_peer_stdout, fatal_peer_stderr = fatal_peer.communicate(timeout=5)
            require(source_return != 0 and peer_return != 0,
                    'fatal-path worker reported successful completion after resident death')
            require(b'KER_SESSION_RING_DETACHED' not in fatal_source_stdout,
                    'fatal-path worker received a successful detach acknowledgement')
            require(b'KER_SESSION_DRAINED' not in resident_stdout + fatal_source_stdout + fatal_peer_stdout,
                    'fatal path falsely reported complete cleanup')
            require_pidfd_exit(resident, resident_pidfd, 'resident')
            fatal_master.close()
            workers.clear(); masters.clear()
            print('PASS: held production dequeue forced bounded post-gate failure; exact resident/worker pidfds died without detach ACK or false DRAINED claim')
        finally:
            for worker in workers:
                try:
                    if worker.poll() is None:
                        worker.kill()
                    worker.communicate(timeout=5)
                except BaseException:
                    pass
            for master in masters:
                try: master.close()
                except BaseException: pass
            if resident is not None and resident.poll() is None:
                resident.send_signal(signal.SIGTERM)
                try: resident.communicate(timeout=20)
                except subprocess.TimeoutExpired:
                    resident.kill(); resident.communicate()
            if resident is not None and resident.returncode not in (0, None):
                if not (expected_fatal_exit and resident.returncode == 125):
                    raise RuntimeError('resident shutdown rc=' + str(resident.returncode))
            for worker in workers:
                try: close_pidfd(worker)
                except OSError: pass
            if resident_pidfd >= 0:
                os.close(resident_pidfd)
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, ValueError) as error:
        print('session-generation-detach: ' + str(error), file=sys.stderr)
        raise SystemExit(1)
