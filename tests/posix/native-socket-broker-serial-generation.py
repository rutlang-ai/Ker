#!/usr/bin/env python3
"""Actual two-inner-process serial generation proof for the public SDK."""
import argparse
from contextlib import ExitStack
import importlib.machinery
import importlib.util
import hashlib
import json
import os
from pathlib import Path
import select
import signal
import socket
import subprocess
import sys
import tempfile
import time


ROOT = Path(__file__).resolve().parents[2]
CONTROLLER_PATH = ROOT / 'tools' / 'ker_serial_generation.py'
LOADER = importlib.machinery.SourceFileLoader('_ker_c37_serial_controller',
    str(CONTROLLER_PATH))
SPEC = importlib.util.spec_from_loader(LOADER.name, LOADER)
if SPEC is None or SPEC.loader is None:
    raise ImportError(f'cannot load serial controller from {CONTROLLER_PATH}')
controller_module = importlib.util.module_from_spec(SPEC)
LOADER.exec_module(controller_module)


def require(value, message):
    if not value:
        raise RuntimeError(message)


def _dead(pidfd):
    if pidfd < 0:
        return True
    poller = select.poll()
    poller.register(pidfd, select.POLLIN | select.POLLHUP | select.POLLERR | select.POLLNVAL)
    events = poller.poll(0)
    return bool(events and events[0][1] & select.POLLIN)


def _wait_adopted(pid, timeout=5):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            got, _ = os.waitpid(pid, os.WNOHANG)
        except ChildProcessError:
            return
        if got == pid:
            return
        time.sleep(0.01)
    raise RuntimeError(f'test-owned adopted child {pid} did not reap')


def _test_owned_cleanup(controller, contexts, watches, record):
    """Only failure cleanup: signal exact pinned pidfds and record every kill."""
    cleanup = []
    if controller is not None and controller._unresolved_context is not None:
        if controller._unresolved_context not in contexts:
            contexts.append(controller._unresolved_context)
    actor_seen = set()
    for watch in watches:
        actor_seen.add(watch.actor.pid)
        if watch.actor.poll() is None:
            signal.pidfd_send_signal(watch.actor_pidfd, signal.SIGKILL)
            watch.actor.wait(timeout=5)
            cleanup.append({'pid': watch.actor.pid, 'reason': 'test-owned failure cleanup'})
        for fd in (watch.watch_fd, watch.actor_pidfd):
            if fd >= 0:
                os.close(fd)
        try:
            watch.channel.close()
        except OSError:
            pass
    for context in contexts:
        actor = context.owner_actor
        if actor is not None and actor.pid not in actor_seen:
            actor_seen.add(actor.pid)
            if actor.poll() is None and context.owner_pidfd >= 0:
                signal.pidfd_send_signal(context.owner_pidfd, signal.SIGKILL)
                actor.wait(timeout=5)
                cleanup.append({'pid': actor.pid,
                    'reason': 'test-owned failure cleanup after incomplete handoff'})
            if context.owner_actor_channel is not None:
                context.owner_actor_channel.close()
            if context.owner_pidfd >= 0:
                os.close(context.owner_pidfd)
                context.owner_pidfd = -1
    for context in reversed(contexts):
        if context.closed:
            continue
        for label, pidfd, pid in (
                ('app', context.app_pidfd, context.app_identity.pid if context.app_identity else None),
                ('worker', context.worker_pidfd, context.worker_identity.pid if context.worker_identity else None),
                ('inner', context.pidfd, context.process.pid)):
            if pidfd >= 0 and not _dead(pidfd):
                signal.pidfd_send_signal(pidfd, signal.SIGKILL)
                cleanup.append({'pid': pid, 'role': label, 'reason': 'test-owned failure cleanup'})
        try:
            context.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            if context.pidfd >= 0 and not _dead(context.pidfd):
                signal.pidfd_send_signal(context.pidfd, signal.SIGKILL)
            context.process.wait(timeout=5)
        for identity in (context.app_identity, context.worker_identity):
            if identity is not None:
                _wait_adopted(identity.pid)
        if context.log and not context.log.closed:
            context.log.flush()
            try:
                tail = Path(context.log.name).read_bytes()[-4096:].decode(
                    'utf-8', errors='replace')
                record.setdefault('cleanup_log_tails', []).append({
                    'generation': context.label, 'tail': tail})
            except OSError:
                pass
            context.log.close()
        if context.relay:
            context.relay.close()
        for fd in (context.app_pidfd, context.worker_pidfd, context.pidfd):
            if fd >= 0:
                os.close(fd)
        context.closed = True
    record['failure_cleanup'] = cleanup


def _retire_old_owner(controller, root, args, contexts, watches):
    old = controller.start_inner('old')
    contexts.append(old)
    controller.receive_ready(old)
    watch = controller.launch_owner_actor(old, args.actor,
        root / 'old' / 'actor-watch.sock', 'A')
    watches.append(watch)
    receipt = controller.capture_claim_receipt(watch)
    controller.prove_owner_payload(watch, 'A', 0xC370000000000101)
    controller.close_owner_listener(watch)
    controller.exit_owner(watch)
    retired = controller.verify_owner_retired(watch, receipt)
    return old, watch, receipt, retired


def run_lost_settlement_case(args, root):
    case_root = root / 'lost-settlement'
    case_root.mkdir()
    launch = controller_module.InnerLaunch(args.launcher, args.library,
        args.worker, args.broker, args.dpdk_plugin_dir, case_root)
    controller = controller_module.SerialGenerationController(launch, args.port)
    contexts, watches = [], []
    result = {'case': 'lost_settlement_receipt', 'status': 'FAIL'}
    try:
        old, watch, _receipt, retired = _retire_old_owner(
            controller, case_root, args, contexts, watches)
        old.relay_sequence += 1
        sequence = old.relay_sequence
        deadline = time.monotonic() + 20
        controller_module._send_packet(old.relay,
            controller_module.wire.pack_stop(old.nonce, old.epoch, sequence), deadline)
        accepted = controller_module._receive_packet(old.relay,
            controller_module.wire.STOP_REPLY.size, old.process.pid, deadline)
        controller_module.wire.unpack_stop_reply(accepted,
            controller_module.wire.STOP_ACCEPTED, old.nonce, old.epoch, sequence)
        settled = controller_module._receive_packet(old.relay,
            controller_module.wire.SETTLED_RECORD.size, old.process.pid, deadline)
        controller_module.wire.unpack_settled(settled, old.ready, old.nonce,
            old.epoch, sequence)
        old.process.wait(timeout=max(0.001, deadline - time.monotonic()))
        require(old.process.returncode == 0,
            'inner did not exit successfully after the consumed SETTLED receipt')
        for pidfd, role in ((old.app_pidfd, 'broker app'), (old.worker_pidfd, 'worker'),
                (old.pidfd, 'inner')):
            controller_module._wait_pidfd_dead(pidfd, deadline, role)
        stats = json.loads(old.stats_path.read_text(encoding='utf-8'))
        require(stats.get('outstanding') == 0 and stats.get('run_shutdown_ack') is True and
            stats.get('control_eof') is True,
            f'consumed SETTLED record did not correspond to actual worker cleanup: {stats!r}')
        # The fixture deliberately discards the valid SETTLED receipt. The
        # controller must not mint RuntimeSettled from process death alone.
        old.unresolved_reason = 'test intentionally discarded the authenticated SETTLED receipt'
        try:
            controller.start_next(old, retired,
                controller_module.RuntimeSettled(old, settled, {}, controller._proof_seal))
        except controller_module.SettlementError:
            pass
        else:
            raise RuntimeError('controller advanced after the settlement receipt was lost')
        require(not (case_root / 'new').exists(),
            'successor path appeared without a controller-registered SETTLED proof')
        result.update(status='PASS', old_pid=old.process.pid,
            actual_settled_record_sha256=hashlib.sha256(settled).hexdigest(),
            worker_stats=stats,
            controller_settled_flag=old.settled,
            successor_started=False,
            reason='SETTLED bytes were consumed by the harness and intentionally withheld')
        _test_owned_cleanup(controller, contexts, watches, result)
        return result
    except BaseException as exc:
        result['error'] = f'{type(exc).__name__}: {exc}'
        _test_owned_cleanup(controller, contexts, watches, result)
        raise


def run_lost_verify_case(args, root):
    case_root = root / 'lost-verify'
    case_root.mkdir()
    launch = controller_module.InnerLaunch(args.launcher, args.library,
        args.worker, args.broker, args.dpdk_plugin_dir, case_root)
    controller = controller_module.SerialGenerationController(launch, args.port)
    contexts, watches = [], []
    result = {'case': 'lost_verify_reply', 'status': 'FAIL'}
    original_receive = controller_module._receive_packet
    dropped = []
    try:
        old = controller.start_inner('old')
        contexts.append(old)
        controller.receive_ready(old)
        watch = controller.launch_owner_actor(old, args.actor,
            case_root / 'old' / 'actor-watch.sock', 'A')
        watches.append(watch)

        def receive_then_drop(sock, expected_size, expected_pid, deadline):
            packet = original_receive(sock, expected_size, expected_pid, deadline)
            if (sock is old.relay and expected_size ==
                    controller_module.wire.VERIFY_REPLY_PREFIX.size + 128):
                dropped.append(packet)
                raise controller_module.DeadlineExpired(
                    'test consumed and discarded the authentic VERIFY reply')
            return packet

        controller_module._receive_packet = receive_then_drop
        try:
            controller._verify(watch)
        except controller_module.DeadlineExpired:
            pass
        else:
            raise RuntimeError('lost VERIFY response was reported as usable')
        finally:
            controller_module._receive_packet = original_receive
        require(len(dropped) == 1 and old.unresolved_reason is not None,
            'actual VERIFY reply was not lost into terminal unresolved state')
        sequence = old.relay_sequence
        try:
            controller._verify(watch)
        except controller_module.ProtocolError:
            pass
        else:
            raise RuntimeError('controller retried after an uncertain VERIFY sequence')
        require(old.relay_sequence == sequence,
            'uncertain VERIFY retry consumed a new sequence')
        fake_retired = controller_module.VerifiedOwnerRetired(
            old, watch, dropped[0][48:], dropped[0], controller._proof_seal)
        fake_settled = controller_module.RuntimeSettled(
            old, b'', {}, controller._proof_seal)
        try:
            controller.start_next(old, fake_retired, fake_settled)
        except controller_module.SettlementError:
            pass
        else:
            raise RuntimeError('controller launched B after an unconfirmed VERIFY')
        require(not (case_root / 'new').exists() and old.process.poll() is None and
            not _dead(old.pidfd),
            'lost VERIFY did not retain the live old context without successor')
        result.update(status='PASS', old_pid=old.process.pid,
            owner_pid=watch.actor.pid, dropped_verify_reply_sha256=hashlib.sha256(
                dropped[0]).hexdigest(), relay_sequence=sequence,
            unresolved_reason=old.unresolved_reason, successor_started=False)
        _test_owned_cleanup(controller, contexts, watches, result)
        return result
    except BaseException as exc:
        result['error'] = f'{type(exc).__name__}: {exc}'
        _test_owned_cleanup(controller, contexts, watches, result)
        raise
    finally:
        controller_module._receive_packet = original_receive


def run_successor_tcp_failure_case(args, root):
    case_root = root / 'successor-failure'
    case_root.mkdir()
    launch = controller_module.InnerLaunch(args.launcher, args.library,
        args.worker, args.broker, args.dpdk_plugin_dir, case_root)
    controller = controller_module.SerialGenerationController(launch, args.port)
    contexts, watches = [], []
    result = {'case': 'successor_tcp_failure', 'status': 'FAIL'}
    try:
        old, _watch, _receipt, retired = _retire_old_owner(
            controller, case_root, args, contexts, watches)
        settled = controller.stop_inner(old, retired)
        new = controller.start_next(old, retired, settled)
        contexts.append(new)
        ready = controller.receive_ready(new)
        failed = None
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM | socket.SOCK_CLOEXEC)
        probe.settimeout(3)
        try:
            probe.connect((controller.address, controller.port))
        except OSError as exc:
            failed = exc
        finally:
            probe.close()
        if failed is None:
            raise RuntimeError('successor unexpectedly accepted TCP without an owner listener')
        controller.record_successor_tcp_failure(new, failed)
        require(new.failure_state == 'NEW_FAILED' and new.process.poll() is None and
            not _dead(new.pidfd) and new.rpc_inode is not None,
            'failed successor did not retain its exact live process/RPC ownership')
        try:
            controller.start_next(old, retired, settled)
        except controller_module.SettlementError:
            pass
        else:
            raise RuntimeError('controller permitted rollback/another generation after NEW_FAILED')
        result.update(status='PASS', old_pid=old.process.pid,
            new_pid=new.process.pid, new_nonce=new.nonce.hex(), new_epoch=new.epoch,
            new_broker_nonce=ready[2].hex(), new_broker_epoch=ready[3],
            new_worker_profile=ready[4].hex(), tcp_error=failed.errno,
            failure_state=new.failure_state,
            retained_rpc_inode=new.rpc_inode, new_pidfd_live=not _dead(new.pidfd),
            no_rollback=True)
        result['events'] = old.events + new.events
        _test_owned_cleanup(controller, contexts, watches, result)
        return result
    except BaseException as exc:
        result['error'] = f'{type(exc).__name__}: {exc}'
        _test_owned_cleanup(controller, contexts, watches, result)
        raise


def _attempt_without_proofs(controller, old, retired):
    fake = controller_module.RuntimeSettled(old, b'', {}, controller._proof_seal)
    old_directory = controller.launch.root / 'new'
    try:
        controller.start_next(old, retired, fake)
    except controller_module.SettlementError:
        pass
    else:
        raise RuntimeError('controller advanced without a registered settlement proof')
    require(not old_directory.exists(), 'unproved successor created a new-generation directory')
    require(old.process.poll() is None and not _dead(old.pidfd),
        'old process unexpectedly died during rejected successor attempt')


def run_serial(args):
    native = Path(__file__).with_name('native-socket-broker-readiness.py')
    tap_loader = importlib.machinery.SourceFileLoader('_ker_c37_readiness_helpers', str(native))
    tap_spec = importlib.util.spec_from_loader(tap_loader.name, tap_loader)
    tap = importlib.util.module_from_spec(tap_spec)
    tap_loader.exec_module(tap)
    tap.set_up_network()
    tap.enable_subreaper()

    controller = None
    contexts = []
    watches = []
    result = {'event': 'SERIAL_GENERATIONS', 'phases': []}
    try:
        with tempfile.TemporaryDirectory(prefix='ker-c37-serial-') as directory, ExitStack() as cleanup_stack:
            root = Path(directory)
            launch = controller_module.InnerLaunch(args.launcher, args.library,
                args.worker, args.broker, args.dpdk_plugin_dir, root)
            controller = controller_module.SerialGenerationController(launch, args.port)
            cleanup_stack.callback(lambda: _test_owned_cleanup(controller, contexts,
                watches, result) if result.get('status') != 'PASS' else None)

            old = controller.start_inner('old')
            contexts.append(old)
            old_ready = controller.receive_ready(old)
            result['phases'].append({'phase': 'old_ready', 'pid': old.process.pid,
                'nonce': old.nonce.hex(), 'epoch': old.epoch,
                'broker_nonce': old_ready[2].hex(), 'broker_epoch': old_ready[3],
                'worker_profile': old_ready[4].hex()})
            old_watch = controller.launch_owner_actor(old, args.actor,
                root / 'old' / 'actor-watch.sock', 'A')
            watches.append(old_watch)
            old_receipt = controller.capture_claim_receipt(old_watch)
            try:
                controller.verify_owner_retired(old_watch, bytes(128))
            except controller_module.RetirementMismatch:
                pass
            else:
                raise RuntimeError('mismatched claim receipt was accepted')
            old_request, old_response = controller.prove_owner_payload(
                old_watch, 'A', 0xC370000000000001)
            close_old = controller.close_owner_listener(old_watch)
            controller.exit_owner(old_watch)
            retired = controller.verify_owner_retired(old_watch, old_receipt)
            _attempt_without_proofs(controller, old, retired)
            settled = controller.stop_inner(old, retired)
            result['phases'].append({'phase': 'old_retired_settled',
                'owner_pid': old_watch.actor.pid, 'owner_start': old_watch.actor_identity.start_ticks,
                'close_listener_verify': close_old.hex(), 'retirement': retired.terminal_result.hex(),
                'settled': settled.settled_record.hex(), 'stats': settled.stats,
                'request': old_request.hex(), 'response': old_response.hex()})

            new = controller.start_next(old, retired, settled)
            contexts.append(new)
            try:
                controller.start_next(old, retired, settled)
            except controller_module.SettlementError:
                pass
            else:
                raise RuntimeError('controller permitted a second advance from the old generation')
            new_ready = controller.receive_ready(new)
            result['phases'].append({'phase': 'new_ready', 'pid': new.process.pid,
                'nonce': new.nonce.hex(), 'epoch': new.epoch,
                'broker_nonce': new_ready[2].hex(), 'broker_epoch': new_ready[3],
                'worker_profile': new_ready[4].hex()})
            require(new.nonce != old.nonce and new.epoch != old.epoch and
                new.process.pid != old.process.pid and
                new_ready[2] != old_ready[2] and new_ready[3] != old_ready[3],
                'successor did not use a fresh process and relay/broker context')
            new_watch = controller.launch_owner_actor(new, args.actor,
                root / 'new' / 'actor-watch.sock', 'B')
            watches.append(new_watch)
            new_receipt = controller.capture_claim_receipt(new_watch)
            new_request, new_response = controller.prove_owner_payload(
                new_watch, 'B', 0xC370000000000002)
            close_new = controller.close_owner_listener(new_watch)
            controller.exit_owner(new_watch)
            new_retired = controller.verify_owner_retired(new_watch, new_receipt)
            new_settled = controller.stop_inner(new, new_retired)
            result['phases'].append({'phase': 'new_retired_settled',
                'owner_pid': new_watch.actor.pid, 'owner_start': new_watch.actor_identity.start_ticks,
                'close_listener_verify': close_new.hex(), 'retirement': new_retired.terminal_result.hex(),
                'settled': new_settled.settled_record.hex(), 'stats': new_settled.stats,
                'request': new_request.hex(), 'response': new_response.hex()})
            result['events'] = old.events + new.events
            events_by_name = {}
            for event in result['events']:
                events_by_name.setdefault(event['event'], []).append(event)
            required_order = ('OLD_OWNER_LIVE_RECEIPT', 'OLD_TCP_PAYLOAD',
                'OLD_LISTENER_CLOSED_LIVE', 'OLD_OWNER_DEAD', 'OLD_OLD_RETIRED',
                'OLD_STOP_ACCEPTED', 'OLD_SETTLED', 'OLD_COMPONENTS_DEAD',
                'NEW_INNER_SPAWN', 'NEW_READY', 'NEW_OWNER_LIVE_RECEIPT',
                'NEW_TCP_PAYLOAD')
            stamps = []
            for event_name in required_order:
                matches = events_by_name.get(event_name, [])
                require(len(matches) == 1, f'missing/duplicate event {event_name}: {matches!r}')
                stamps.append(matches[0]['monotonic_ns'])
            require(stamps == sorted(stamps) and len(set(stamps)) == len(stamps),
                f'old settlement did not precede new startup/TCP: {stamps!r}')
            require(old.closed and new.settled and new.process.returncode == 0,
                'terminal controller state did not close old and settle new')
            controller.close_watch(new_watch)
            controller.close_context(new, 'settled')
            result.update(status='PASS', generations=2,
                claim_receipt_mismatch_rejected=True,
                successor_without_settlement_rejected=True,
                second_advance_rejected=True,
                original_linux_payload_roundtrips=2)
            result['negative_controls'] = [
                run_lost_verify_case(args, root),
                run_lost_settlement_case(args, root),
                run_successor_tcp_failure_case(args, root)]
            return result
    except BaseException as exc:
        result.update(status='FAIL', error=f'{type(exc).__name__}: {exc}')
        raise
    finally:
        if args.result:
            args.result.write_text(json.dumps(result, sort_keys=True) + '\n',
                encoding='utf-8')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--launcher', type=Path, required=True)
    parser.add_argument('--library', type=Path, required=True)
    parser.add_argument('--worker', type=Path, required=True)
    parser.add_argument('--broker', type=Path, required=True)
    parser.add_argument('--actor', type=Path, required=True)
    parser.add_argument('--dpdk-plugin-dir', type=Path, required=True)
    parser.add_argument('--port', type=int, default=4127)
    parser.add_argument('--result', type=Path, default=Path('/dev/shm/c37-serial-result.json'))
    parser.add_argument('--inside', action='store_true')
    args = parser.parse_args()
    if not args.inside:
        command = ['unshare', '-Urn', sys.executable, str(Path(__file__).resolve()),
            '--inside', '--launcher', str(args.launcher.resolve()),
            '--library', str(args.library.resolve()), '--worker', str(args.worker.resolve()),
            '--broker', str(args.broker.resolve()), '--actor', str(args.actor.resolve()),
            '--dpdk-plugin-dir', str(args.dpdk_plugin_dir.resolve()), '--port', str(args.port),
            '--result', str(args.result.resolve())]
        subprocess.run(command, check=True)
        return 0
    result = run_serial(args)
    print(json.dumps({'status': result['status'], 'generations': result['generations'],
        'payload_roundtrips': result['original_linux_payload_roundtrips'],
        'negative_controls': [item['case'] for item in result['negative_controls']]},
        sort_keys=True))
    print('SERIAL_GENERATION_TAP_OK old_retired_settled_before_new_ready tcp_payloads=2')
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f'serial generation TAP failed: {exc}', file=sys.stderr)
        raise SystemExit(1)
