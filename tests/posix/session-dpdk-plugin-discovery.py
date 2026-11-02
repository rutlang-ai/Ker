#!/usr/bin/env python3
"""Verify configured and custom-prefix DPDK PMD resolution for session fixtures."""
import argparse
import contextlib
import errno
import importlib.util
import io
import json
import os
import shlex
from pathlib import Path
import stat
import tempfile
import sys
from types import SimpleNamespace


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def load_fixture(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def expect_error(call, label):
    try:
        call()
    except RuntimeError:
        return
    raise RuntimeError(label + ' unexpectedly resolved')


class ReapedProcess:
    def poll(self):
        return 0


def private_hugepage_cleanup_checks(native):
    prefix = 'a09-private-test-'

    def snapshot(directory):
        root = Path(directory)
        root_stat = root.lstat()
        result = [('directory', root_stat.st_dev, root_stat.st_ino, root_stat.st_uid,
            stat.S_IFMT(root_stat.st_mode), stat.S_IMODE(root_stat.st_mode))]
        for entry in sorted(root.iterdir(), key=lambda item: item.name):
            value = entry.lstat()
            identity = (entry.name, value.st_dev, value.st_ino, value.st_uid,
                stat.S_IFMT(value.st_mode), stat.S_IMODE(value.st_mode), value.st_nlink)
            if stat.S_ISREG(value.st_mode):
                result.append(identity + (entry.read_bytes(),))
            elif stat.S_ISLNK(value.st_mode):
                result.append(identity + (os.readlink(entry),))
            else:
                result.append(identity)
        return tuple(result)

    def setup(parent):
        parent_fd, directory_fd, parent_identity, directory_identity = \
            native.create_handoff_hugepage_dir(parent, 'owned')
        Path(parent, 'owned', prefix + 'map_0_0').write_bytes(b'backing')
        Path(parent, 'owned', prefix + 'map_0_1').write_bytes(b'backing-two')
        return parent_fd, directory_fd, parent_identity, directory_identity

    def refusal(label, mutate=None, actor_alive=False):
        with tempfile.TemporaryDirectory(prefix='a09-private-refuse-') as raw:
            parent = Path(raw)
            parent_fd, directory_fd, parent_identity, directory_identity = setup(parent)
            live_pidfd = os.pidfd_open(os.getpid()) if actor_alive else -1
            expected = [snapshot(parent / 'owned')]
            try:
                try:
                    native.cleanup_private_hugepage_dir(parent, parent_fd, parent_identity,
                        'owned', directory_fd, directory_identity, prefix,
                        [live_pidfd] if actor_alive else [], -1, ReapedProcess(), None, True,
                        before_second_pass=(lambda: (mutate(parent), expected.__setitem__(0,
                            snapshot(parent / 'owned')))) if mutate else None)
                except RuntimeError:
                    pass
                else:
                    raise RuntimeError(label + ' unexpectedly passed private cleanup')
                held = Path(parent, 'owned')
                require(held.exists(), label + ' removed the owned directory after refusal')
                require(snapshot(held) == expected[0],
                    label + ' changed held directory entries before refusing cleanup')
            finally:
                if live_pidfd >= 0: os.close(live_pidfd)
                os.close(directory_fd); os.close(parent_fd)

    refusal('unknown entry', mutate=lambda parent: Path(parent, 'owned', 'unexpected').write_text('x'))
    refusal('symlink entry', mutate=lambda parent: Path(parent, 'owned', 'stray').symlink_to('missing'))
    refusal('FIFO entry', mutate=lambda parent: os.mkfifo(Path(parent, 'owned', 'stray')))
    refusal('subdirectory entry', mutate=lambda parent: Path(parent, 'owned', 'stray').mkdir())
    refusal('live actor', actor_alive=True)
    with tempfile.TemporaryDirectory(prefix='a09-private-unproven-') as raw:
        parent = Path(raw)
        parent_fd, directory_fd, parent_identity, directory_identity = setup(parent)
        snapshot_before = snapshot(parent / 'owned')
        try:
            try:
                native.cleanup_private_hugepage_dir(parent, parent_fd, parent_identity,
                    'owned', directory_fd, directory_identity, prefix, [], -1,
                    ReapedProcess(), None, False)
            except RuntimeError:
                pass
            else:
                raise RuntimeError('incomplete actor proof unexpectedly allowed hugepage cleanup')
            require(snapshot(parent / 'owned') == snapshot_before,
                'incomplete actor proof changed private files')
        finally:
            os.close(directory_fd); os.close(parent_fd)


    refusal('mutation between validation passes', mutate=lambda parent: Path(parent, 'owned',
        prefix + 'map_0_2').write_bytes(b'raced'))
    refusal('directory mode change', mutate=lambda parent: os.chmod(Path(parent, 'owned'), 0o755))
    refusal('hard-linked backing file', mutate=lambda parent: os.link(
        Path(parent, 'owned', prefix + 'map_0_0'), Path(parent, 'outside-link')))

    with tempfile.TemporaryDirectory(prefix='a09-private-replace-') as raw:
        parent = Path(raw)
        parent_fd, directory_fd, parent_identity, directory_identity = setup(parent)
        held_snapshot = snapshot(parent / 'owned')
        try:
            (parent / 'owned').rename(parent / 'held')
            (parent / 'owned').mkdir(mode=0o700)
            (parent / 'owned' / (prefix + 'map_0_0')).write_bytes(b'replacement')
            replacement_snapshot = snapshot(parent / 'owned')
            try:
                native.cleanup_private_hugepage_dir(parent, parent_fd, parent_identity,
                    'owned', directory_fd, directory_identity, prefix,
                    [], -1, ReapedProcess(), None, True)
            except RuntimeError:
                pass
            else:
                raise RuntimeError('replaced directory unexpectedly passed private cleanup')
            require(snapshot(parent / 'held') == held_snapshot and
                snapshot(parent / 'owned') == replacement_snapshot,
                'directory replacement refusal removed entries from either directory')
        finally:
            os.close(directory_fd); os.close(parent_fd)

    with tempfile.TemporaryDirectory(prefix='a09-private-symlink-replace-') as raw:
        parent = Path(raw)
        parent_fd, directory_fd, parent_identity, directory_identity = setup(parent)
        held_snapshot = snapshot(parent / 'owned')
        try:
            (parent / 'owned').rename(parent / 'held')
            (parent / 'owned').symlink_to('held', target_is_directory=True)
            try:
                native.cleanup_private_hugepage_dir(parent, parent_fd, parent_identity,
                    'owned', directory_fd, directory_identity, prefix,
                    [], -1, ReapedProcess(), None, True)
            except RuntimeError:
                pass
            else:
                raise RuntimeError('symlink directory replacement unexpectedly passed cleanup')
            link_stat = (parent / 'owned').lstat()
            require(snapshot(parent / 'held') == held_snapshot and stat.S_ISLNK(link_stat.st_mode) and
                os.readlink(parent / 'owned') == 'held',
                'symlink replacement refusal modified the held directory')
        finally:
            os.close(directory_fd); os.close(parent_fd)

    with tempfile.TemporaryDirectory(prefix='a09-private-cycle-') as raw:
        parent = Path(raw)
        parent_fd, directory_fd, parent_identity, directory_identity = setup(parent)
        old_fd = -1
        try:
            old = parent / 'owned' / (prefix + 'map_0_0')
            old_fd = os.open(old, os.O_RDONLY | os.O_CLOEXEC)
            old_inode = os.fstat(old_fd).st_ino
            old.unlink()
            old.write_bytes(b'new mapping at reused name')
            require(old.stat().st_ino != old_inode,
                'inode-cycle fixture did not force a distinct replacement inode')
            native.cleanup_private_hugepage_dir(parent, parent_fd, parent_identity,
                'owned', directory_fd, directory_identity, prefix, [], -1,
                ReapedProcess(), None, True)
            require(not (parent / 'owned').exists(),
                'post-reap exact private mappings were not removed')
        finally:
            if old_fd >= 0: os.close(old_fd)
            os.close(directory_fd); os.close(parent_fd)


def handoff_socket_budget_checks(native):
    prefix = 'a9-' + 'c' * 32
    primary, secondary = native.validate_dpdk_mp_socket_paths('/tmp/a9-12345678', prefix)
    require(str(primary) == f'/tmp/a9-12345678/dpdk/{prefix}/mp_socket' and
        str(secondary) == str(primary) + '_2147483647_ffffffffffffffff' and
        len(os.fsencode(primary)) < 108 and len(os.fsencode(secondary)) <= 107,
        'maximum DPDK primary/secondary socket path geometry is wrong')
    boundary_root = '/' + 'x' * 27
    boundary_primary, boundary_secondary = native.validate_dpdk_mp_socket_paths(boundary_root, prefix)
    require(len(os.fsencode(boundary_secondary)) == 107,
        'exact 107-byte secondary path was not accepted')
    for index, overlong_root in enumerate(('/' + 'x' * 28, '/' + 'é' * 14)):
        primary_candidate, secondary_candidate = native.dpdk_mp_socket_paths(overlong_root, prefix)
        require(len(os.fsencode(secondary_candidate)) >= 108,
            '108-byte rejection fixture did not exceed the encoded path limit')
        if index == 1:
            require(len(str(secondary_candidate)) < 108,
                'multibyte fixture does not distinguish encoded bytes from characters')
        expect_error(lambda value=overlong_root: native.validate_dpdk_mp_socket_paths(value, prefix),
            '108-byte or multibyte DPDK socket path')
    long_runtime = '/' + 'runtime-component-' * 8
    with tempfile.TemporaryDirectory(prefix='a09-path-budget-') as raw:
        huge_parent = Path(raw) / 'huge'
        huge_parent.mkdir()
        try:
            native.prepare_handoff_hugepage_dir(long_runtime, huge_parent, prefix)
        except RuntimeError as error:
            require('multiprocess socket path exceeds sun_path' in str(error) and
                'secondary_worst_case=' in str(error), 'long TMPDIR rejection lacked byte-budget diagnostics')
        else:
            raise RuntimeError('overlong TMPDIR was accepted for EAL startup')
        require(not list(huge_parent.iterdir()) and not (Path(long_runtime) / 'dpdk').exists(),
            'overlong TMPDIR preflight left hugepage or runtime-directory state')
    for unsafe in ('', '.', '..', 'a/b', 'a%b', 'a\x00b', 'x' * 65):
        expect_error(lambda value=unsafe: native.validate_dpdk_mp_socket_paths('/tmp', value),
            'unsafe DPDK prefix')
    known = ('EAL: peer 123_ffffffff socket path too long\n'
        'EAL: failed to init mp channel\n'
        'EAL: failed to send to (/tmp/dpdk/mp_socket) due to Bad file descriptor\n'
        'EAL: Fail to send request /tmp/dpdk/mp_socket:bus_vdev_mp\n'
        'VDEV_BUS: vdev_scan(): Failed to request vdev from primary')
    require(len(native.eal_mp_channel_errors(known)) == 5,
        'fixture did not recognize the pinned EAL multiprocess path/init failure chain')
    require(not native.eal_mp_channel_errors('ker-session: resident failed closed after expected QUIESCED'),
        'EAL diagnostic guard misclassified an intended Ker handoff fatal result')
    base = '/tmp/a9-test/dpdk/' + prefix + '/mp_socket'
    owner, peer = 12345, 12346
    runner_log = (f'EAL: Multi-process socket {base}_{owner}_aabbcc\n'
        f'EAL: Multi-process socket {base}_{peer}_0123456789abcdef\n')
    with contextlib.redirect_stdout(io.StringIO()):
        accepted = native.require_live_eal_mp_channels('host-check',
            f'EAL: Multi-process socket {base}\n', runner_log,
            Path(base), owner, peer)
    require(len(accepted) == 2, 'full primary/secondary EAL channel proof was not accepted')

    def rejected_channels(label, primary_log, worker_log):
        try:
            with contextlib.redirect_stdout(io.StringIO()):
                native.require_live_eal_mp_channels(label, primary_log, worker_log,
                    Path(base), owner, peer)
        except RuntimeError:
            return
        raise RuntimeError(label + ' channel diagnostics were accepted')

    rejected_channels('missing secondary', f'EAL: Multi-process socket {base}\n',
        runner_log.splitlines()[0])
    rejected_channels('missing primary', '', runner_log)
    rejected_channels('wrong socket base', f'EAL: Multi-process socket {base}\n',
        runner_log.replace(base, base + '-wrong'))
    rejected_channels('wrong actor pid', f'EAL: Multi-process socket {base}\n',
        runner_log.replace(f'_{peer}_', '_54321_'))
    rejected_channels('duplicate actor pid', f'EAL: Multi-process socket {base}\n',
        runner_log.replace(f'_{peer}_', f'_{owner}_'))
    rejected_channels('positive-looking socket plus MP failure', f'EAL: Multi-process socket {base}\n',
        runner_log + 'EAL: failed to init mp channel\n')

def runner_script_path():
    sibling = Path(__file__).with_name('ker_session_run.py')
    if sibling.is_file():
        return sibling
    source = Path(__file__).resolve()
    for parent in list(source.parents)[:5]:
        candidate = parent / 'tools' / 'ker_session_run.py'
        if candidate.is_file():
            return candidate
    raise RuntimeError('cannot locate the launcher helper beside this fixture or in its repository parents')


def active_consumer_reap_oracle_checks(native, runner):
    committed = dict(generation=0, queue=0, object_index=1, pool_tag=7,
        tx_lease_id=101, packet_pointer='0x1000')
    no_trailing = runner.active_consumer_deferred_counts(committed, [], [], '')
    require(no_trailing == (0, 1), 'single held U2 did not derive the exact 0/1 baseline')
    mld = dict(port=0, queue=0, generation=0, object_index=2, pool_tag=7,
        tx_lease_id=102, packet_pointer='0x2000', length=len(runner.CI_HANDOFF_MLD_FRAME),
        frame_hex=runner.CI_HANDOFF_MLD_FRAME.hex())
    output = 'KER_SESSION_FRAME_COMMITTED ' + json.dumps(mld) + '\n'
    with_trailing = runner.active_consumer_deferred_counts(committed, [], [], output)
    require(with_trailing == (1, 2), 'post-dequeue committed MLD did not derive the exact 1/2 baseline')
    prior = dict(mld, object_index=3, tx_lease_id=103, packet_pointer='0x3000')
    prior_drain = dict(object_index=3, lease_id=103, pool_tag=7, packet_pointer='0x3000')
    require(runner.active_consumer_deferred_counts(committed, [prior], [prior_drain], '') == (0, 1),
        'pre-U2 unrelated frame drained before the held barrier did not derive exact 0/1')
    require(runner.active_consumer_deferred_counts(committed, [prior], [prior_drain], output) == (1, 2),
        'late MLD after an exact pre-U2 drain did not derive exact 1/2')
    duplicate = dict(mld, object_index=1, tx_lease_id=101, packet_pointer='0x1000')
    require(runner.active_consumer_deferred_counts(committed, [], [],
        'KER_SESSION_FRAME_COMMITTED ' + json.dumps(duplicate) + '\n') is None,
        'duplicate physical commit identity was accepted')
    require(runner.active_consumer_deferred_counts(committed, [prior], [prior_drain, prior_drain], '') is None,
        'duplicate drained identity was accepted')
    unmatched_drain = dict(prior_drain, lease_id=104)
    require(runner.active_consumer_deferred_counts(committed, [prior], [unmatched_drain], '') is None,
        'drain without the exact committed lease identity was accepted')
    for field, value in (('generation', 1), ('queue', 1), ('frame_hex', '00')):
        malformed = dict(mld); malformed[field] = value
        require(runner.active_consumer_deferred_counts(committed, [], [],
            'KER_SESSION_FRAME_COMMITTED ' + json.dumps(malformed) + '\n') is None,
            'invalid trailing commit escaped frame validation: ' + field)
    require(runner.active_consumer_deferred_counts(committed, [], [],
        'KER_SESSION_FRAME_COMMITTED {broken json}\n') is None,
        'malformed trailing commit was ignored')
    base = dict(status=-errno.EBUSY, full_reap_attempts=0, preflight_only=True,
        tx_before=1, tx_after=1, pool_before=2, pool_after=2,
        counters_before=[1, 2, 3, 4, 5], counters_after=[1, 2, 3, 4, 5])
    require(native.active_consumer_deferred_snapshot_matches(base, dict(tx=1, pool=2)),
        'exact 1/2 no-mutation preflight was rejected')
    for field, value in (('tx_after', 0), ('pool_after', 1), ('full_reap_attempts', 1),
                         ('preflight_only', False), ('counters_after', [1, 2, 3, 4, 6])):
        mutated = dict(base); mutated[field] = value
        require(not native.active_consumer_deferred_snapshot_matches(mutated, dict(tx=1, pool=2)),
            'preflight mutation escaped the held-consumer oracle: ' + field)
    legacy = dict(base, tx_before=0, tx_after=0, pool_before=1, pool_after=1)
    require(native.active_consumer_deferred_snapshot_matches(legacy, dict(tx=0, pool=1)),
        'exact legacy 0/1 no-mutation preflight was rejected')
    require(not native.active_consumer_deferred_snapshot_matches(legacy, dict(tx=1, pool=2)),
        'legacy baseline incorrectly accepted the observed 1/2 state')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--configured-dir', type=Path, required=True)
    args = parser.parse_args()
    native = load_fixture('native_packets_fixture', Path(__file__).with_name('session-native-packets.py'))
    private_hugepage_cleanup_checks(native)
    handoff_socket_budget_checks(native)
    observer = load_fixture('tc3_observer_fixture', Path(__file__).with_name('session-tc3-observer.py'))
    coordinate = load_fixture('coordinate_fixture', Path(__file__).with_name('session-coordinate.py'))
    drain_peer = load_fixture('drain_peer_fixture', Path(__file__).with_name('session-drain-peer.py'))
    runner = load_fixture('ker_session_run_fixture', runner_script_path())
    active_consumer_reap_oracle_checks(native, runner)
    configured = args.configured_dir.resolve(strict=True)

    native_paths = native.resolve_dpdk_plugin_paths(configured, ('mempool_ring',), {})
    observer_paths = observer.resolve_dpdk_plugin_paths(configured, ('mempool_ring', 'net_ring'), {})
    coordinate_paths = coordinate.resolve_dpdk_plugin_paths(configured, ('mempool_ring',), {})
    drain_paths = drain_peer.resolve_dpdk_plugin_paths(configured, ('mempool_ring', 'net_ring'), {})
    env_paths = native.resolve_dpdk_plugin_paths(None, ('mempool_ring',),
        {'KER_DPDK_PLUGIN_DIR': str(configured)})
    require(len(native_paths) == 1 and len(observer_paths) == 2 and
            len(coordinate_paths) == 1 and len(drain_paths) == 2,
            'fixtures did not request their exact module sets')
    require(native_paths[0] == observer_paths[0] == coordinate_paths[0] ==
            drain_paths[0] == env_paths[0] and observer_paths[1] == drain_paths[1],
            'fixtures selected different configured PMD files')
    require(all(Path(path).is_file() and os.access(path, os.R_OK) for path in
                native_paths + observer_paths + coordinate_paths + drain_paths),
            'configured PMD selection is not readable regular files')

    with tempfile.TemporaryDirectory(prefix='ker-session-pmd-custom-') as directory:
        custom = (Path(directory) / 'prefix with spaces').resolve()
        custom.mkdir()
        fdinfo = custom / 'fdinfo'
        fdinfo.mkdir()
        (fdinfo / '3').write_text('pos:\t0\nflags:\t02000002\niff:\tkex12345678\n')
        (fdinfo / '4').write_text('pos:\t0\nflags:\t02000002\niff:\tkersession0\n')
        (fdinfo / '5').write_text('pos:\t0\nflags:\t02000002\n')
        require(set(runner.tap_interfaces_for_process(12345, fdinfo_dir=fdinfo)) ==
                {'kex12345678', 'kersession0'},
                'launcher fdinfo helper did not read every original TUN interface record')
        original_error = ValueError('profile failed first')
        cleanup_error = RuntimeError('stage=post-reap-before-unlink path=/huge/map_0 expected=old actual=new')
        original_report = io.StringIO()
        try:
            with contextlib.redirect_stdout(original_report):
                try:
                    raise original_error
                finally:
                    native.report_hugepage_cleanup_refusal('peer-death', sys.exc_info()[1], cleanup_error)
        except ValueError as error:
            require(error is original_error,
                'hugepage cleanup refusal replaced the active profile exception')
        else:
            require(False, 'active profile exception did not propagate after cleanup refusal')
        original_marker = json.loads(original_report.getvalue().strip().split(' ', 1)[1])
        require(original_marker['original'] == {'type': 'ValueError', 'message': str(original_error)} and
                original_marker['cleanup'] == {'type': 'RuntimeError', 'message': str(cleanup_error)},
                'combined cleanup marker omitted the original or cleanup diagnostic')
        cleanup_report = io.StringIO()
        try:
            with contextlib.redirect_stdout(cleanup_report):
                native.report_hugepage_cleanup_refusal('peer-death', None, cleanup_error)
        except RuntimeError as error:
            require(error is cleanup_error, 'cleanup refusal did not propagate when no profile error existed')
        else:
            require(False, 'cleanup refusal was swallowed without an active profile exception')
        module_names = ('mempool_ring', 'net_ring')
        expected = []
        for module in module_names:
            versioned = custom / ('librte_' + module + '.so.custom-test')
            versioned.write_bytes(b'\x7fELFcustom-prefix-test')
            (custom / ('librte_' + module + '.so')).symlink_to(versioned.name)
            expected.append(str(versioned.resolve(strict=True)))
        fallback_env = {'KER_DPDK_PLUGIN_DIR': str(custom)}
        forwarded = native.resolve_dpdk_plugin_dir(custom, {})
        namespace_args = dict(
            huge_dir=custom / 'huge pages', worker=custom / 'worker', tool=custom / 'tool',
            library=custom / 'library', app=custom / 'app')
        command = native.namespace_reexec_command(SimpleNamespace(**namespace_args), forwarded,
            script=custom / 'session-native-packets.py')
        require(command[0:3] == ['unshare', '-Urn', os.sys.executable] and
                command[3] == str(custom / 'session-native-packets.py') and
                command[command.index('--dpdk-plugin-dir') + 1] == str(custom),
                'native namespace re-exec did not preserve explicit canonical plugin paths')
        require(command[command.index('--huge-dir') + 1] == str(custom / 'huge pages'),
                'native namespace re-exec split a path containing spaces')
        explicit_false = native.namespace_reexec_command(SimpleNamespace(
            **namespace_args, handoff_negative_profiles=False), forwarded,
            script=custom / 'session-native-packets.py')
        require('--handoff-negative-profiles' not in explicit_false,
                'explicit false handoff profile option was forwarded')
        require(command == explicit_false,
                'omitted and explicit false handoff profile options changed the re-exec command')
        explicit_true = native.namespace_reexec_command(SimpleNamespace(
            **namespace_args, handoff_negative_profiles=True), forwarded,
            script=custom / 'session-native-packets.py')
        require(explicit_true.count('--handoff-negative-profiles') == 1,
                'enabled handoff negative profiles were not forwarded exactly once')
        fallback = observer.resolve_dpdk_plugin_paths(None, module_names, fallback_env)
        native_fallback = native.resolve_dpdk_plugin_paths(None, ('mempool_ring',), fallback_env)
        explicit = native.resolve_dpdk_plugin_paths(custom, ('mempool_ring',),
            {'KER_DPDK_PLUGIN_DIR': str(configured)})
        observer_explicit = observer.resolve_dpdk_plugin_paths(custom, module_names,
            {'KER_DPDK_PLUGIN_DIR': str(configured)})
        require(fallback == expected, 'environment-selected custom prefix did not canonicalize plugin files')
        require(native_fallback == expected[:1], 'native fixture environment fallback selected wrong prefix')
        require(explicit == expected[:1], 'native fixture explicit prefix did not override environment fallback')
        require(observer_explicit == expected, 'observer fixture explicit prefix did not override environment fallback')
        coordinate_explicit = coordinate.resolve_dpdk_plugin_paths(custom, ('mempool_ring',),
            {'KER_DPDK_PLUGIN_DIR': str(configured)})
        drain_explicit = drain_peer.resolve_dpdk_plugin_paths(custom, module_names,
            {'KER_DPDK_PLUGIN_DIR': str(configured)})
        native_eal = shlex.split(native.dpdk_plugin_eal_options(explicit))
        observer_eal = shlex.split(observer.dpdk_plugin_eal_options(observer_explicit))
        coordinate_eal = shlex.split(coordinate.dpdk_plugin_eal_options(coordinate_explicit))
        drain_eal = shlex.split(drain_peer.dpdk_plugin_eal_options(drain_explicit))
        require(native_eal == ['-d', expected[0]], 'native EAL -d path with spaces was not quoted')
        require(observer_eal == ['-d', expected[0], '-d', expected[1]],
                'observer EAL -d paths with spaces were not quoted')
        require(coordinate_eal == ['-d', expected[0]],
                'coordinate EAL -d path with spaces was not quoted')
        require(drain_eal == ['-d', expected[0], '-d', expected[1]],
                'drain-peer EAL -d paths with spaces were not quoted')
        for fixture, modules in ((native, ('mempool_ring', 'net_null')),
                                 (observer, ('mempool_ring', 'net_ring', 'net_null')),
                                 (coordinate, ('mempool_ring', 'net_null')),
                                 (drain_peer, ('mempool_ring', 'net_ring', 'net_null'))):
            expect_error(lambda fixture=fixture, modules=modules:
                fixture.resolve_dpdk_plugin_paths(custom, modules, {}), 'missing module')
        for fixture in (native, observer, coordinate, drain_peer):
            expect_error(lambda fixture=fixture:
                fixture.resolve_dpdk_plugin_paths(None, ('mempool_ring',), {}), 'missing configuration')
        expect_error(lambda: native.resolve_dpdk_plugin_paths(custom / 'missing', ('mempool_ring',), {}),
            'missing directory')

    print('SESSION_DPDK_PLUGIN_DISCOVERY_PASS configured=' + str(configured) +
          ' native=mempool_ring observer=mempool_ring,net_ring coordinate=mempool_ring '
          'drain-peer=mempool_ring,net_ring custom-prefix=PASS missing-module/config=FAIL-CLOSED')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
