#!/usr/bin/env python3
"""Verify configured and custom-prefix DPDK PMD resolution for session fixtures."""
import argparse
import contextlib
import importlib.util
import io
import json
import os
import shlex
from pathlib import Path
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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--configured-dir', type=Path, required=True)
    args = parser.parse_args()
    native = load_fixture('native_packets_fixture', Path(__file__).with_name('session-native-packets.py'))
    observer = load_fixture('tc3_observer_fixture', Path(__file__).with_name('session-tc3-observer.py'))
    coordinate = load_fixture('coordinate_fixture', Path(__file__).with_name('session-coordinate.py'))
    drain_peer = load_fixture('drain_peer_fixture', Path(__file__).with_name('session-drain-peer.py'))
    runner = load_fixture('ker_session_run_fixture', runner_script_path())
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
