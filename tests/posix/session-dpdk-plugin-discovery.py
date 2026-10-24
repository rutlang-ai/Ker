#!/usr/bin/env python3
"""Verify configured and custom-prefix DPDK PMD resolution for session fixtures."""
import argparse
import importlib.util
import os
import shlex
from pathlib import Path
import tempfile
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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--configured-dir', type=Path, required=True)
    args = parser.parse_args()
    native = load_fixture('native_packets_fixture', Path(__file__).with_name('session-native-packets.py'))
    observer = load_fixture('tc3_observer_fixture', Path(__file__).with_name('session-tc3-observer.py'))
    configured = args.configured_dir.resolve(strict=True)

    native_paths = native.resolve_dpdk_plugin_paths(configured, ('mempool_ring',), {})
    observer_paths = observer.resolve_dpdk_plugin_paths(configured, ('mempool_ring', 'net_ring'), {})
    env_paths = native.resolve_dpdk_plugin_paths(None, ('mempool_ring',),
        {'KER_DPDK_PLUGIN_DIR': str(configured)})
    require(len(native_paths) == 1 and len(observer_paths) == 2,
            'fixtures did not request their exact module sets')
    require(native_paths[0] == observer_paths[0] == env_paths[0],
            'fixtures selected different configured mempool_ring files')
    require(all(Path(path).is_file() and os.access(path, os.R_OK) for path in native_paths + observer_paths),
            'configured PMD selection is not readable regular files')

    with tempfile.TemporaryDirectory(prefix='ker-session-pmd-custom-') as directory:
        custom = (Path(directory) / 'prefix with spaces').resolve()
        custom.mkdir()
        module_names = ('mempool_ring', 'net_ring')
        expected = []
        for module in module_names:
            versioned = custom / ('librte_' + module + '.so.custom-test')
            versioned.write_bytes(b'\x7fELFcustom-prefix-test')
            (custom / ('librte_' + module + '.so')).symlink_to(versioned.name)
            expected.append(str(versioned.resolve(strict=True)))
        fallback_env = {'KER_DPDK_PLUGIN_DIR': str(custom)}
        forwarded = native.resolve_dpdk_plugin_dir(custom, {})
        command = native.namespace_reexec_command(SimpleNamespace(
            huge_dir=custom / 'huge pages', worker=custom / 'worker', tool=custom / 'tool',
            library=custom / 'library', app=custom / 'app'), forwarded,
            script=custom / 'session-native-packets.py')
        require(command[0:3] == ['unshare', '-Urn', os.sys.executable] and
                command[3] == str(custom / 'session-native-packets.py') and
                command[command.index('--dpdk-plugin-dir') + 1] == str(custom),
                'native namespace re-exec did not preserve explicit canonical plugin paths')
        require(command[command.index('--huge-dir') + 1] == str(custom / 'huge pages'),
                'native namespace re-exec split a path containing spaces')
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
        native_eal = shlex.split(native.dpdk_plugin_eal_options(explicit))
        observer_eal = shlex.split(observer.dpdk_plugin_eal_options(observer_explicit))
        require(native_eal == ['-d', expected[0]], 'native EAL -d path with spaces was not quoted')
        require(observer_eal == ['-d', expected[0], '-d', expected[1]],
                'observer EAL -d paths with spaces were not quoted')
        expect_error(lambda: observer.resolve_dpdk_plugin_paths(custom, ('mempool_ring', 'net_ring', 'net_null'), {}),
            'missing module')
        expect_error(lambda: native.resolve_dpdk_plugin_paths(None, ('mempool_ring',), {}),
            'missing configuration')
        expect_error(lambda: native.resolve_dpdk_plugin_paths(custom / 'missing', ('mempool_ring',), {}),
            'missing directory')

    print('SESSION_DPDK_PLUGIN_DISCOVERY_PASS configured=' + str(configured) +
          ' native=mempool_ring observer=mempool_ring,net_ring custom-prefix=PASS missing-module=FAIL-CLOSED')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
