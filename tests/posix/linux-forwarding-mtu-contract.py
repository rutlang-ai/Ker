"""Coverage contract for the complete upstream minimum/maximum MTU shell."""
import re
import json


def require(value, message):
    if not value:
        raise RuntimeError(message)


def validate_evidence(report):
    original = report.get('original', {})
    names = ['ping', 'ping6', 'Test maximum MTU configuration',
             'Test traffic, packet size is maximum MTU', 'Test minimum MTU configuration',
             'Test traffic, packet size is minimum MTU']
    results = [re.fullmatch(r'TEST: (.*?)\s+\[ OK \]', line) for line in original.get('stdout', '').splitlines()]
    require(len(results) == 6 and all(results) and [r[1] for r in results] == names and
            original.get('returncode') == 0 and not original.get('stderr'),
            'incomplete original six-case MTU matrix')
    records = report['commands']
    bounds = [json.loads(r['stdout'])[0] for r in records
              if r['arguments'][:4] == ['-d', '-j', 'link', 'show'] and r['returncode'] == 0]
    require(bounds and len({r['min_mtu'] for r in bounds}) == len({r['max_mtu'] for r in bounds}) == 1,
            'native interface MTU bounds are absent or incompatible')
    minimum, maximum = bounds[0]['min_mtu'], bounds[0]['max_mtu']
    pings = [r for r in records if r['arguments'][:2] == ['vrf', 'exec']]
    require(len(pings) == 7 and [r['returncode'] == 0 for r in pings] ==
            [True, True, True, True, False, False, True], 'incomplete native MTU traffic/error matrix')
    for record in pings:
        args = record['arguments']
        require(args[args.index('-c') + 1] == '10' and args[args.index('-i') + 1] == '0.1' and
                args[args.index('-w') + 1] == '5', 'original ping count or timing changed')
        require(record['vrf']['linkinfo']['info_kind'] == 'vrf', 'MTU ping did not use native VRF')
        if record['returncode'] == 0:
            require('10 received' in record['stdout'], 'MTU boundary ping lost packets')
    changes = [r for r in records if r['arguments'][:3] == ['link', 'set', 'dev'] and 'mtu' in r['arguments']]
    require(changes and sum(r['returncode'] != 0 for r in changes) == 4,
            'missing original native min-1/max+1 MTU rejections')
    require([(r['arguments'][3], int(r['arguments'][-1])) for r in changes if r['returncode']] ==
            [('veth0', maximum + 1), ('veth1', maximum + 1), ('veth0', minimum - 1), ('veth1', minimum - 1)],
            'original boundary configuration errors were not returned by Linux')
    require([int(r['arguments'][r['arguments'].index('-s') + 1]) for r in pings[2:]] ==
            [maximum - 28, maximum - 48, maximum - 28, maximum - 48, minimum - 28],
            'original boundary packet lengths changed')
    expected_failures = [r for r in changes if r['returncode']] + [r for r in pings if r['returncode']]
    expected_failures += [r for r in records if r['arguments'] == ['link', 'show', 'dev', 'veth0']]
    require(all(r in expected_failures for r in records if r['returncode']), 'unexpected native topology/cleanup failure')
    native, stats = report.get('native_fixture', {}), report.get('stats', {})
    require(native.get('netlinks', 0) > 0 and native.get('raw_sockets', 0) > 0 and native.get('live') == 0 and
            stats.get('outstanding') == 0 and stats.get('worker_exit_code') == 0 and
            stats.get('control_eof') is True and stats.get('shutdown_timed_out') is False,
            'native MTU resources did not close normally')
    require(report.get('missing_backend_control', {}).get('returncode') not in (None, 0),
            'original MTU shell passed without native Linux')
    binding = report.get('vrf_binding_control', {})
    require(binding.get('baseline', {}).get('returncode') == 0 and
            binding.get('unknown_vrf', {}).get('returncode') not in (None, 0),
            'native VRF binding control failed')
