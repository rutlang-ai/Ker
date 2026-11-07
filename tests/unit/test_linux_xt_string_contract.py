"""Reject incomplete or synthetic native string matching evidence."""
import copy
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('xt_string', ROOT / 'tests/posix/linux-xt-string-selftest.py')
contract = importlib.util.module_from_spec(spec); spec.loader.exec_module(contract)


class StringContractTests(unittest.TestCase):
    def test_original_boundaries_counters_and_cleanup_are_required(self):
        original = json.loads(Path(__file__).with_name('xt-string-transcript.json').read_text())
        for mutation in ('complete', 'missing-send', 'payload', 'timeout', 'algorithm', 'counter', 'bytes',
                         'missing-window', 'missing-reset', 'reset-order', 'warning', 'host-fallback', 'leak', 'forced-stop'):
            with self.subTest(mutation=mutation):
                report = copy.deepcopy(original); rows = report['commands']
                sends = [r for r in rows if r['tool'] == 'socat' and r['arguments'] != ['-h']]
                counters = [r for r in rows if r['arguments'] == ['-v', '-S', 'OUTPUT']]
                if mutation == 'missing-send': rows.remove(sends[-1])
                elif mutation == 'payload': sends[5]['stdin'] += ' '
                elif mutation == 'timeout': sends[0]['arguments'][1] = '5'
                elif mutation == 'algorithm': counters[3]['stdout'] = counters[3]['stdout'].replace('--algo kmp', '--algo bm')
                elif mutation == 'counter': counters[3]['stdout'] = counters[3]['stdout'].replace('-c 1 1506', '-c 0 0')
                elif mutation == 'bytes': counters[3]['stdout'] = counters[3]['stdout'].replace('-c 1 1506', '-c 1 1500')
                elif mutation == 'missing-window': rows.remove(counters[-1])
                elif mutation == 'missing-reset': report['commands'] = [r for r in rows if r['arguments'] != ['-Z', 'OUTPUT']]
                elif mutation == 'reset-order':
                    reset = next(r for r in rows if r['arguments'] == ['-Z', 'OUTPUT']); rows.remove(reset); rows.append(reset)
                elif mutation == 'warning': sends[0]['stderr'] = 'failed to send\n'
                elif mutation == 'host-fallback': report['missing_backend_control']['returncode'] = 0
                elif mutation == 'leak': report['native_fixture']['namespaces_deleted'] = 0
                elif mutation == 'forced-stop': report['stats']['shutdown_timed_out'] = True
                if mutation == 'complete': contract.validate_evidence(report)
                else:
                    with self.assertRaises(RuntimeError): contract.validate_evidence(report)


if __name__ == '__main__': unittest.main()
