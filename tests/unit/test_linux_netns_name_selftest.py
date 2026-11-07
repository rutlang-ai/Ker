"""Reject shell success when any original native conflict/visibility branch is absent."""
import copy
import importlib.util
import json
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('netns_name_runner',
    Path(__file__).resolve().parents[1] / 'posix/linux-netns-name-selftest.py')
runner = importlib.util.module_from_spec(spec); spec.loader.exec_module(runner)


class NamespaceNameMatrixTests(unittest.TestCase):
    def test_original_success_marker_cannot_replace_conflicts_and_visibility(self):
        complete = json.loads(Path(__file__).with_name('netns-name-commands.json').read_text())
        runner.validate_commands(complete)
        for mutation in ('missing-move', 'conflict-accepted', 'wrong-native-error',
                         'missing-rename', 'old-namespace-still-visible', 'same-namespace', 'missing-tool'):
            with self.subTest(mutation=mutation):
                records = copy.deepcopy(complete)
                moves = [r for r in records if r['operation'] == 'move']
                shows = [r for r in records if r['operation'] == 'ip' and r['arguments'][:2] == ['link', 'show']]
                if mutation == 'missing-move':
                    records.remove(moves[-1])
                elif mutation == 'conflict-accepted':
                    moves[1]['returncode'] = 0
                elif mutation == 'wrong-native-error':
                    moves[1]['errno'] = 95
                elif mutation == 'missing-rename':
                    moves[2]['arguments'] = moves[2]['arguments'][:-2]
                elif mutation == 'old-namespace-still-visible':
                    shows[-1]['returncode'] = 0
                elif mutation == 'same-namespace':
                    shows[-1]['namespace'] = shows[-2]['namespace']
                else:
                    records.remove(next(r for r in records if r['operation'] == 'ip'))
                with self.assertRaises(RuntimeError):
                    runner.validate_commands(records)


if __name__ == '__main__':
    unittest.main()
