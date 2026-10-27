import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock
from contextlib import nullcontext
from types import SimpleNamespace


SOURCE = Path(__file__).with_name('tcp-interop.py')
SPEC = importlib.util.spec_from_file_location('tcp_interop', SOURCE)
tcp_interop = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(tcp_interop)


def completed(stdout=''):
    return subprocess.CompletedProcess([], 0, stdout=stdout, stderr='')


def netem(*, packets=0, drops=0):
    return {'kind': 'netem', 'root': True, 'handle': '8001:', 'packets': packets, 'bytes': packets * 64,
            'drops': drops, 'overlimits': 0}


class TcpFaultSetupTests(unittest.TestCase):
    def test_install_resets_only_root_netem_and_records_fresh_baselines(self):
        calls = []
        show_counts = {'kerlink': 0, 'kerhost': 0}

        def run(command, **kwargs):
            calls.append(command)
            if command[1:4] == ['-j', '-s', 'qdisc']:
                device = command[-1]
                ordinal = show_counts[device]
                show_counts[device] += 1
                if device == 'kerlink' and ordinal == 0:
                    return completed(json.dumps([netem(packets=12, drops=2)]))
                if device == 'kerhost' and ordinal == 0:
                    return completed('[]')
                return completed(json.dumps([netem()]))
            return completed()

        with mock.patch.object(tcp_interop.subprocess, 'run', side_effect=run):
            baseline = tcp_interop.install_tcp_fault_qdiscs({})

        self.assertEqual(baseline['kerlink']['packets'], 0)
        self.assertEqual(baseline['kerlink']['drops'], 0)
        self.assertEqual(baseline['kerhost']['packets'], 0)
        self.assertIn(['tc', 'qdisc', 'del', 'dev', 'kerlink', 'root'], calls)
        self.assertFalse(any(command[:4] == ['tc', 'qdisc', 'del', 'dev'] and
                             command[4] == 'kerhost' for command in calls))
        self.assertEqual(sum(command[:3] == ['tc', 'qdisc', 'add'] for command in calls), 2)

    def test_install_rejects_stale_qdiscs_and_records_nonzero_baseline(self):
        stale = completed(json.dumps([{'kind': 'fq_codel', 'root': True}]))
        with mock.patch.object(tcp_interop.subprocess, 'run', return_value=stale):
            with self.assertRaisesRegex(RuntimeError, 'unexpected root qdisc'):
                tcp_interop.install_tcp_fault_qdiscs({})

        wrong_handle = completed(json.dumps([{'kind': 'netem', 'root': True, 'handle': '8002:'}]))
        with mock.patch.object(tcp_interop.subprocess, 'run', return_value=wrong_handle):
            with self.assertRaisesRegex(RuntimeError, 'unexpected root qdisc'):
                tcp_interop.install_tcp_fault_qdiscs({})

        calls = []

        def nonzero(command, **kwargs):
            calls.append(command)
            if command[1:4] == ['-j', '-s', 'qdisc']:
                return completed(json.dumps([netem(packets=1, drops=1)]))
            return completed()

        with mock.patch.object(tcp_interop.subprocess, 'run', side_effect=nonzero):
            baseline = tcp_interop.install_tcp_fault_qdiscs({})
        self.assertEqual(baseline['kerlink']['packets'], 1)
        self.assertEqual(baseline['kerhost']['drops'], 1)

    def test_post_run_requires_new_packets_and_drops_on_both_devices(self):
        responses = [completed(json.dumps([netem(packets=8, drops=2)])),
                     completed(json.dumps([netem(packets=3, drops=1)]))]
        with mock.patch.object(tcp_interop.subprocess, 'run', side_effect=responses):
            result = tcp_interop.tcp_fault_qdisc_counters({}, {
                'kerlink': {'packets': 7, 'drops': 1},
                'kerhost': {'packets': 2, 'drops': 0},
            })
        self.assertEqual(result['kerlink']['drops'], 2)
        self.assertEqual(result['kerhost']['packets'], 3)

        unchanged = [completed(json.dumps([netem(packets=8, drops=1)]))]
        with mock.patch.object(tcp_interop.subprocess, 'run', side_effect=unchanged):
            with self.assertRaisesRegex(RuntimeError, 'drops counter did not advance'):
                tcp_interop.tcp_fault_qdisc_counters({}, {
                    'kerlink': {'packets': 7, 'drops': 1},
                    'kerhost': {'packets': 2, 'drops': 0},
                })

    def test_cleanup_deletes_only_exact_owned_root_netem(self):
        calls = []

        def run(command, **kwargs):
            calls.append(command)
            if command[1:4] == ['-j', '-s', 'qdisc']:
                return completed(json.dumps([netem()]))
            return completed()

        with mock.patch.object(tcp_interop.subprocess, 'run', side_effect=run):
            tcp_interop.remove_tcp_fault_qdiscs({})
        self.assertEqual([call[4] for call in calls if call[:3] == ['tc', 'qdisc', 'del']],
                         ['kerlink', 'kerhost'])

    def test_cleanup_refuses_foreign_root_qdisc_without_deleting_it(self):
        calls = []

        def run(command, **kwargs):
            calls.append(command)
            return completed(json.dumps([{'kind': 'fq_codel', 'root': True, 'handle': '8001:'}]))

        with mock.patch.object(tcp_interop.subprocess, 'run', side_effect=run):
            with self.assertRaisesRegex(RuntimeError, 'unowned root qdisc'):
                tcp_interop.remove_tcp_fault_qdiscs({})
        self.assertFalse(any(call[:3] == ['tc', 'qdisc', 'del'] for call in calls))

    def test_server_runs_fault_qdisc_cleanup_after_success_and_error(self):
        with tempfile.TemporaryDirectory(prefix='tcp-fault-server-cleanup-') as directory:
            log_path = Path(directory) / 'server.log'
            with log_path.open('w+') as log, mock.patch.object(
                    tcp_interop, 'remove_tcp_fault_qdiscs') as cleanup:
                with tcp_interop.server([sys.executable, '-c',
                        'print("READY 25001",flush=True); print("DONE",flush=True)'],
                        25001, log, {}, cleanup_fault_qdiscs=True):
                    pass
                cleanup.assert_called_once_with({})
            with log_path.open('w+') as log, mock.patch.object(
                    tcp_interop, 'remove_tcp_fault_qdiscs') as cleanup:
                with self.assertRaisesRegex(ValueError, 'preserve original failure'):
                    with tcp_interop.server([sys.executable, '-c',
                            'import time; print("READY 25001",flush=True); time.sleep(30)'],
                            25001, log, {}, cleanup_fault_qdiscs=True):
                        raise ValueError('preserve original failure')
                cleanup.assert_called_once_with({})

    def test_udp_compat_failure_identifies_mode_and_role(self):
        with tempfile.TemporaryDirectory(prefix='tcp-fault-udp-context-') as directory:
            args = SimpleNamespace(udp_app=Path(directory) / 'udp-test')
            with mock.patch.object(tcp_interop, 'server', return_value=nullcontext()), \
                    mock.patch.object(tcp_interop, 'client', side_effect=RuntimeError('epoll timeout')):
                with self.assertRaisesRegex(RuntimeError, 'UDP basic server failed: epoll timeout'):
                    tcp_interop.udp_compat(args, [], Path(directory), {}, None)

    def test_gated_client_installs_faults_before_releasing_client(self):
        with tempfile.TemporaryDirectory(prefix='tcp-fault-gate-test-') as directory:
            root = Path(directory)
            fifo = root / 'release.fifo'
            marker = root / 'qdisc-installed'
            os.mkfifo(fifo)
            code = (
                'import os,sys; '
                'assert os.path.exists(sys.argv[2]); '
                'print("READY 25001",flush=True); '
                'fd=os.open(sys.argv[1],os.O_RDONLY); token=os.read(fd,1); os.close(fd); '
                'assert token==b"\\xa5" and os.path.exists(sys.argv[2]); '
                'print("TCP_INFO total_retrans=1"); '
                'print("PASS: gated fake client",flush=True)'
            )

            def install(_env):
                marker.write_text('installed')
                return {'kerlink': netem(), 'kerhost': netem()}

            pre_release = {'kerlink': netem(packets=1), 'kerhost': netem(packets=2)}
            with mock.patch.object(tcp_interop, 'install_tcp_fault_qdiscs', side_effect=install), \
                    mock.patch.object(tcp_interop, 'tcp_fault_qdisc_snapshot', return_value=pre_release):
                output, installed = tcp_interop.gated_client(
                    [sys.executable, '-c', code, str(fifo), str(marker)], 25001, {}, fifo)
            self.assertIn('PASS: gated fake client', output)
            self.assertTrue(marker.exists())
            self.assertIn('kerlink', installed)
            self.assertEqual(installed, pre_release)

    def test_gated_client_fails_boundedly_if_child_exits_before_fifo_open(self):
        with tempfile.TemporaryDirectory(prefix='tcp-fault-gate-exit-') as directory:
            fifo = Path(directory) / 'release.fifo'
            os.mkfifo(fifo)
            started = time.monotonic()
            with mock.patch.object(tcp_interop, 'install_tcp_fault_qdiscs', return_value={}), \
                    mock.patch.object(tcp_interop, 'tcp_fault_qdisc_snapshot', return_value={}):
                with self.assertRaisesRegex(RuntimeError, 'stopped before fault release'):
                    tcp_interop.gated_client(
                        [sys.executable, '-c', 'print("READY 25001",flush=True)'],
                        25001, {}, fifo)
            self.assertLess(time.monotonic() - started, 2)


if __name__ == '__main__':
    unittest.main(verbosity=2)
