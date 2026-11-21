import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import select
import signal
import sys
import struct
import subprocess
import tempfile
import time
import unittest
from unittest import mock


sys.dont_write_bytecode = True
MODULE_PATH = Path(__file__).resolve().parents[2] / 'tools' / 'ker-run.py'
SPEC = importlib.util.spec_from_file_location('ker_run', MODULE_PATH)
ker_run = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ker_run)


class PrivateC31ShutdownParserTests(unittest.TestCase):
    def setUp(self):
        self.nonce = bytes(range(1, 17))
        self.epoch = 19
        self.worker = (1234, os.getuid(), os.getgid(), 101)
        self.supervisor = (5678, os.getuid(), os.getgid(), 202)
        header = struct.pack('<IHHII16sQQQQ', 0x4b525844, 2, 7, 64, 80,
            self.nonce, self.epoch, 0, 3, 0)
        body = struct.pack('<QII', 1, 0, 0)
        self.record = header + body
        self.value = {'record_hex': self.record.hex(), 'worker_pid': self.worker[0],
            'worker_uid': self.worker[1], 'worker_gid': self.worker[2],
            'worker_start_ticks': self.worker[3], 'supervisor_pid': self.supervisor[0],
            'supervisor_uid': self.supervisor[1], 'supervisor_gid': self.supervisor[2],
            'supervisor_start_ticks': self.supervisor[3], 'nonce': self.nonce.hex(),
            'epoch': self.epoch, 'last_packet_id': 1, 'last_result_id': 1,
            'outstanding_count': 0, 'status': 0}
        self.io = {'rx_decision_enabled': True, 'rx_decision_settled': True,
            'control_eof': True, 'outstanding': 0,
            'rx_decision_last_settled_packet_id': 1}

    def _status(self, value=None, order=('ready', 'stopping', 'receipt', 'done')):
        value = self.value if value is None else value
        encoded = json.dumps(value, separators=(',', ':')).encode()
        mapping = {'ready': b'KER_NATIVE_READY\n',
            'stopping': b'KER_NATIVE_STOPPING\n',
            'receipt': b'KER_C31_SHUTDOWN ' + encoded + b'\n',
            'done': b'KER_NATIVE_DONE\n'}
        return b''.join(mapping[key] for key in order)

    def _parse(self, status=None, io=None):
        return ker_run.private_c31_shutdown_record(
            self._status() if status is None else status,
            self.io if io is None else io, worker_identity=self.worker,
            supervisor_identity=self.supervisor, nonce=self.nonce, epoch=self.epoch)

    def test_private_c31_settled_receipt_joins_wire_actors_and_io_done(self):
        parsed = self._parse()
        self.assertEqual(parsed['record_hex'], self.record.hex())

    def test_private_c31_idle_settlement_accepts_zero_packet_ids(self):
        header = self.record[:64]
        idle_record = header + struct.pack('<QII', 0, 0, 0)
        value = dict(self.value, record_hex=idle_record.hex(),
            last_packet_id=0, last_result_id=0)
        io = dict(self.io, rx_decision_last_settled_packet_id=0)
        self.assertEqual(self._parse(status=self._status(value), io=io)['last_packet_id'], 0)

    def test_private_c31_settled_rejects_duplicate_malformed_order_and_mismatch(self):
        bad_value = dict(self.value, record_hex='00')
        wrong_wire = bytearray(self.record); wrong_wire[16] ^= 1
        cases = [
            self._status(order=('ready', 'stopping', 'receipt', 'receipt', 'done')),
            self._status(order=('ready', 'receipt', 'stopping', 'done')),
            self._status(bad_value),
            self._status(dict(self.value, worker_pid=self.worker[0] + 1)),
            self._status(dict(self.value, last_result_id=2)),
            self._status(dict(self.value, record_hex=bytes(wrong_wire).hex())),
            self._status(dict(self.value, status=1)),
            self._status(dict(self.value, worker_start_ticks=-1)),
        ]
        for status in cases:
            with self.subTest(status=status[:40]):
                with self.assertRaises(ValueError):
                    self._parse(status=status)
        for io in (dict(self.io, rx_decision_last_settled_packet_id=2),
                   dict(self.io, rx_decision_settled=False)):
            with self.subTest(io=io):
                with self.assertRaises(ValueError):
                    self._parse(io=io)

    def test_private_c31_rejects_duplicate_json_keys_and_boolean_io_counters(self):
        line = self._status().splitlines()[2]
        payload = line[len(b'KER_C31_SHUTDOWN '):]
        duplicate = payload[:-1] + b',"status":0}'
        status = b'KER_NATIVE_READY\nKER_NATIVE_STOPPING\nKER_C31_SHUTDOWN ' + duplicate + b'\nKER_NATIVE_DONE\n'
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            self._parse(status=status)
        for key in ('rx_decision_last_settled_packet_id', 'outstanding'):
            with self.subTest(key=key):
                io = dict(self.io, **{key: True})
                with self.assertRaises(ValueError):
                    self._parse(io=io)

    def test_actual_c_formatter_max_width_line_is_bounded_and_parseable(self):
        source = MODULE_PATH.parents[1] / 'tests' / 'posix' / 'c31-shutdown-line-host.c'
        include = MODULE_PATH.parents[1] / 'src' / 'posix'
        with tempfile.TemporaryDirectory(prefix='ker-c31-line-') as tmp:
            binary = Path(tmp) / 'formatter'
            subprocess.run(['/usr/bin/cc', '-std=c11', '-Wall', '-Wextra', '-Werror',
                '-I', str(include), str(source), '-o', str(binary)], check=True,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            output = subprocess.run([str(binary)], check=True, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE).stdout
        self.assertLess(len(output), 640)
        self.assertTrue(output.startswith(b'KER_C31_SHUTDOWN '))
        self.assertTrue(output.endswith(b'\n'))
        worker = (2**32 - 1, 2**32 - 1, 2**32 - 1, 2**64 - 1)
        supervisor = worker
        nonce = bytes([0xa5]) * 16
        io = {'rx_decision_enabled': True, 'rx_decision_settled': True,
            'control_eof': True, 'outstanding': 0,
            'rx_decision_last_settled_packet_id': 2**64 - 1}
        status = b'KER_NATIVE_READY\nKER_NATIVE_STOPPING\n' + output + b'KER_NATIVE_DONE\n'
        parsed = ker_run.private_c31_shutdown_record(status, io,
            worker_identity=worker, supervisor_identity=supervisor,
            nonce=nonce, epoch=2**64 - 1)
        self.assertEqual(parsed['epoch'], 2**64 - 1)
        self.assertEqual(parsed['worker_pid'], 2**32 - 1)

    def test_actual_c_line_and_io_done_join_over_exited_popen_pipes(self):
        source = MODULE_PATH.parents[1] / 'tests' / 'posix' / 'c31-shutdown-line-host.c'
        include = MODULE_PATH.parents[1] / 'src' / 'posix'
        nonce = bytes(range(16))
        epoch, packet_id = 19, 7
        with tempfile.TemporaryDirectory(prefix='ker-c31-streams-') as tmp:
            binary = Path(tmp) / 'formatter'
            subprocess.run(['/usr/bin/cc', '-std=c11', '-Wall', '-Wextra', '-Werror',
                '-I', str(include), str(source), '-o', str(binary)], check=True,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            worker_code = ("import os,time; os.write(1,b'KER_IO_READY {}\\n"
                "KER_IO_DONE {\\\"outstanding\\\":0,\\\"rx_decision_last_settled_packet_id\\\":7,"
                "\\\"rx_decision_enabled\\\":true,\\\"rx_decision_settled\\\":true,"
                "\\\"control_eof\\\":true}\\n'); time.sleep(.1)")
            worker = subprocess.Popen([sys.executable, '-u', '-c', worker_code],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            worker_pidfd = os.pidfd_open(worker.pid, 0)
            worker_ticks = ker_run.process_start_ticks(worker.pid)
            io_stdout_identity = ker_run._private_pipe_identity(worker.stdout.fileno())
            supervisor = (os.getpid(), os.getuid(), os.getgid(),
                ker_run.process_start_ticks(os.getpid()))
            worker_identity = (worker.pid, os.getuid(), os.getgid(), worker_ticks)
            formatter = subprocess.run([str(binary), str(worker.pid), str(os.getuid()),
                str(os.getgid()), str(worker_ticks), str(supervisor[0]),
                str(supervisor[1]), str(supervisor[2]), str(supervisor[3]),
                str(epoch), str(packet_id), nonce.hex()], check=True,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout
            native = {'buffer_allocations':0,'buffer_releases':0,
                'buffer_shutdown_releases':0,'buffers_live':0,'buffer_bytes':0,
                'buffer_option_guards_live':0}
            startup_payload = (b'KER_NATIVE_READY\nKER_NATIVE_STOPPING\n' + formatter +
                b'KER_NATIVE_STATS ' + json.dumps(native,separators=(',',':')).encode() +
                b'\nKER_NATIVE_DONE\n')
            startup_read, startup_write = os.pipe2(os.O_CLOEXEC | os.O_NONBLOCK)
            startup_identity = ker_run._private_pipe_identity(startup_read)
            producer = subprocess.Popen([sys.executable, '-c',
                'import os,sys,time; os.write(int(sys.argv[1]),bytes.fromhex(sys.argv[2])); time.sleep(.1)',
                str(startup_write), startup_payload.hex()], pass_fds=(startup_write,),
                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            os.close(startup_write)
            producer_pidfd = os.pidfd_open(producer.pid, 0)
            try:
                self.assertGreater(ker_run.process_start_ticks(producer.pid), 0)
                self.assertEqual(producer.communicate(timeout=3), (b'', b''))
                self.assertEqual(producer.returncode, 0)
                self.assertTrue(ker_run._private_pidfd_exited(producer_pidfd))
                ready = ker_run.read_worker_startup(worker, 'coalesced C31 fixture', timeout=2)
                self.assertTrue(ready.startswith('KER_IO_READY '))
                startup, worker_output = ker_run._read_private_shutdown_pipes(
                    startup_read, worker.stdout.fileno(), b'', startup_identity,
                    io_stdout_identity, time.monotonic_ns() + 2_000_000_000)
                self.assertEqual(worker.wait(timeout=2), 0)
                self.assertTrue(ker_run._private_pidfd_exited(worker_pidfd))
            finally:
                os.close(startup_read)
                os.close(producer_pidfd)
                os.close(worker_pidfd)
                if worker.poll() is None:
                    worker.kill()
                    worker.wait(timeout=2)
                worker.stdout.close()
                worker.stderr.close()
            io_stats = ker_run._private_io_done_record(worker_output)
            parsed = ker_run.private_c31_shutdown_record(bytes(startup), io_stats,
                worker_identity=worker_identity, supervisor_identity=supervisor,
                nonce=nonce, epoch=epoch)
            self.assertEqual(parsed['last_packet_id'], packet_id)

    def test_io_ready_and_done_coalesced_write_retains_done_for_single_reader(self):
        payload = (b'KER_IO_READY {"port_id":0}\n' +
            b'KER_IO_DONE {"outstanding":0,"rx_decision_last_settled_packet_id":0,'
            b'"rx_decision_enabled":true,"rx_decision_settled":true,"control_eof":true}\n')
        code = ('import os,sys,time; os.write(1,bytes.fromhex(sys.argv[1])); time.sleep(.05)')
        process = subprocess.Popen([sys.executable, '-c', code, payload.hex()],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        pidfd = os.pidfd_open(process.pid, 0)
        try:
            pipe_identity = ker_run._private_pipe_identity(process.stdout.fileno())
            ready = ker_run.read_worker_startup(process, 'coalesced private I/O', timeout=2)
            self.assertTrue(ready.startswith('KER_IO_READY '))
            raw = bytearray()
            fd = process.stdout.fileno()
            while True:
                select.select([fd], [], [], 1)
                chunk = os.read(fd, 4096)
                if not chunk: break
                raw.extend(chunk)
            self.assertEqual(process.wait(timeout=2), 0)
            self.assertTrue(ker_run._private_pidfd_exited(pidfd))
            self.assertEqual(ker_run._private_pipe_identity(fd), pipe_identity)
            stats = ker_run._private_io_done_record(bytes(raw))
            self.assertEqual(stats['rx_decision_last_settled_packet_id'], 0)
        finally:
            os.close(pidfd)
            process.stdout.close()
            process.stderr.close()

    def test_private_io_done_requires_unique_final_well_typed_record(self):
        valid = (b'KER_IO_READY {}\nKER_IO_DONE {"outstanding":0,'
            b'"rx_decision_last_settled_packet_id":1,"rx_decision_enabled":true,'
            b'"rx_decision_settled":true,"control_eof":true}\n')
        self.assertEqual(ker_run._private_io_done_record(valid)['outstanding'], 0)
        malformed = [
            valid[:-1] + b'\nKER_IO_DONE {"outstanding":0}\n',
            valid.replace(b'"outstanding":0',
                b'"outstanding":0,"outstanding":0'),
            valid.replace(b'"rx_decision_last_settled_packet_id":1',
                b'"rx_decision_last_settled_packet_id":true'),
            valid.replace(b'"outstanding":0', b'"outstanding":-1'),
            valid + b'KER_IO_ERROR\n',
            valid[:-1],
        ]
        for raw in malformed:
            with self.subTest(raw=raw[-80:]):
                with self.assertRaises(ValueError):
                    ker_run._private_io_done_record(raw)

    def test_private_startup_prefix_cannot_supply_shutdown_authority(self):
        self.assertTrue(ker_run._validate_private_startup_prefix(
            b'KER_NATIVE_READY\nKER_RX_DECISION_READY\n'))
        for suffix in (b'KER_NATIVE_STOPPING\n', b'KER_C31_SHUTDOWN {}\n',
                b'KER_NATIVE_STATS {}\n', b'KER_NATIVE_DONE\n'):
            with self.subTest(suffix=suffix), self.assertRaises(PermissionError):
                ker_run._validate_private_startup_prefix(b'KER_NATIVE_READY\n' + suffix)

    def test_nested_private_receipt_fields_are_recursively_frozen(self):
        frozen = ker_run._freeze_private_value({'rx_pollers': [{'cpu': 3}]})
        with self.assertRaises(TypeError):
            frozen['rx_pollers'][0]['cpu'] = 4
        with self.assertRaises(AttributeError):
            frozen['rx_pollers'].append({'cpu': 4})

    def test_private_run_stop_does_not_read_shutdown_pipe_ahead_of_collector(self):
        prefix = b'KER_NATIVE_READY\nKER_RX_DECISION_READY\n'
        with mock.patch.object(ker_run.os, 'read', side_effect=AssertionError(
                'private collector must remain the sole startup-pipe reader')):
            self.assertEqual(ker_run._validate_run_stop_request(91, prefix, True), prefix)

    def test_legacy_run_stop_still_requires_native_done_from_startup_pipe(self):
        read_fd, write_fd = os.pipe2(os.O_CLOEXEC | os.O_NONBLOCK)
        self.addCleanup(os.close, read_fd)
        self.addCleanup(os.close, write_fd)
        os.write(write_fd, b'KER_NATIVE_DONE\n')
        result = ker_run._validate_run_stop_request(read_fd, b'', False)
        self.assertEqual(result, b'KER_NATIVE_DONE\n')


WORKER = f'''#!{sys.executable}
import json, os, select, signal, socket, sys, time
from pathlib import Path
args = sys.argv
fd = int(args[args.index('--control-fd') + 1])
packet_fd = int(args[args.index('--packet-fd') + 1])
port = args[args.index('--port') + 1]
if port == 'aux0' and os.environ.get('FAKE_AUX_MALFORMED') == '1':
    print('KER_IO_DONE not-json', flush=True)
    sys.exit(0)
if port == 'aux0' and os.environ.get('FAKE_AUX_SIGNAL') == '1':
    Path(os.environ['FAKE_AUX_PID_FILE']).write_text(str(os.getpid()))
    def stop(signum, frame):
        print('KER_IO_DONE {{"outstanding": 0}}', flush=True)
        Path(os.environ['FAKE_AUX_DONE_FILE']).write_text(str(time.monotonic_ns()))
        sys.exit(0)
    signal.signal(signal.SIGTERM, stop)
    print('KER_IO_READY ' + json.dumps({{'mac': '02:00:00:00:00:02', 'tx_offload_features': 0}}), flush=True)
    while True: signal.pause()
if os.environ.get('FAKE_RUNTIME_SERVICE_READY') == '1':
    ready_record = {{'mac': '02:00:00:00:00:01', 'tx_offload_features': 0}}
    ready_record.update(process_type='primary', mbuf_pool_count=4, queues=1)
    print('KER_IO_READY ' + json.dumps(ready_record), flush=True)
else:
    print('KER_IO_READY ' + json.dumps({{'mac': '02:00:00:00:00:01', 'tx_offload_features': 0}}), flush=True)
if port == 'aux0' and os.environ.get('FAKE_AUX_PID_FILE'):
    Path(os.environ['FAKE_AUX_PID_FILE']).write_text(str(os.getpid()))
if os.environ.get('FAKE_PRIMARY_PID_FILE'):
    Path(os.environ['FAKE_PRIMARY_PID_FILE']).write_text(str(os.getpid()))
if os.environ.get('FAKE_WORKER_EXIT_EARLY') == '1':
    print('KER_IO_DONE {{"outstanding": 0}}', flush=True)
    sys.exit(0)
if os.environ.get('FAKE_EXIT_AFTER_STOP_FILE'):
    while not Path(os.environ['FAKE_EXIT_AFTER_STOP_FILE']).exists():
        time.sleep(0.005)
elif os.environ.get('FAKE_EXIT_ON_PACKET_EOF') == '1':
    packet = socket.socket(fileno=os.dup(packet_fd))
    while True:
        readable, _, _ = select.select([fd, packet], [], [], 0.05)
        if fd in readable and not os.read(fd, 1):
            break
        if packet in readable and packet.recv(1, socket.MSG_PEEK) == b'':
            break
else:
    while os.read(fd, 1): pass
if port == 'aux0' and os.environ.get('FAKE_AUX_DUPLICATE') == '1':
    print('KER_IO_DONE ' + json.dumps({{'outstanding': int(os.environ['FAKE_AUX_DUPLICATE_FIRST'])}}), flush=True)
    print('KER_IO_DONE ' + json.dumps({{'outstanding': int(os.environ['FAKE_AUX_DUPLICATE_LAST'])}}), flush=True)
else:
    print('KER_IO_DONE {{"outstanding": 0}}', flush=True)
sys.exit(int(os.environ.get('FAKE_AUX_WORKER_EXIT' if port == 'aux0' else 'FAKE_WORKER_EXIT', '0')))
'''

APP_GUARD = f'''#!{sys.executable}
import os, sys
status = b'KER_NATIVE_READY\\n'
if 'FAKE_NATIVE_TERMINAL' in os.environ:
    status += os.environ['FAKE_NATIVE_TERMINAL'].encode()
else:
    if os.environ.get('FAKE_NATIVE_STOPPING') == '1':
        status += b'KER_NATIVE_STOPPING\\n'
    if os.environ.get('FAKE_NATIVE_DONE') == '1':
        status += b'KER_NATIVE_DONE\\n'
os.write(int(os.environ['KER_STARTUP_FD']), status)
os.execvpe(sys.argv[1], sys.argv[1:], os.environ)
'''


class WorkerQueueProofTests(unittest.TestCase):
    nonce = '0123456789abcdef0123456789abcdef'
    epoch = 91
    pid = 4321

    def record(self, **proof_changes):
        proof = {
            'version': 1, 'worker_pid': self.pid,
            'session_nonce': self.nonce, 'session_epoch': self.epoch,
            'role': 'native-io-owner', 'source_proc_id': 1, 'port_id': 0,
            'queues': [{'queue_id': 0, 'owner_eal_lcore': 1,
                'observed_eal_lcore': 1, 'allowed_cpus': [7], 'actual_cpu': 7}],
        }
        proof.update(proof_changes)
        return 'KER_IO_READY ' + json.dumps({
            'mac': '02:00:00:00:00:01', 'tx_offload_features': 0,
            'queue_owner_proof': proof})

    def parse(self, line=None, **kwargs):
        return ker_run.worker_ready_record(line or self.record(),
            expected_pid=self.pid, expected_session=(self.nonce, self.epoch),
            require_queue_proof=True, expected_port_id=0,
            expected_queue_lcores=(1,), expected_source_proc_id=1, **kwargs)

    def test_valid_actual_queue_proof_shape(self):
        value = self.parse()
        self.assertEqual(value['queue_owner_proof']['queues'][0]['actual_cpu'], 7)

    def test_legacy_ready_only_allowed_when_proof_is_optional(self):
        legacy = 'KER_IO_READY ' + json.dumps({'mac': '02:00:00:00:00:01',
            'tx_offload_features': 0})
        self.assertEqual(ker_run.worker_ready_record(legacy)['mac'], '02:00:00:00:00:01')
        with self.assertRaisesRegex(RuntimeError, 'requires native queue-owner'):
            self.parse(legacy)

    def test_process_session_role_and_port_must_match(self):
        for changes, expected in (
                ({'worker_pid': self.pid + 1}, 'process/session mismatch'),
                ({'session_nonce': 'f' * 32}, 'process/session mismatch'),
                ({'session_epoch': self.epoch + 1}, 'process/session mismatch'),
                ({'source_proc_id': 0}, 'source role mismatch'),
                ({'port_id': 1}, 'port mismatch')):
            with self.subTest(changes=changes), self.assertRaisesRegex(RuntimeError, expected):
                self.parse(self.record(**changes))

    def test_schema_queue_coverage_lcore_and_cpu_are_strict(self):
        proof = json.loads(self.record().removeprefix('KER_IO_READY '))['queue_owner_proof']
        mutations = (
            ({'version': True}, 'schema'),
            ({'session_nonce': '0123456789ABCDEF0123456789ABCDEF'}, 'schema'),
            ({'queues': []}, 'schema'),
            ({'queues': [{'queue_id': 0, 'owner_eal_lcore': 1,
                'observed_eal_lcore': 0, 'allowed_cpus': [7], 'actual_cpu': 7}]}, 'invalid.*entry'),
            ({'queues': [{'queue_id': 0, 'owner_eal_lcore': 1,
                'observed_eal_lcore': 1, 'allowed_cpus': [7], 'actual_cpu': -1}]}, 'entry'),
            ({'queues': [{'queue_id': 0, 'owner_eal_lcore': 1,
                'observed_eal_lcore': 1, 'allowed_cpus': [8], 'actual_cpu': 7}]}, 'entry'),
            ({'queues': [{'queue_id': 0, 'owner_eal_lcore': 1,
                'observed_eal_lcore': 1, 'allowed_cpus': [7, 8], 'actual_cpu': 7}]}, 'single-CPU'),
            ({'queues': [proof['queues'][0], proof['queues'][0]]}, 'queue count'),
        )
        for changes, expected in mutations:
            proof_value = dict(proof); proof_value.update(changes)
            line = 'KER_IO_READY ' + json.dumps({'mac': '02:00:00:00:00:01',
                'tx_offload_features': 0, 'queue_owner_proof': proof_value})
            with self.subTest(changes=changes), self.assertRaisesRegex(RuntimeError, expected):
                self.parse(line)


class KerRunMainTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tempdir = tempfile.TemporaryDirectory(prefix='ker-run-test-')
        cls.root = Path(cls.tempdir.name)
        cls.worker = cls.root / 'ker-io-worker'
        cls.guard = cls.root / 'ker-app'
        cls.library = cls.root / 'libker-posix.so'
        cls.config = cls.root / 'multiport.ini'
        cls.config.write_text('[interface.aux]\naddress=198.19.0.2/24\n'
                              'port=aux0\neal=--no-pci\n')
        cls.aux_pid_file = cls.root / 'aux.pid'
        cls.aux_done_file = cls.root / 'aux.done'
        cls.app_start_file = cls.root / 'app.start'
        cls.app_done_file = cls.root / 'app.done'
        cls.worker.write_text(WORKER)
        cls.guard.write_text(APP_GUARD)
        cls.worker.chmod(0o755)
        cls.guard.chmod(0o755)
        cls.library.touch()

    @classmethod
    def tearDownClass(cls):
        cls.tempdir.cleanup()

    def test_runtime_service_resolves_bare_command_through_path(self):
        with tempfile.TemporaryDirectory(prefix='ker-run-path-') as directory:
            command = Path(directory) / 'python-runtime-service'
            command.symlink_to(sys.executable)
            resolved = ker_run.resolve_runtime_service_app_executable(
                command.name, directory)
            self.assertEqual(resolved, Path(sys.executable).resolve())

    def test_runtime_service_launches_path_resolved_elf(self):
        with tempfile.TemporaryDirectory(prefix='ker-run-launch-path-') as directory:
            command = Path(directory) / 'python-runtime-service'
            command.symlink_to(sys.executable)
            result = self.run_launcher(0, native_done=True,
                command=[command.name, '-c', 'import sys; sys.exit(0)'],
                runtime_service_enabled=True,
                extra_env={'PATH': directory, 'FAKE_RUNTIME_SERVICE_READY': '1',
                    'PYTHONPATH': str(MODULE_PATH.parent)})
            self.assertEqual(result, 0)

    def test_runtime_service_resolves_explicit_path(self):
        resolved = ker_run.resolve_runtime_service_app_executable(sys.executable)
        self.assertEqual(resolved, Path(sys.executable).resolve())

    def test_runtime_service_resolves_explicit_symlink_to_executed_elf(self):
        with tempfile.TemporaryDirectory(prefix='ker-run-explicit-link-') as directory:
            command = Path(directory) / 'python-link'
            command.symlink_to(sys.executable)
            resolved = ker_run.resolve_runtime_service_app_executable(str(command))
            self.assertEqual(resolved, Path(sys.executable).resolve())

    def test_runtime_service_rejects_missing_path_command(self):
        with tempfile.TemporaryDirectory(prefix='ker-run-empty-path-') as directory:
            with self.assertRaisesRegex(RuntimeError, 'not found on PATH'):
                ker_run.resolve_runtime_service_app_executable(
                    'missing-runtime-service-app', directory)

    def run_launcher(self, app_code, *, native_done, worker_code=0, signal_app=False,
                     config=None, app_source=None, extra_env=None, capture_stderr=False,
                     runtime_service_enabled=False, command=None):
        env = os.environ.copy()
        env.update(FAKE_NATIVE_DONE='1' if native_done else '0',
                   FAKE_WORKER_EXIT=str(worker_code))
        if extra_env:
            env.update(extra_env)
        if app_source is not None:
            app = app_source
        elif signal_app:
            app = 'import os, signal; os.kill(os.getpid(), signal.SIGTERM)'
        else:
            app = f'import sys; sys.exit({app_code})'
        app_command = command if command is not None else [sys.executable, '-c', app]
        argv = ['ker-run.py', '--address', '192.0.2.2/24', '--port', 'fake0',
                '--eal', '', '--library', str(self.library), '--io-worker', str(self.worker),
                *(('--runtime-service',) if runtime_service_enabled else ()),
                *(('--config', str(config)) if config else ()),
                '--', *app_command]
        with (io.StringIO() if capture_stderr else open(os.devnull, 'w')) as stderr, \
                mock.patch.dict(os.environ, env, clear=True), \
                mock.patch.object(sys, 'argv', argv), \
                contextlib.redirect_stderr(stderr):
            result = ker_run.main()
            message = stderr.getvalue() if capture_stderr else ''
        return (result, message) if capture_stderr else result

    def test_missing_native_done_overrides_nonzero_app_exit(self):
        self.assertEqual(self.run_launcher(7, native_done=False), 125)

    def test_worker_failure_overrides_nonzero_app_exit(self):
        self.assertEqual(self.run_launcher(7, native_done=True, worker_code=9), 125)

    def test_successful_backend_preserves_nonzero_app_exit(self):
        self.assertEqual(self.run_launcher(7, native_done=True), 7)

    def test_runtime_service_claim_releases_worker_control_pin(self):
        app = r'''import os, socket
import runtime_service_wire as wire
path = os.environ['KER_RUNTIME_SERVICE_PATH']
nonce = bytes.fromhex(os.environ['KER_RUNTIME_SERVICE_NONCE'])
epoch = int(os.environ['KER_RUNTIME_SERVICE_EPOCH'])
ticket = bytes.fromhex(os.environ['KER_RUNTIME_SERVICE_TICKET'])
role = bytes.fromhex(os.environ['KER_RUNTIME_SERVICE_PROFILE'])
expected_worker = bytes.fromhex(os.environ['KER_RUNTIME_SERVICE_WORKER_PROFILE'])
assert int(os.environ['KER_RUNTIME_SERVICE_SUPERVISOR_PID']) == os.getppid()
assert int(os.environ['KER_RUNTIME_SERVICE_SUPERVISOR_START_TICKS']) > 0
channel = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
channel.connect(path)
def rpc(operation, sequence, lease=b'\0' * wire.LEASE_BYTES, body=b''):
    packet = wire.pack_header(operation, sequence, epoch, nonce, lease,
        packet_length=wire.HEADER.size + len(body)) + body
    channel.sendall(packet)
    response = channel.recv(wire.HEADER.size + wire.CLAIM_RESULT.size)
    op, status, seq, got_epoch, got_nonce, got_lease = wire.unpack_header(response)
    assert (op, seq, got_epoch, got_nonce) == (operation, sequence, epoch, nonce)
    return status, got_lease, response[wire.HEADER.size:]
status, lease, body = rpc(wire.CLAIM, 1,
    body=wire.CLAIM_BODY.pack(ticket, role))
assert status == 0 and body == wire.CLAIM_RESULT.pack(expected_worker)
assert rpc(wire.CHECK, 2, lease)[0] == 0
assert rpc(wire.RELEASE, 3, lease)[0] == 0
channel.close()
'''
        result = self.run_launcher(0, native_done=True, app_source=app,
            runtime_service_enabled=True, extra_env={'FAKE_RUNTIME_SERVICE_READY': '1',
                'PYTHONPATH': str(MODULE_PATH.parent)})
        self.assertEqual(result, 0)

    def test_missing_done_overrides_ordinary_143_exit(self):
        self.assertEqual(self.run_launcher(143, native_done=False), 125)

    def test_actual_child_signal_is_preserved_with_incomplete_shutdown(self):
        self.assertEqual(self.run_launcher(0, native_done=False, signal_app=True),
                         128 + signal.SIGTERM)

    def test_primary_exit_after_stopping_and_done_is_graceful(self):
        pid_file = self.root / 'primary.pid'
        stop_file = self.root / 'primary.stop'
        pid_file.unlink(missing_ok=True)
        stop_file.unlink(missing_ok=True)
        app = f'''import os, sys, time
from pathlib import Path
os.close(int(os.environ['KER_PACKET_FD']))
Path(os.environ['FAKE_EXIT_AFTER_STOP_FILE']).write_text('stop')
pid_file = Path(os.environ['FAKE_PRIMARY_PID_FILE'])
deadline = time.monotonic() + 3
while time.monotonic() < deadline:
    if pid_file.exists():
        pid = pid_file.read_text()
        try:
            state = Path('/proc/' + pid + '/stat').read_text().rsplit(')', 1)[1].split()[0]
        except FileNotFoundError:
            break
        if state == 'Z': break
    time.sleep(0.005)
else:
    raise SystemExit('primary worker did not exit after packet endpoint close')
sys.exit(0)
'''
        self.assertEqual(self.run_launcher(0, native_done=True, app_source=app,
            extra_env={'FAKE_NATIVE_STOPPING': '1', 'FAKE_EXIT_AFTER_STOP_FILE': str(stop_file),
                       'FAKE_PRIMARY_PID_FILE': str(pid_file)}), 0)

    def test_primary_exit_rejects_duplicate_out_of_order_and_incomplete_markers(self):
        pid_file = self.root / 'primary-malformed.pid'
        stop_file = self.root / 'primary-malformed.stop'
        cases = {
            'duplicate': 'KER_NATIVE_STOPPING\nKER_NATIVE_STOPPING\nKER_NATIVE_DONE\n',
            'out-of-order': 'KER_NATIVE_DONE\nKER_NATIVE_STOPPING\n',
            'incomplete': 'KER_NATIVE_STOPPING\nKER_NATIVE_INCOMPLETE\nKER_NATIVE_DONE\n',
            'malformed': 'KER_NATIVE_STOPPING\nKER_NATIVE_STOPPING extra\nKER_NATIVE_DONE\n',
        }
        for name, terminal in cases.items():
            with self.subTest(name=name):
                pid_file.unlink(missing_ok=True)
                stop_file.unlink(missing_ok=True)
                app = f'''import os, sys, time
from pathlib import Path
os.close(int(os.environ['KER_PACKET_FD']))
Path(os.environ['FAKE_EXIT_AFTER_STOP_FILE']).write_text('stop')
pid_file = Path(os.environ['FAKE_PRIMARY_PID_FILE'])
deadline = time.monotonic() + 3
while time.monotonic() < deadline:
    if pid_file.exists():
        pid = pid_file.read_text()
        try: state = Path('/proc/' + pid + '/stat').read_text().rsplit(')', 1)[1].split()[0]
        except FileNotFoundError: break
        if state == 'Z': break
    time.sleep(0.005)
else: raise SystemExit('primary worker did not exit')
'''
                result, stderr = self.run_launcher(0, native_done=False, app_source=app,
                    capture_stderr=True, extra_env={'FAKE_NATIVE_TERMINAL': terminal,
                        'FAKE_EXIT_AFTER_STOP_FILE': str(stop_file),
                        'FAKE_PRIMARY_PID_FILE': str(pid_file)})
                self.assertEqual(result, 125)
                self.assertIn('invalid native shutdown marker sequence', stderr)

    def test_primary_exit_before_stopping_remains_fatal(self):
        app = 'import time; time.sleep(1)'
        result, stderr = self.run_launcher(0, native_done=False, app_source=app,
            capture_stderr=True, extra_env={'FAKE_WORKER_EXIT_EARLY': '1'})
        self.assertEqual(result, 125)
        self.assertIn('DPDK worker stopped while the application was running', stderr)

    def graceful_auxiliary_loss(self):
        self.aux_pid_file.unlink(missing_ok=True)
        self.aux_done_file.unlink(missing_ok=True)
        self.app_start_file.unlink(missing_ok=True)
        self.app_done_file.unlink(missing_ok=True)
        app = f'''import os, signal, sys, time
from pathlib import Path
start = time.monotonic_ns()
Path(os.environ['FAKE_APP_START_FILE']).write_text(str(start))
pid_file = Path(os.environ['FAKE_AUX_PID_FILE'])
deadline = time.monotonic() + 1
while not pid_file.exists() and time.monotonic() < deadline: time.sleep(0.001)
os.kill(int(pid_file.read_text()), signal.SIGTERM)
deadline = time.monotonic() + 1
exited = False
while time.monotonic() < deadline:
    try:
        state = Path('/proc/' + pid_file.read_text() + '/stat').read_text().rsplit(')', 1)[1].split()[0]
    except FileNotFoundError:
        break
    if state == 'Z':
        exited = True
        break
    time.sleep(0.001)
Path(os.environ['FAKE_APP_DONE_FILE']).write_text(f'{{time.monotonic_ns()}} {{int(exited)}}')
sys.exit(0)
'''
        result, stderr = self.run_launcher(0, native_done=True, config=self.config, app_source=app,
            capture_stderr=True, extra_env={'FAKE_AUX_SIGNAL': '1',
                'FAKE_AUX_PID_FILE': str(self.aux_pid_file),
                'FAKE_AUX_DONE_FILE': str(self.aux_done_file),
                'FAKE_APP_START_FILE': str(self.app_start_file),
                'FAKE_APP_DONE_FILE': str(self.app_done_file)})
        return result, stderr

    def test_graceful_auxiliary_exit_during_successful_app_wait_is_failure(self):
        result, stderr = self.graceful_auxiliary_loss()
        self.assertTrue(self.aux_done_file.exists(), 'auxiliary worker did not emit KER_IO_DONE')
        self.assertEqual(result, 125)
        self.assertIn('additional DPDK worker stopped while the application was running: aux', stderr)
        worker_exit = int(self.aux_done_file.read_text())
        app_start = int(self.app_start_file.read_text())
        app_exit, auxiliary_exited = map(int, self.app_done_file.read_text().split())
        self.assertLess(worker_exit, app_exit, 'auxiliary must exit before the application')
        self.assertEqual(auxiliary_exited, 1, 'auxiliary process must be exited before app success')
        self.assertLess(app_exit - app_start, 250_000_000,
                        'application must exit during its first 250 ms wait interval')

    def test_successful_app_allows_coordinator_initiated_auxiliary_shutdown(self):
        self.assertEqual(self.run_launcher(0, native_done=True, config=self.config), 0)

    def test_auxiliary_nonzero_exit_remains_an_infrastructure_failure(self):
        self.assertEqual(self.run_launcher(0, native_done=True, config=self.config,
            extra_env={'FAKE_AUX_WORKER_EXIT': '9'}), 125)

    def test_malformed_auxiliary_completion_remains_an_infrastructure_failure(self):
        self.assertEqual(self.run_launcher(0, native_done=True, config=self.config,
            extra_env={'FAKE_AUX_MALFORMED': '1'}), 125)

    def test_duplicate_auxiliary_completion_is_failure_and_children_recover(self):
        for first, last in ((0, 0), (1, 0), (0, 1)):
            with self.subTest(first=first, last=last):
                result, stderr = self.run_launcher(0, native_done=True, config=self.config,
                    capture_stderr=True, extra_env={
                        'FAKE_AUX_DUPLICATE': '1',
                        'FAKE_AUX_DUPLICATE_FIRST': str(first),
                        'FAKE_AUX_DUPLICATE_LAST': str(last),
                        'FAKE_AUX_PID_FILE': str(self.aux_pid_file)})
                self.assertEqual(result, 125)
                self.assertIn('duplicate additional DPDK worker completion record: aux', stderr)
                pid = int(self.aux_pid_file.read_text())
                with self.assertRaises(ProcessLookupError):
                    os.kill(pid, 0)
        self.assertEqual(self.run_launcher(0, native_done=True, config=self.config), 0)


if __name__ == '__main__':
    unittest.main(verbosity=2)
