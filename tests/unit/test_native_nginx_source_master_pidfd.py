"""Exercise the source-master fixture's retained predecessor pidfd helper."""
import ast
import fcntl
import os
from pathlib import Path
import select
import subprocess
import sys
import time
import unittest


FIXTURE = Path(__file__).resolve().parents[1] / 'posix' / 'native-nginx-source-master.py'


def load_helpers():
    tree = ast.parse(FIXTURE.read_text())
    wanted = {'require', 'pidfd_target_pid', 'retain_owner_pidfd'}
    functions = [node for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name in wanted]
    if {node.name for node in functions} != wanted:
        raise AssertionError('fixture pidfd helper definitions are incomplete')
    namespace = {
        'fcntl': fcntl,
        'os': os,
        're': __import__('re'),
        'select': select,
        'Path': Path,
    }
    code = compile(ast.Module(body=functions, type_ignores=[]), str(FIXTURE), 'exec')
    exec(code, namespace)
    return namespace['retain_owner_pidfd']


def process_start_ticks(pid):
    fields = Path(f'/proc/{pid}/stat').read_text().split(') ', 1)[1].split()
    return int(fields[19])


def fd_count():
    return len(list(Path('/proc/self/fd').iterdir()))


class RetainedOwnerPidfdTests(unittest.TestCase):
    def test_manager_close_does_not_destroy_owned_death_observation(self):
        retain = load_helpers()
        child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)'],
            close_fds=True)
        borrowed = os.pidfd_open(child.pid)
        retained = -1
        try:
            count_with_borrowed = fd_count()
            expected_count = count_with_borrowed + 1
            owner = type('Owner', (), {
                'owner_pid': child.pid,
                'owner_start': process_start_ticks(child.pid),
                'owner_pidfd': borrowed,
            })()
            retained = retain(owner, process_start_ticks)
            self.assertEqual(fd_count(), expected_count)
            self.assertTrue(fcntl.fcntl(retained, fcntl.F_GETFD) & fcntl.FD_CLOEXEC)
            self.assertFalse(select.select([retained], [], [], 0)[0])

            os.close(borrowed)  # mirrors manager promotion closing its borrowed fd
            borrowed = -1
            child.terminate()
            child.wait(timeout=3)
            self.assertTrue(select.select([retained], [], [], 3)[0])
        finally:
            if child.poll() is None:
                child.kill()
                child.wait(timeout=3)
            if borrowed >= 0:
                os.close(borrowed)
            if retained >= 0:
                os.close(retained)
        self.assertEqual(fd_count(), expected_count - 2)

    def test_wrong_pid_is_rejected_without_leaking_duplicate(self):
        retain = load_helpers()
        child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)'],
            close_fds=True)
        borrowed = os.pidfd_open(child.pid)
        before = fd_count()
        try:
            owner = type('Owner', (), {
                'owner_pid': child.pid + 1,
                'owner_start': process_start_ticks(child.pid),
                'owner_pidfd': borrowed,
            })()
            with self.assertRaises(RuntimeError):
                retain(owner, process_start_ticks)
            self.assertEqual(fd_count(), before)
        finally:
            child.terminate()
            child.wait(timeout=3)
            os.close(borrowed)


if __name__ == '__main__':
    unittest.main()
