#!/usr/bin/env python3
"""Exact orphan control-reservation lifetime; no secondary EAL or hardware."""
import ctypes
import errno
import importlib
import json
import os
from pathlib import Path
import selectors
import signal
import subprocess
import sys
import tempfile
import time

control = importlib.import_module('session-control-frames')

MASTER = r'''
import importlib, importlib.util, json, signal, sys
from contextlib import ExitStack
sys.path.insert(0, sys.argv[1])
control = importlib.import_module('session-control-frames')
spec = importlib.util.spec_from_file_location('api', sys.argv[2])
api = importlib.util.module_from_spec(spec)
spec.loader.exec_module(api)
def terminate(signum, frame):
    raise SystemExit(1)
signal.signal(signal.SIGTERM, terminate)
with ExitStack() as stack:
    master = stack.enter_context(control.channel(sys.argv[3]))
    _, ticket = control.exchange(api, master, api.packet(api.MASTER, 1))
    children = []
    for index in range(int(sys.argv[4])):
        request = dict(control.identity(ticket), generation=index, process=3-index)
        child, pidfd, reply = stack.enter_context(control.master_child(api, sys.argv[3], request, 'orphan'))
        # Socket EOF is acknowledged while the child remains alive.
        if sys.argv[5] == 'eof':
            control.require(child.stdin.write(b'C') == 1 and control.child_line(child) == 'CLOSED',
                            'child did not close its control socket')
        children.append({'pid': child.pid, 'generation': index, 'process': 3-index})
    print(json.dumps({'ticket': ticket, 'children': children}), flush=True)
    # The supervisor kills this process only after obtaining every child pidfd.
    sys.stdin.buffer.read(1)
'''


def wait_state(api, path, session, slots, users):
    deadline = time.monotonic() + 3
    observer = api.Connection(path)
    try:
        while True:
            state = observer.request(api.STATUS)
            control.require(state['session'] == session and
                            state['generation'] + state['token'] == 511 and
                            state['token'] == state['process'], 'invalid orphan census: ' + repr(state))
            if state['slot'] == slots and state['process'] == users:
                return
            control.require(time.monotonic() < deadline, 'orphan census did not converge: ' + repr(state))
            time.sleep(0.01)
    finally:
        observer.close()


def wait_adopted(pid, pidfd, check_signal=True):
    with selectors.DefaultSelector() as selector:
        selector.register(pidfd, selectors.EVENT_READ)
        control.require(selector.select(5), 'orphan did not die after exact pidfd kill')
    waited, status = os.waitpid(pid, 0)
    control.require(waited == pid and (not check_signal or os.waitstatus_to_exitcode(status) == -signal.SIGKILL),
                    'orphan was not adopted/reaped after SIGKILL')


def orphan_reservations(api, path, session, mode):
    libc = ctypes.CDLL(None, use_errno=True)
    prior = ctypes.c_int()
    control.require(libc.prctl(37, ctypes.byref(prior), 0, 0, 0) == 0, 'cannot read subreaper state')
    control.require(libc.prctl(36, 1, 0, 0, 0) == 0, 'cannot become child subreaper')
    children = []
    process = None
    try:
        with tempfile.TemporaryFile() as errors, control.channel(path) as sentinel:
            _, stable = control.exchange(api, sentinel, api.packet(api.MASTER, 1))
            process = subprocess.Popen([sys.executable, '-c', MASTER, str(Path(__file__).parent),
                api.__file__, str(path), '2' if mode == 'staged' else '1',
                'eof' if mode == 'eof' else 'open'], stdin=subprocess.PIPE,
                stdout=subprocess.PIPE, stderr=errors, start_new_session=True, bufsize=0)
            try:
                record = json.loads(control.child_line(process))
                ticket = record['ticket']
                control.require(ticket['session'] == session and ticket['slot'] != stable['slot'],
                                'orphan master has wrong identity')
                for entry in record['children']:
                    children.append([entry['pid'], os.pidfd_open(entry['pid']), False])
                count = 2 if mode == 'staged' else 1
                control.require(len(children) == count and len({p[0] for p in children}) == count,
                                'wrong independent borrower count')
                control.status_snapshot(api, path, session, slots=2, users=count)
                if mode == 'frozen':
                    signal.pidfd_send_signal(children[0][1], signal.SIGSTOP)
                    deadline = time.monotonic() + 3
                    while Path(f'/proc/{children[0][0]}/stat').read_text().rsplit(')', 1)[1].split()[0] not in ('T', 't'):
                        control.require(time.monotonic() < deadline, 'orphan borrower did not stop')
                        time.sleep(0.01)
                process.kill()
                control.require(process.wait(timeout=5) == -signal.SIGKILL, 'master did not die')
                # The master cannot unwind its child contexts on SIGKILL.
                for _ in range(8):
                    for _, pidfd, _ in children:
                        control.require_pidfd(pidfd, False)
                    control.status_snapshot(api, path, session, slots=2, users=count)
                    control.epoch_live(api, path, ticket['epoch'], 1)
                for index, child in enumerate(children):
                    signal.pidfd_send_signal(child[1], signal.SIGKILL)
                    wait_adopted(child[0], child[1]); child[2] = True
                    remaining = count-index-1
                    wait_state(api, path, session, 2 if remaining else 1, remaining)
                    control.status_snapshot(api, path, session, slots=2 if remaining else 1, users=remaining)
                    control.epoch_live(api, path, ticket['epoch'], 1 if remaining else 0)
                    control.epoch_live(api, path, stable['epoch'], 1)
                    control.epoch_live(api, path, 0, 1)
                    if remaining:
                        control.require_pidfd(children[index+1][1], False)
                with control.channel(path) as replacement:
                    control.exchange(api, replacement, api.packet(api.RELEASE, 1, **control.identity(ticket)), -errno.ESTALE)
                    _, fresh = control.exchange(api, replacement, api.packet(api.MASTER, 2))
                    control.require(fresh['slot'] == ticket['slot'] and fresh['epoch'] > ticket['epoch'],
                                    'dead orphan slot was not safely recycled')
                    control.epoch_live(api, path, ticket['epoch'], 0)
                    control.exchange(api, replacement, api.packet(api.RELEASE, 3, **control.identity(fresh)))
                control.exchange(api, sentinel, api.packet(api.RELEASE, 2, **control.identity(stable)))
                control.status_snapshot(api, path, session)
            except BaseException:
                errors.seek(0)
                print(errors.read().decode(errors='replace'), file=sys.stderr)
                raise
            finally:
                # This private process group contains only our master/borrowers.
                # It also covers an interrupted startup before PIDs were reported.
                if process.returncode is None or not children or not all(child[2] for child in children):
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                process.wait(timeout=5)
                for child in children:
                    try:
                        if not child[2]:
                            try:
                                wait_adopted(child[0], child[1], check_signal=False)
                            except ChildProcessError:
                                pass  # A failed exit-status assertion may already have reaped it.
                    finally:
                        os.close(child[1])
                # Reap any adopted startup child before dropping subreaper status.
                deadline = time.monotonic() + 5
                while True:
                    try:
                        pid, _ = os.waitpid(-process.pid, os.WNOHANG)
                    except ChildProcessError:
                        break
                    if pid == 0:
                        control.require(time.monotonic() < deadline, 'startup child cleanup timed out')
                        time.sleep(0.01)
                process.stdin.close(); process.stdout.close()
    finally:
        control.require(libc.prctl(36, prior.value, 0, 0, 0) == 0, 'cannot restore subreaper state')


if __name__ == '__main__':
    sys.exit(control.main({
        'orphan-eof': lambda api, path, session: orphan_reservations(api, path, session, 'eof'),
        'orphan-frozen': lambda api, path, session: orphan_reservations(api, path, session, 'frozen'),
        'orphan-staged': lambda api, path, session: orphan_reservations(api, path, session, 'staged'),
    }))
