"""Real FF owners exchange one original-Linux NFQUEUE without exiting."""
import json
import os
import re
import signal
import socket
import subprocess
import threading


def require(value, message):
    if not value:
        raise RuntimeError(message)


def run(args, stop_path, stats, broker, environment, wait_line):
    owners = []
    events = []
    broker_output = {name: [] for name in ('stdout', 'stderr')}
    readers = []

    def drain(pipe, name):
        while True:
            data = os.read(pipe.fileno(), 65536)
            if not data:
                break
            broker_output[name].append(data)

    for name in broker_output:
        thread = threading.Thread(target=drain, args=(getattr(broker, name), name), daemon=True)
        thread.start()
        readers.append(thread)

    def launch(port, ready=True):
        process = subprocess.Popen([str(args.client), 'window-handoff'],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, bufsize=1, env=environment | {'KER_C17_TEST_LISTENER_PORT': str(port)})
        owners.append(process)
        if ready:
            wait_line(process, 'C16_APP_READY', 20)
            return process, window(process, 'INITIAL', 1, 0)
        output, errors = process.communicate(timeout=15)
        require(process.returncode == 2 and 'C16_APP_READY' not in output and
            'C16 app setup failed stage=broker admission attach errno=104' in errors,
            f'second active queue was permitted: rc={process.returncode}; {output!r}; {errors!r}')
        events.append({'event': 'ACTIVE_QUEUE_REJECTED', 'port': port})
        return process, None

    def window(process, marker, epoch, inserted):
        text = wait_line(process, 'C17_WINDOW_' + marker, 15)
        match = re.search(r'epoch=(\d+) lease=(\d+) active=(\d+) inserted=(\d+)', text)
        require(match, f'missing window identity: {text!r}')
        actual_epoch, lease, active, actual_inserted = map(int, match.groups())
        require(actual_epoch == epoch and lease > 0 and active == (marker != 'RETIRED') and
            actual_inserted == inserted, f'unexpected map state: {text!r}')
        events.append({'event': marker, 'pid': process.pid, 'epoch': epoch, 'lease': lease,
            'inserted': inserted})
        return lease

    def retire(process, epoch, lease, inserted):
        os.kill(process.pid, signal.SIGWINCH)
        require(window(process, 'RETIRED', epoch, inserted) == lease, 'retire changed its lease')

    def rearm(process, epoch, inserted):
        os.kill(process.pid, signal.SIGHUP)
        return window(process, 'READY', epoch, inserted)

    def busy(process):
        os.kill(process.pid, signal.SIGHUP)
        wait_line(process, 'C17_REARM_BUSY retired_unchanged=1 map_closed=1', 10)
        events.append({'event': 'REARM_REJECTED_WITHOUT_MUTATION', 'pid': process.pid})

    def echo(port, payload):
        with socket.create_connection(('198.18.0.2', port), timeout=8) as peer:
            peer.settimeout(8)
            peer.sendall(payload)
            result = bytearray()
            while len(result) < len(payload):
                chunk = peer.recv(len(payload) - len(result))
                require(chunk, 'original Linux stream closed before echo')
                result.extend(chunk)
            require(result == payload, 'original Linux stream corrupted payload')

    def stop(process, accepted, inserted):
        os.kill(process.pid, signal.SIGUSR2)
        done = wait_line(process, 'C16_APP_DONE', 15)
        require(f'accepted={accepted} inserted={inserted} ' in done, f'wrong owner accounting: {done!r}')
        output, errors = process.communicate(timeout=10)
        require(process.returncode == 0, f'owner cleanup failed: {output!r}; {errors!r}')
        events.append({'event': 'OWNER_EXITED', 'pid': process.pid, 'accepted': accepted, 'inserted': inserted})

    def finish(minimum_opens):
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as stop_socket:
            stop_socket.sendto(b'STOP', str(stop_path))
        broker.wait(timeout=35)
        for reader in readers:
            reader.join(timeout=2)
        require(all(not reader.is_alive() for reader in readers), 'broker pipes did not close')
        report = json.loads(stats.read_text())
        require(broker.returncode == 0 and report.get('outstanding') == 0 and
            report.get('native', {}).get('passive_opens', 0) >= minimum_opens,
            f'broker cleanup or original Linux traffic evidence missing: {report!r}; {broker_output!r}')
        if not args.window_handoff_stop_live:
            print('C17_WINDOW_HANDOFF_PASS ' + json.dumps({'events': events, 'stats': report}, sort_keys=True))
        return 0

    try:
        first, lease1 = launch(8080)
        echo(8080, b'first-active')
        launch(8090, ready=False)
        echo(8080, b'first-still-active')
        retire(first, 1, lease1, 2)
        second, lease2 = launch(8081)
        require(lease2 > lease1, 'new owner reused the previous queue lease')
        busy(first)
        echo(8080, b'first-retired-listener')
        echo(8081, b'second-active')
        if args.window_handoff_stop_live:
            for process in (first, second):
                os.kill(process.pid, signal.SIGSTOP)
                state = os.waitid(os.P_PID, process.pid, os.WSTOPPED | os.WEXITED | os.WNOWAIT)
                require(state.si_code == os.CLD_STOPPED and state.si_status == signal.SIGSTOP,
                    'owner did not acknowledge stop before broker shutdown')
            result = finish(4)
            output = b''.join(broker_output['stdout']).decode(errors='replace')
            require(output.count('C16_ADMISSION listener-ref-put-before-native-finalize') == 2 and
                'C16_ADMISSION listener-ref-put-at-task-release' not in output,
                f'live task listener references were not released exactly once before finalization: {output!r}')
            # The owners remain stopped while their authenticated channels are
            # revoked. Cleanup kills these fixture processes after the broker
            # has proved every listener reference was put before finalization.
            print('C17_WINDOW_HANDOFF_STOP_LIVE_PASS listener_refs=2 pool=0')
            return result
        retire(second, 1, lease2, 1)
        lease3 = rearm(first, 2, 2)
        require(lease3 > lease2, 'first owner rearmed with a stale lease')
        busy(second)
        echo(8080, b'first-rearmed')
        echo(8081, b'second-retired-listener')
        # Releasing a retired task must not relinquish another task's queue.
        stop(second, 2, 1)
        launch(8091, ready=False)
        echo(8080, b'first-still-rearmed')
        retire(first, 2, lease3, 4)
        third, lease4 = launch(8082)
        require(lease4 > lease3, 'third owner reused a stale lease')
        echo(8080, b'first-retired-again')
        stop(first, 6, 4)
        echo(8082, b'third-after-retired-exits')
        stop(third, 1, 1)
        return finish(9)
    except BaseException:
        print('C17_WINDOW_HANDOFF_FAILURE events=' + json.dumps(events), flush=True)
        for process in owners:
            if process.poll() is not None:
                output, errors = process.communicate()
                print(f'owner pid={process.pid} rc={process.returncode} output={output!r} errors={errors!r}', flush=True)
        print('broker output=' + repr(broker_output), flush=True)
        raise
    finally:
        for process in owners:
            if process.poll() is None:
                process.kill()
                output, errors = process.communicate(timeout=10)
                print(f'cleanup pid={process.pid} rc={process.returncode} output={output!r} errors={errors!r}', flush=True)
