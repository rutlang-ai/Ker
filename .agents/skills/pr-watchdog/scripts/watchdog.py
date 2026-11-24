#!/usr/bin/env python3
"""Start, inspect or stop one detached PR poller for a canonical watch set."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shlex
import signal
import subprocess
import sys
import time

SCRIPTS = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS))
from poll_prs import canonicalize, current_repo, validate_state_path, load_state, save_state


def matching_processes(command):
    matches = []
    for path in Path('/proc').glob('[0-9]*/cmdline'):
        try:
            arguments = path.read_bytes().split(b'\0')
            if [os.fsdecode(x) for x in arguments if x] == command:
                matches.append(int(path.parent.name))
        except (OSError, ValueError):
            continue
    return matches


def remaining_processes(found):
    return [pid for pid, command in found if pid in matching_processes(command)]


def poller_arguments(command):
    """Extract positional PR identifiers and state path from poll_prs argv."""
    prs = []
    state = None
    value_options = {'--state-file', '--interval', '--on-change-command'}
    arguments = command[2:]
    index = 0
    while index < len(arguments):
        argument = arguments[index]
        if argument in value_options:
            if index + 1 >= len(arguments):
                raise ValueError(f'missing value for {argument}')
            value = arguments[index + 1]
            if argument == '--state-file':
                state = value
            index += 2
        elif argument.startswith('--'):
            if argument.startswith('--state-file='):
                state = argument.partition('=')[2]
            index += 1
        else:
            prs.append(argument)
            index += 1
    return prs, state


def process_repo(pid):
    """Resolve numeric poller arguments against that process's git cwd."""
    cwd = Path(f'/proc/{pid}/cwd').resolve(strict=True)
    result = subprocess.run(
        ['gh', 'repo', 'view', '--json', 'nameWithOwner'], cwd=cwd,
        text=True, capture_output=True, check=False, timeout=30,
    )
    if result.returncode:
        raise RuntimeError(result.stderr.strip() or f'cannot resolve repository for poller PID {pid}')
    try:
        return json.loads(result.stdout)['nameWithOwner']
    except (json.JSONDecodeError, KeyError, TypeError) as error:
        raise RuntimeError(f'cannot resolve repository for poller PID {pid}') from error


def discover_pollers(targets, state):
    matches = []
    for path in Path('/proc').glob('[0-9]*/cmdline'):
        try:
            command = [os.fsdecode(x) for x in path.read_bytes().split(b'\0') if x]
            if len(command) < 2 or Path(command[1]).name != 'poll_prs.py':
                continue
            pid = int(path.parent.name)
            identifiers, state_argument = poller_arguments(command)
            target_numbers = {int(target.rsplit('#', 1)[-1]) for target in targets}
            numeric_identifiers = [x for x in identifiers if x.isdigit()]
            relevant_numbers = [x for x in numeric_identifiers
                                if int(x) in target_numbers]
            default_repo = process_repo(pid) if relevant_numbers else None
            found = []
            unresolved_numeric = False
            for identifier in identifiers:
                if identifier.isdigit() and not default_repo:
                    unresolved_numeric = True
                    continue
                owner, number = canonicalize(identifier, default_repo)
                found.append(f'{owner}#{number}')
            found.sort()
            if not set(found).intersection(targets):
                continue
            if unresolved_numeric or found != targets:
                raise RuntimeError('an overlapping PR watch has unresolved numeric identifiers; inspect PID '
                                   + path.parent.name)
            process_state = Path(state_argument) if state_argument else None
            if process_state is not None and not process_state.is_absolute():
                process_cwd = Path(f'/proc/{pid}/cwd').resolve(strict=True)
                process_state = process_cwd / process_state
            if (found != targets or process_state is None or process_state.resolve() != state):
                raise RuntimeError('an overlapping PR watch is running; inspect PID ' + path.parent.name)
            matches.append((pid, command))
        except (OSError, ValueError, IndexError):
            continue
    return matches


def poller_thread(command):
    """Return a coordinator thread only for the known Codex dispatch hook."""
    try:
        hook = shlex.split(command[command.index('--on-change-command') + 1])
        entrypoint = (hook[0] if hook else None)
        if len(hook) > 1 and Path(hook[0]).name.startswith('python'):
            entrypoint = hook[1]
        if not entrypoint or Path(entrypoint).name != 'dispatch_codex.py':
            return None
        thread = hook[hook.index('--thread') + 1]
        return thread if thread and not thread.startswith('-') else None
    except (ValueError, IndexError):
        return None


def reset_restart_fingerprints(data, targets):
    """Force fresh snapshots for active PRs while retaining retired records."""
    for target in targets:
        record = data['prs'].get(target, {})
        if not record.get('terminal'):
            record.pop('fingerprint', None)
            record.pop('error_dispatched', None)
        data['prs'][target] = record


def startup_ready(records, targets, started_at):
    return all(records.get(pr, {}).get('terminal') or
               (records.get(pr, {}).get('fingerprint') and
                records[pr].get('last_polled_at', 0) >= started_at)
               for pr in targets)


def watch_healthy(records, targets):
    return all(
        records.get(pr, {}).get('terminal') or
        (records.get(pr, {}).get('fingerprint') and
         not records.get(pr, {}).get('last_error'))
        for pr in targets
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['start', 'status', 'stop'])
    parser.add_argument('prs', nargs='+')
    parser.add_argument('--thread', default=os.environ.get('CODEX_THREAD_ID'))
    args = parser.parse_args()
    repo = current_repo() if any(p.isdigit() for p in args.prs) else None
    targets = sorted({f'{owner}#{number}' for owner, number in
                      (canonicalize(p, repo) for p in args.prs)})
    if len(targets) != len(args.prs):
        parser.error('duplicate PR identifiers')
    watch_id = hashlib.sha256('\n'.join(targets).encode()).hexdigest()[:16]
    root = Path.home() / '.local/state/pr-watchdog' / watch_id
    state = validate_state_path(root / 'poll-state.json')
    root.mkdir(parents=True, exist_ok=True)
    manifest_path = root / 'watch.json'
    with (root.parent / 'lifecycle.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        try:
            manifest = json.loads(manifest_path.read_text())
        except (FileNotFoundError, json.JSONDecodeError):
            manifest = None
        found = discover_pollers(targets, state)
        if found:
            command = found[0][1]
            thread = poller_thread(command)
            manifest = {'prs': targets, 'thread': thread, 'command': command,
                        'started_at': (manifest or {}).get('started_at', 0),
                        'log': str(root / 'poll.log')}
            manifest_path.write_text(json.dumps(manifest, indent=2) + '\n')
        command = manifest['command'] if manifest else None
        pids = [pid for pid, _ in found]
        if args.action == 'stop':
            for pid in pids:
                os.kill(pid, signal.SIGTERM)
            deadline = time.monotonic() + 5
            while remaining_processes(found) and time.monotonic() < deadline:
                time.sleep(.1)
            if remaining_processes(found):
                raise RuntimeError('poller did not stop; inspect recorded PIDs')
            print(json.dumps({'status': 'stopped', 'pids': pids, 'directory': str(root)}))
            return 0
        if args.action == 'start':
            if not args.thread and not pids:
                parser.error('provide --thread or run within a Codex session')
            if len(pids) > 1 and not args.thread:
                raise RuntimeError(
                    'multiple pollers are running; provide --thread to reconcile them safely')
            if len(pids) == 1 and args.thread and not manifest.get('thread'):
                raise RuntimeError(
                    'the existing poller has no recognized Codex coordinator hook; '
                    'stop it, then start again with --thread')
            if (args.thread and manifest and manifest.get('thread')
                    and manifest['thread'] != args.thread and pids):
                parser.error('watch is already attached to another session; stop it before switching')
            if len(pids) > 1 and args.thread:
                for pid in pids:
                    os.kill(pid, signal.SIGTERM)
                deadline = time.monotonic() + 5
                while remaining_processes(found) and time.monotonic() < deadline:
                    time.sleep(.1)
                if remaining_processes(found):
                    raise RuntimeError('duplicate pollers did not exit')
                pids = []
            if not pids:
                subprocess.run(['gh', 'api', 'user', '--jq', '.login'], check=True,
                               stdout=subprocess.DEVNULL)
                subprocess.run(['codex', 'queue', '--help'], check=True,
                               stdout=subprocess.DEVNULL)
                hook = shlex.join([sys.executable, str(SCRIPTS / 'dispatch_codex.py'),
                                   '--thread', args.thread])
                command = [sys.executable, str(SCRIPTS / 'poll_prs.py'), *targets,
                           '--state-file', str(state), '--on-change-command', hook]
                # Each new process must hand off a fresh initial snapshot, even
                # if metadata is unchanged or the previous session disappeared.
                data = load_state(state)
                reset_restart_fingerprints(data, targets)
                save_state(state, data)
                manifest = {'prs': targets, 'thread': args.thread, 'command': command,
                            'started_at': time.time(), 'log': str(root / 'poll.log')}
                temporary = root / 'watch.json.tmp'
                temporary.write_text(json.dumps(manifest, indent=2) + '\n')
                temporary.replace(manifest_path)
                with (root / 'poll.log').open('ab', buffering=0) as log:
                    child = subprocess.Popen(command, stdin=subprocess.DEVNULL,
                                             stdout=log, stderr=log, start_new_session=True,
                                             cwd=SCRIPTS.parents[3])
                pids = [child.pid]
                # Observe first metadata fetch and successful event hand-off.
                deadline = time.monotonic() + 45
                while time.monotonic() < deadline:
                    if child.poll() is not None:
                        break
                    if state.exists():
                        data = load_state(state)
                        records = data.get('prs', {})
                        if startup_ready(records, targets, manifest['started_at']):
                            break
                    time.sleep(.2)
                pids = matching_processes(command)
        data = load_state(state) if state.exists() else {}
        print(json.dumps({'status': 'running' if pids else 'stopped', 'pids': pids,
                          'prs': targets, 'thread': manifest.get('thread') if manifest else None,
                          'directory': str(root), 'poll_state': data}, ensure_ascii=False))
        terminal = all(data.get('prs', {}).get(p, {}).get('terminal') for p in targets)
        healthy = watch_healthy(data.get('prs', {}), targets)
        return 0 if terminal or (pids and healthy) else 1


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (OSError, ValueError, RuntimeError, subprocess.CalledProcessError) as error:
        print(str(error), file=sys.stderr)
        sys.exit(1)
