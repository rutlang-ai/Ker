"""Private namespace/tool transport for unchanged packetdrill selftests."""
import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time


spec = importlib.util.spec_from_file_location('packetdrill_wire', Path(__file__).with_name('linux-mptcp-diag-shim.py'))
wire = importlib.util.module_from_spec(spec); spec.loader.exec_module(wire)


def equivalent(left, right):
    def token(value):
        try:
            return int(value, 16 if value.startswith(('0x', '0X')) else 10)
        except ValueError:
            return value.lower()
    return list(map(token, left.split())) == list(map(token, right.split()))


def append(path, value):
    # One complete line per write, including commands that fail before a TAP
    # script notices them. A zero tool exit alone never qualifies the matrix.
    with open(path, 'a') as stream:
        stream.write(json.dumps(value) + '\n')


def entry(config, arguments):
    namespace = 'pkt-' + str(os.getpid())
    environment = dict(os.environ, KER_MPTCP_SOCKET_NAMESPACE=namespace,
                       LD_PRELOAD=config['preload'], BASH_ENV=config['bash_env'])
    record = dict(arguments=arguments, namespace=namespace, returncode=None)
    wire.rpc(wire.NEWNS, namespace); wire.rpc(wire.UP, namespace)
    try:
        started = time.monotonic()
        process = subprocess.Popen([config['tool'], *arguments], env=environment,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True)
        try:
            out, err = process.communicate(timeout=45)
        except BaseException:
            os.killpg(process.pid, signal.SIGKILL)
            process.communicate(timeout=5)
            raise
        record.update(returncode=process.returncode, stdout=out, stderr=err,
                      seconds=time.monotonic() - started)
        for name in ('snmp', 'snmp6'):
            record[name] = wire.rpc(wire.FILE, namespace, '/proc/net/' + name).decode()
        sys.stdout.write(out); sys.stderr.write(err)
        return process.returncode
    finally:
        try:
            wire.rpc(wire.DELNS, namespace)
        finally:
            append(config['entries'], record)


def main():
    config = json.loads(Path(os.environ['KER_PACKETDRILL_CONFIG']).read_text())
    name, arguments = sys.argv[1], sys.argv[2:]
    if name == 'packetdrill':
        return entry(config, arguments)
    namespace = os.environ['KER_MPTCP_SOCKET_NAMESPACE']
    if name in ('ip', 'tc'):
        program = str(Path(config['iproute']) / name)
        environment = dict(os.environ, LD_PRELOAD=config['diag_preload'])
        os.execve(program, [program, *arguments], environment)
    if name in ('cat', 'grep'):
        for index, argument in enumerate(arguments):
            if argument.startswith(('/proc/net/', '/proc/sys/net/')):
                content = wire.rpc(wire.FILE, namespace, argument)
                fd = os.memfd_create('packetdrill-native-proc', flags=0)
                if os.write(fd, content) != len(content):
                    raise RuntimeError('incomplete native proc snapshot')
                os.lseek(fd, 0, 0); os.set_inheritable(fd, True)
                arguments[index] = '/proc/self/fd/' + str(fd)
        os.execve('/usr/bin/' + name, [name, *arguments], dict(os.environ))
    if name == 'sysctl':
        for option in (item for item in arguments if item.startswith('-')):
            if option not in ('-q', '-e'):
                raise RuntimeError('unsupported sysctl option: ' + option)
        settings = [item for item in arguments if not item.startswith('-')]
        if not settings:
            raise RuntimeError('missing native sysctl setting')
        for setting in settings:
            key, separator, requested = setting.partition('=')
            # procps accepts both slash and dot notation. The transport uses
            # dots and still opens/writes the actual native proc entry.
            key = key.replace('/', '.')
            if separator:
                wire.rpc(wire.SYSCTL, namespace, key + '=' + requested)
            value = wire.rpc(wire.FILE, namespace, '/proc/sys/' + key.replace('.', '/')).decode().strip()
            if separator and not equivalent(requested, value):
                raise RuntimeError('native sysctl write/readback mismatch: ' + key)
            append(config['sysctls'], dict(namespace=namespace, setting=setting, readback=value,
                                          operation='sysctl'))
            if '-q' not in arguments:
                print(key + ' = ' + value)
        return 0
    raise RuntimeError('unsupported packetdrill helper: ' + name)


if __name__ == '__main__':
    try:
        sys.exit(main())
    except Exception as error:
        sys.exit('native packetdrill helper: ' + str(error))
