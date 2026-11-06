"""Write original shell echo bytes to a real native sysctl descriptor."""
import os
import importlib.util
import json
from pathlib import Path
import socket
import struct
import subprocess
import sys

HEADER = struct.Struct('=IIIIIIq')
MAGIC, WRITE, LIMIT = 0x4b4d5331, 9, 131072


def main():
    try:
        channel = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET, fileno=os.dup(1))
        if channel.getpeername() != os.environ.get('KER_MPTCP_SOCKET_CHANNEL'):
            channel.close()
            os.execv('/bin/echo', ['echo', *sys.argv[1:]])
    except OSError:
        os.execv('/bin/echo', ['echo', *sys.argv[1:]])
    with channel:
        result = subprocess.run(['/bin/echo', *sys.argv[1:]], capture_output=True)
        if result.returncode:
            os.write(2, result.stderr)
            return result.returncode
        data = result.stdout
        if len(data) > LIMIT:
            raise RuntimeError('sysctl echo exceeds fixture message limit')
        channel.settimeout(5)
        channel.sendall(HEADER.pack(MAGIC, WRITE, len(data), 0, 0, 0, 0) + data)
        packet, _, flags, _ = channel.recvmsg(HEADER.size + LIMIT)
        if flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC) or len(packet) != HEADER.size:
            raise RuntimeError('invalid native sysctl write response')
        magic, operation, length, _, _, _, count = HEADER.unpack(packet)
        if (magic, operation, length) != (MAGIC, WRITE, 0) or count != len(data):
            raise RuntimeError('native sysctl write failed: ' + (os.strerror(-count) if count < 0 else 'short write'))
        target = os.environ['KER_PACKETDRILL_PROC_TARGET']
        spec = importlib.util.spec_from_file_location('native_proc', Path(__file__).with_name('linux-mptcp-diag-shim.py'))
        wire = importlib.util.module_from_spec(spec); spec.loader.exec_module(wire)
        namespace = os.environ['KER_MPTCP_SOCKET_NAMESPACE']
        value = wire.rpc(wire.FILE, namespace, target).decode()
        spec = importlib.util.spec_from_file_location('packetdrill_command', Path(__file__).with_name('linux-packetdrill-command.py'))
        command = importlib.util.module_from_spec(spec); spec.loader.exec_module(command)
        if not command.equivalent(value, data.decode()):
            raise RuntimeError('native sysctl write/readback mismatch: ' + target)
        with open(os.environ['KER_PACKETDRILL_SYSCTL_LOG'], 'a') as log:
            log.write(json.dumps(dict(namespace=namespace, path=target, requested=data.decode(), readback=value,
                                      operation='original_echo')) + '\n')
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except Exception as error:
        sys.exit('native echo: ' + str(error))
