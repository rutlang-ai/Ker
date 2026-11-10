"""Read-only native MDB notifications and packet timestamps during original tests."""
import argparse
import ctypes
import errno
import fcntl
import json
import os
from pathlib import Path
import signal
import socket
import struct
import subprocess
import time
import traceback


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--ip',required=True);parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();running=True;handles=[]
    result=dict(kind='native_read_only_mdb_and_packet_monitor',started_monotonic=time.monotonic(),events=[],packets=[],error=None)
    def stop(signum,frame):
        nonlocal running
        running=False
    signal.signal(signal.SIGTERM,stop);signal.signal(signal.SIGINT,stop)
    libc=ctypes.CDLL(None,use_errno=True);libc.socket.argtypes=(ctypes.c_int,ctypes.c_int,ctypes.c_int);libc.socket.restype=ctypes.c_int
    libc.bind.argtypes=(ctypes.c_int,ctypes.c_void_p,ctypes.c_uint);libc.bind.restype=ctypes.c_int
    try:
        # Use plain SOCK_RAW as original Mausezahn does, then wrap its native
        # proxy descriptor without Python creating a second CLOEXEC socket.
        def opened(family,protocol):
            fd=libc.socket(family,socket.SOCK_RAW,protocol)
            if fd<0:raise OSError(ctypes.get_errno(),os.strerror(ctypes.get_errno()))
            sock=socket.socket(family=family,type=socket.SOCK_RAW,proto=protocol,fileno=fd)
            handles.append(sock)
            flags=libc.fcntl(fd,fcntl.F_GETFL,0)
            if flags<0 or libc.fcntl(fd,fcntl.F_SETFL,flags|os.O_NONBLOCK)<0:
                raise OSError(ctypes.get_errno(),os.strerror(ctypes.get_errno()))
            return sock
        netlink=opened(socket.AF_NETLINK,0);netlink.bind((0,0))
        # Linux UAPI: SOL_NETLINK=270, NETLINK_ADD_MEMBERSHIP=1,
        # RTNLGRP_MDB=26. All are unchanged in the pinned kernel headers.
        netlink.setsockopt(270,1,struct.pack('=I',26))
        packet=None;next_lookup=0;deadline=time.monotonic()+180
        while running and time.monotonic()<deadline:
            now=time.monotonic()
            if packet is None and now>=next_lookup:
                lookup=subprocess.run([args.ip,'-j','link','show','dev','veth2'],capture_output=True,text=True,timeout=5)
                if lookup.returncode==0:
                    rows=json.loads(lookup.stdout)
                    if len(rows)!=1 or rows[0]['ifname']!='veth2':raise RuntimeError('native monitor device lookup mismatch')
                    index=rows[0]['ifindex'];packet=opened(socket.AF_PACKET,socket.htons(3))
                    address=ctypes.create_string_buffer(struct.pack('=HHiHBB8s',socket.AF_PACKET,socket.htons(3),index,0,0,0,b'\0'*8))
                    if libc.bind(packet.fileno(),address,20)<0:raise OSError(ctypes.get_errno(),os.strerror(ctypes.get_errno()))
                    result.update(packet_ifindex=index,packet_ready_monotonic=time.monotonic())
                next_lookup=now+0.1
            for sock,key in ((netlink,'events'),(packet,'packets')):
                if sock is None:continue
                for _ in range(256):
                    try:data=sock.recv(65536)
                    except OSError as error:
                        if error.errno in (errno.EAGAIN,errno.EWOULDBLOCK,errno.EINTR):break
                        if sock is packet and error.errno==errno.ENETDOWN:
                            result['device_down_samples']=result.get('device_down_samples',0)+1
                            break
                        raise
                    if not data:raise RuntimeError('native monitor socket closed unexpectedly')
                    result[key].append(dict(monotonic=time.monotonic(),data_hex=data.hex()))
                    if sock is packet:result.setdefault('first_packet_monotonic',time.monotonic())
            time.sleep(0.05)
        if running:raise RuntimeError('native multicast monitor deadline reached')
        if packet is None:raise RuntimeError('native packet monitor never bound veth2')
    except BaseException as error:
        result['error']=repr(error);result['traceback']=traceback.format_exc()
    finally:
        for sock in reversed(handles):sock.close()
        result['finished_monotonic']=time.monotonic()
        args.output.write_text(json.dumps(result,indent=2)+'\n')
    return int(result['error'] is not None)


if __name__=='__main__':raise SystemExit(main())
