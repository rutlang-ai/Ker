"""Record the original broadcast shell's literal grep oracle without changing it."""
import hashlib
import json
import os
import subprocess
import sys

program = os.environ['KER_BROADCAST_GREP']
arguments = sys.argv[1:]
if len(arguments) != 1 or not arguments[0].startswith('bytes from '):
    os.execv(program, [program, *arguments])

data = sys.stdin.buffer.read()
result = subprocess.run([program, *arguments], input=data, capture_output=True)
record = dict(tool='grep', arguments=arguments, input=data.decode(),
              input_sha256=hashlib.sha256(data).hexdigest(), returncode=result.returncode,
              stdout=result.stdout.decode(), stderr=result.stderr.decode())
with open(os.environ['KER_FORWARDING_LOG'], 'a') as stream:
    stream.write(json.dumps(record) + '\n')
sys.stdout.buffer.write(result.stdout)
sys.stderr.buffer.write(result.stderr)
sys.exit(result.returncode)
