# Pinned F-Stack reload harness tooling check

This is an explicit, opt-in check for the process-control and fixture helpers
used by the pinned F-Stack reload harness. It does not run a native socket
compatibility test, advance the native compatibility count, or claim that
F-Stack protocol behavior has been migrated. The upstream reload suite is not
added to the default CTest catalog.

## Run

From the Ker repository root, run:

```sh
python3 -B tests/posix/fstack-reload-harness-runtime.py \
  --timeout 300 --log /tmp/ker-c10-harness-runtime.log
```

The runner first verifies SHA-256 hashes for all 13 pinned inputs, including
`test_reload_harness.py`, its unit Makefile and C fixture, the reload supervisor,
runtime/check/remote helpers, integration script, and five probe scripts. The
expected digests are kept next to the runner in its `PINNED` map. It makes a
private copy of the unit test directory inputs and builds the unchanged
`reload_process_fixture.c` there with the host `cc`; neither source files nor a
binary are written into the upstream tree.

The suite invoked inside the sandbox is the upstream test's direct command:
`python3 -B tests/upstream/fstack/tests/unit/test_reload_harness.py -v`. The
runner requires exactly 53 tests, an `OK` verdict, and no skips. The independent
Ker helper checks run first and require exactly five passing tests. To run only
those focused checks, use:

```sh
python3 -B tests/posix/fstack-reload-harness-runtime.py --focused-only
```

Runner rejection and cleanup behavior has a separate opt-in check. It verifies
that a modified pinned input is rejected, a real nonzero child exit is
preserved, and a timed-out bwrap PID namespace leaves no marked child process:

```sh
python3 -B -S tests/posix/reload-harness-runtime/test_runner.py
```

This check requires the same `bwrap` namespace support as the main runner and
does not invoke the 53-test upstream suite.

## Requirements and isolation

The host needs Python 3, `bwrap` (bubblewrap), and a C compiler named `cc`.
The sandbox must support user, PID, network, IPC, and UTS namespaces. Missing
tools or namespace support are failures; there is no unsandboxed fallback.
The runner has a bounded timeout (300 seconds by default, at most 900 seconds).

The sandbox uses a read-only root and repository, private `/proc`, isolated
network and process namespaces, cleared environment, and private writable
`/tmp` and `/data/workspace`. The only upstream test directory overlaid is the
private copy containing the verified fixture source and its compiled binary.
The helper scripts are copied into the private workspace. No host-global tool
installation, host process, upstream source, network service, or test expectation
is modified by the runner.

The kill helper's `.sh` entry point is intentional: the pinned supervisor calls
the tool through `/bin/bash`. Each shell wrapper resolves its adjacent Python
helper and executes `/usr/bin/python3` directly. The kill helper requires full
PID/start-time/executable/device/inode identity, uses pidfds, has bounded
wait-only behavior, and does not fall back to numeric-PID signaling or escalate
signals. Cleanup and chmod helpers are limited to private fixture directories.

## Evidence boundary

A pass means only that the pinned reload harness's tooling tests execute under
this isolated host environment and the Ker helper contracts pass their focused
tests. It is not a native F-Stack dataplane run, does not establish imported
Linux TCP behavior, and must not be counted as native compatibility coverage.
