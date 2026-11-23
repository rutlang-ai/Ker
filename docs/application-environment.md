# Application environment adaptation

`native-fstack-application-environment` adapts the environment set/get scenario
from `tests/unit/test_ff_host_interface.c::test_ff_setenv_getenv_roundtrip` to an
existing production consumer. [ker-app](../src/posix/app-guard.c) reads the
launcher's `KER_PRELOAD_LIBRARY`, calls real `setenv("LD_PRELOAD", ..., 1)`,
removes its internal key, and executes the application. No new environment API,
FreeBSD environment namespace or unused `ff_*` wrapper is introduced.

The test launcher starts with a deliberately wrong inherited internal key and
an unrelated `hello-world` application value. The actual launcher replaces the
internal key with its resolved native library path. After the real guard's
setenv/exec and native constructor, the test application requires the exact
`LD_PRELOAD` value, absence of `KER_PRELOAD_LIBRARY`, and preservation of the
unrelated value. It resolves the real Ker capability entry point and exchanges
an exact TCP payload inside original Linux; the guard prohibits host TCP
syscalls. Shutdown statistics must show exactly one native active and passive
open and no outstanding worker mbufs. The enclosing runner retains independent
host/DPDK TCP acceptance as well.

A deliberately wrong expected preload value must return application status 1
before any native TCP open, omit the success marker, and still clean up the
runtime. A separate development mutation that changes the production guard's
preload destination key must fail native startup. This is evidence that real
application configuration is exercised, not a standalone libc set/get program.
It does not qualify arbitrary F-Stack ABI parity, environment mutation after
threads start, cross-process shared environment, time caches, file-backed/shared
host mmap, or idempotent kqueue registration.

The source literal variable name/value are test data; the adapted consumer uses
its actual preload configuration key/path. The observed roundtrip goes through
production Ker code and a real executed native application. Only this one
source scenario receives a mapping. Nine other cases in #229 remain open.
