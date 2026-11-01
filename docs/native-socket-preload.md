# Native socket broker POSIX preload

`ker::socket-preload` is a caller-side adapter over the explicit
[native socket broker](native-socket-broker.md) API. It lets a compatible
Linux process use ordinary integer descriptors for a bounded set of original
Linux TCP operations while retaining host files, Unix sockets, eventfds, and
host epoll descriptors. The preload library links to `ker::socket-client`,
not `libker-posix` or LKL. The broker remains the only process that loads and
runs the original Linux networking stack.

The current profile supports `AF_INET` and `AF_INET6` `SOCK_STREAM` sockets,
socket setup and naming calls, `accept4`, `shutdown`, the documented broker
socket options, scalar and vectored read/write, `send`/`recv`, and mixed
host/original-Linux epoll. Host descriptors take the host libc path. Existing
host UDP descriptors remain host descriptors; creating an INET datagram
socket through the native profile is rejected. Native
user buffers and iovec arrays are copied with fault-aware process memory
access before broker calls. Host arguments are not truncated to broker limits.
Each native broker data operation is bounded to 4096 bytes. A larger scalar or
vectored request may return a short transfer; callers retry the remaining
bytes as normal POSIX code does. For host-file to native-socket `sendfile`, the
adapter uses bounded `pread` plus original-Linux `send` and preserves partial
progress and the caller's offset rules.

Mixed epoll uses a host epoll descriptor plus the broker's original-Linux
epoll capability. It waits on both readiness sources without holding the
descriptor-map lock across an interruptible host wait, and alternates which
source gets first priority. It does not keep a replay queue of events. Native
socket and composite-epoll descriptors can be inherited through `fork`; a
child authenticates a fresh broker RPC session on its first request. Exec
reconstructs inherited socket capabilities when the replacement environment
preserves `LD_PRELOAD` and `KER_SOCKET_BROKER_PATH`. An exec that would preserve a
non-close-on-exec composite epoll is rejected with `EOPNOTSUPP` before the
exec call, because recreating only one half would lose registrations. Fixed
destination `dup2`/`dup3` onto native capabilities is also unsupported and
fails before mutation. Ordinary host `dup2`, including daemon log and stderr
redirection, remains host behavior.

This is an explicit compatibility profile, not a transparent general-purpose
POSIX backend. Native UDP, arbitrary socket families, arbitrary ioctl or
fcntl commands, ancillary data, unsupported message flags, `select`/`poll`,
`posix_spawn`, `system`, and `popen` are outside the profile. The explicit
broker SDK's epoll RPC is nonblocking and only polls original Linux with
timeout zero; the preload frontend supplies POSIX epoll timeouts by combining
that poll with a host epoll wait. A broker transport failure never falls back
to a host socket. The adapter raises `SIGPIPE` in the caller for native writes
that return `EPIPE`, unless the send flags request suppression.

## Nginx prerequisite

The optional `native-nginx-socket-preload-lifecycle` CTest accepts a separately
built, pinned Nginx binary through `KER_NO_FF_NGINX_BINARY`. The test runs the
unmodified no-FF Nginx image with the preload and a broker, then checks active
HTTP stream bytes across HUP worker replacement and USR2 exec handover, the
inherited listener, WINCH retirement of old workers, and continued service by
the replacement master. The external client verifies response lengths and
body hashes. Nginx starts in a user/network namespace with its real worker
credential path; no credential or networking stubs are used.

The tested source is F-Stack commit
[`646a641cfff77f4815e1e29829a09e1ed15a2999`](https://github.com/F-Stack/f-stack/tree/646a641cfff77f4815e1e29829a09e1ed15a2999/app/nginx-1.28.0),
subtree tree `2cd18ae3bcc055a9d7bfb9c492297ec2f6ae3916`. It is Nginx 1.28.0
built without `--with-ff_module`; binary SHA-256 is
`d963f290aeca20e555e8bc71c834718e5c3d819ca7a83f0a5c571dbe04d2c55a`. The
external build-only compatibility header, helper C, helper object, and Make
override SHA-256 values are respectively
`10d93d84ca267d3bedd8e121d0888f79ee5d7785b6e3b7adcb68a3985fa88484`,
`30d079362e01d6d0c1f01bec4d1e4f3279701932299ea02b23ec9be60b090475`,
`60fcc5e9e1eea482b76b48857bc04cfbaeb46366456bf5bae9980c6f923747f4`, and
`1e21333eab901ad41355ee7cc1ad424efe021e5053c1a7bc7ede6dc45fc4005a`. These
files live outside the repository and only make the no-FF host control image
buildable; the header rejects an enabled F-Stack build and aborts if disabled
profile fallback hooks are reached.

This demonstrates that the current caller adapter can support this tested
no-FF Nginx profile. It does not run Nginx's F-Stack module, qualify the full
upstream F-Stack fault/performance matrix, or migrate the graceful-reload
compatibility case. That case remains blocked until the original F-Stack
runtime lifecycle and its service-level counters and state transitions are
exercised end to end.
