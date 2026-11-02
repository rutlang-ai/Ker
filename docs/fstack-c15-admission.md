# C15 original-Linux SYN-ACK admission boundary

C15 is a private qualification fixture for holding an original-LKL TCP
SYN-ACK until the unchanged F-Stack flow-map owner admits the four-tuple. It
does not enable public graceful reload, alter `ff_flow_map`, replace a TCP
state machine, or qualify the Nginx dispatcher/FSM.

The private, disabled-by-default Ker LKL overlay hooks original IPv4
`LOCAL_OUT` packets carrying the registered mark into the original kernel
NFQUEUE implementation. The test controller binds and configures the queue,
receives the kernel-issued queue lease, authenticates the separate map-owner
process, and only then calls `listen()` on the application descriptor and
publishes `READY`. The external host client starts only after that marker. A
failed setup closes the unlistened application descriptor and queue while
leaving the mark gated. There is no fail-open queue mode.

The current qualification is limited to one IPv4 owner/listener/registered
mark, with stateful request sockets and no TFO or forced syncookies. The
private queue device accepts a trusted privileged caller's mark; production
broker-owner mark binding is not yet integrated. The fixture's credentialed
map-owner channel does not authenticate the queue-device caller.

The map owner is a separate process started before `ker-run`; every imported
`ff_flow_map` operation stays on its one owner thread. The controller submits
bounded commands over a private credential-checked Unix `SOCK_SEQPACKET`
channel. Each original NFQUEUE packet has one absolute 250 ms decision
deadline. A timeout or lost result fails closed. A map entry created for a
packet that was definitely not accepted is revoked on the owner thread. Once
an `NF_ACCEPT` send may have reached the kernel, ACK loss is uncertain and the
map entry is retained. A retransmitted SYN-ACK for an existing key is admitted
as a duplicate without deleting the existing entry.

The private original-LKL loopback test also submits a verdict for a nonexistent
NFQUEUE packet ID. It requires the kernel's matching `-ENOENT` ACK, verifies
that the actual pending packet remains recorded and prevents queue disarm,
then closes the queue so any still-queued packet is dropped. A second queue
cannot replace the still-registered mark. This covers the rule that a full
netlink send or DROP error does not prove that the queued skb was removed.

## Evidence and reproduction

The frozen native Linux input for this fixture is fingerprint
`399c02b3aa05a7ee2a35c13fca64a279198c0d0675a8dc218eddc07399525b8d`.
The focused build used `/dev/shm/ker-c15-cmake` with the matching original
kernel artifact at `/dev/shm/ker-c15-native-full` and the installed DPDK
pkg-config directory from the local `dpdk-tap-retry-install` package.

From the feature checkout, after providing the exact lightweight Linux source
tree needed by CMake, reproduce the focused checks with:

```sh
cmake -S . -B /dev/shm/ker-c15-cmake \
  -DKER_NATIVE_LINUX_BUILD=/dev/shm/ker-c15-native-full \
  -DKER_DPDK_PKGCONFIG_DIR=/home/hurricane/.local/state/ker-compat-work/dpdk-tap-retry-install/lib64/pkgconfig \
  -DKER_WITH_DPDK=ON -DKER_WITH_NATIVE_TCP=ON \
  -DKER_BUILD_FSTACK_NGINX_RUNTIME=OFF -DKER_BUILD_EXAMPLES=OFF \
  -DBUILD_TESTING=ON
cmake --build /dev/shm/ker-c15-cmake --target \
  ker-fstack-c15-admission-wire ker-fstack-c15-admission-channel \
  ker-posix-member-census-test-runtime ker-c15-admission-tap-client \
  ker-c15-admission-map-owner ker-io-worker ker-app -j4
LD_LIBRARY_PATH=/home/hurricane/.local/state/ker-compat-work/dpdk-tap-retry-install/lib64 \
  ctest --test-dir /dev/shm/ker-c15-cmake --output-on-failure \
  -R '^(fstack-c15-admission-owner-channel|fstack-c15-original-lkl-loopback-admission-smoke|native-c15-admission-tap-smoke)$'
```

The external TAP case uses 16 distinct real handshakes that collide in the
unchanged original map, then verifies the 17th full-map request is rejected,
its exact Linux request is revoked, no SYN-ACK escapes, and a late ACK receives
the original Linux reset. Separate controls cover lost ACCEPT ACK with the
map retained, a SIGSTOP map owner with an independent 250 ms controller
deadline, and an original TCP SYN-ACK retransmission that hits the duplicate
map entry. The handshake controls wait for server-side `accept4()`, not only
the host active-open socket's local completion. Retransmission comparison
requires the same server sequence and all non-timestamp TCP options; timestamp
values legitimately change on retransmission.

These checks qualify only the private admission adapter and its original-Linux
packet behavior. The pinned Nginx source itself calls its real map arm from
`app/nginx-1.28.0/src/event/modules/ngx_ff_module.c` when its original reload
window predicates hold. C15 does not yet bind Ker's runtime to that arm,
dispatcher, map lifetime, or generation FSM; those remain separate migration
work and do not change any F-Stack test catalog counts.
