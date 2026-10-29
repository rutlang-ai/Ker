# A10 synthetic metadata dispatch mechanisms

Exactly two source cases from
`tests/integration/test_ff_reload_integration.c` at F-Stack
`646a641cfff77f4815e1e29829a09e1ed15a2999` are scenario-adapted:

| Source case | CTest | Original bounded judgment |
| --- | --- | --- |
| `test_it_a10_halfopen_dispatch` | `fstack-a10-halfopen-dispatch` | Unrecorded tuple forwards an original mbuf; caller-published metadata exists before a second input, whose hit is consumed locally while the first peer packet remains queued |
| `test_it_a10_halfopen_window_mechanism` | `fstack-a10-window-mechanism` | Two repeated same-tuple fixtures forward and consume once through parked software input; a closed-window miss drops/counts and restores the pool |

The source harness explicitly simulates admission and links no FreeBSD stack.
Its comments reserve actual ESTABLISHED, no-RST, syncache drain and two-process
RV12 judgments for later runtime work. Its repeated “later data” fixture is
constructed by the same fixed ACK-shaped packet helper. This qualification
preserves that synthetic mechanism scope. It establishes no real half-open
TCP connection, Linux SYN/PCB/syncache hook, actual TCP data exchange,
physical NIC or full application reload.

## Caller-only composition

The existing original flow table remains caller-owned. The original
`it_flow_dispatcher`, `fill_tcp_ack`, `inj_mbuf` and `flow_key_v4` bodies are
retained byte-for-byte in excerpts. `fstack-a10-source-import` checks them
against the immutable source snapshot. A caller wrapper bounds Ethernet,
optional single VLAN, IPv4 IHL and TCP header reads before entering the source
classifier; out-of-profile layouts go to the caller's local input path. It does not
validate a complete network protocol or implement TCP state.

`ker-example-a10-dispatch` is an application policy fixture, not a Ker library
or exported component. It composes the existing public peer dispatcher,
reload gate and caller flow-map policy. No Ker implementation/header or
imported upstream file changes. The application input sink observes exact
bytes and ownership, then frees its mbuf; it is not a stand-in TCP engine.

The classifier role polls original net_ring RX through `ker_reload_poll`.
A metadata miss uses `ker_packet_dispatch_peer` to transfer ownership. A hit
reaches the chosen local application sink. The parked role consumes its
caller-owned software ring directly into the application input callback,
without running the classifier again. The hardware-owner role leaves that
ring untouched. Ring identity, exclusivity, callback ownership and lifetime
remain caller responsibilities. This is a serialized, directory-less,
un-stopped role profile; stopped RX returns `-EAGAIN` without consuming input.

## Actual execution

Real EAL/net_ring RX is observed by an independent DPDK RX callback and
original driver `ipackets`. The driver must transmit no packets. Each input
sink checks actual role permission, original mbuf pointer, complete length,
all bytes and one reference before releasing ownership.

Observed normal results:

| Mode | Original PMD inputs | Classifier calls | Local inputs | Parked inputs | Other observations |
| --- | ---: | ---: | ---: | ---: | --- |
| Dispatch |2|2|1|1|Before cleanup: peer ring1, pool511; after parked input: pool512 |
| Window mechanism |3|3|0|2|Two forwards, then closed1/drop-segments1; pool512 |
| Bounds/roles |5|5|5|1|Valid/VLAN input plus malformed header layouts; invalid budget and stopped RX retain the peer packet |

The bounds mode's role/budget fixture is queued directly in the software peer
ring, separately from its five PMD inputs.

The owner is denied software-peer consumption before role switch. A hardware
poll attempt while parked invokes no callback. Parked input does not increase
classifier or hardware counters, and a second dequeue is empty. Application
input therefore runs once per transferred object, with no recirculation.
Every mode allocates all512 pool objects afterward, requires unique pointers
and exact exhaustion, returns them, and releases callback/state/table, PMD,
rings, pool and EAL. No init failure is accepted as a skip.

GCC Release/shared and Clang Release/static builds require strict C11 and
warnings as errors; all4 focused checks pass in each configuration. An external CMake consumer repeats all3
runtime modes against installed public Ker targets and libraries, with copied
caller policy archives, public example headers and fixture helpers. It uses no
private Ker implementation/header. All19 new/related flow-map, peer, reload
and callback checks pass, as do the106-file/433-case audit and21 catalog
regression/mutation tests.

Two separate private negative builds preserve the assertions: forcing a local
result despite executing the real source classifier fails the required peer
outcome; reclassifying dequeued peer input recirculates it and fails the
empty-after-consumption assertion. Neither mutation enters normal artifacts.

Qualified implementation: `018e37c76393bd13055f0908d3a485f747a05abb`.
Manifest:
`/home/hurricane/.local/state/ker-compat-work/fstack-a10-dispatch-evidence/qualification-manifest.json`,
SHA-256 `1e71b41a3f860cfd5b3357339f94528060ce4ef5bb186e8b8b6d864c4d10b9f2`.
It binds source/excerpt hashes, builds, raw normal/negative results, copied
caller archives, installed library/target and external consumer. Execution
uses unprivileged UID1002, one allowed CPU, no PCI and no hugepages; host
settings are unchanged.

Only the two named source cases gain status:282/12/69 becomes284/12/67
(adapted/partial/blocked), leaving79 behavioral cases incomplete. Full RV12
and application reload remain under issue218. No operational TCP criterion
is counted as passed by this batch.

## Reproduce

Configure `KER_WITH_DPDK=ON`, `BUILD_TESTING=ON` and supported DPDK:

```sh
cmake --build build --target ker-fstack-a10-dispatch-test
ctest --test-dir build --output-on-failure -R '^fstack-a10-'
python3 tests/fstack_migration.py
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -p test_fstack_migration.py
```
