# Bounded old-owner relay transport

The private `rx-owner-relay-peer` adapter provides one old-owner transport hop
for an already authenticated primary classifier's PEER reply. It sends the
complete unchanged frame snapshot over a caller-supplied `SOCK_SEQPACKET`
channel. The original DPDK packet stays with its C31 producer; the adapter
never injects a copied frame or transfers an mbuf into another address space.

The caller must first authenticate the supervisor, old owner's initial slot,
generation, capability, READY identity and delegated descriptors. This adapter
does not discover or select a peer, register an old owner, or authorize a slot
from an application's PID. Its private binding pins the expected owner with
a pidfd and process start ticks and supplies the shared run/worker identity.
The caller must retain and revalidate live reload-window/slot authority before
settling C31; a transport reply alone does not authorize a generation transition.
For every reply the transport checks the actual `SCM_CREDENTIALS` PID/UID/GID,
owner PID/TID/start ticks, pidfd liveness, nonce, epoch, original packet id and
deadline, queue/VLAN metadata, exact bytes, hash and unchanged marker.
Unexpected descriptors are closed and rejected.

Each packet id gets at most one send attempt. The outgoing old-owner request
keeps the producer's original absolute deadline, capped by the existing C31
100 ms lease bound. Polling never renews it. Only a live old owner's unchanged
local-queue result can produce a C31 LOCAL disposition. A second PEER, ERROR,
RESPONSE or other-queue result becomes DROP, so this hop cannot loop. Transport
or validation errors leave the caller's output unchanged and require producer
DROP/expiry; they do not authorize delivery. Calls on one binding are serialized.

The C31 relay consumer now uses this boundary for PEER results. Its existing
single-owner profile deliberately has an unbound old peer and still drops.
The supervisor does not yet delegate a second authenticated owner/channel;
connecting that authority and qualifying real old/new Nginx traffic is the next
integration step. This change does not enable production graceful reload,
authenticate two generations, preserve old TCP streams by itself, or complete
the original source shell entrypoint. Migration counts remain unchanged.

`native-rx-owner-relay-peer-transport` uses real child processes, Unix packet
sockets, kernel credentials and pidfds to exercise the transport. It verifies
opaque frame delivery, local/drop results, same-id rejection, deadline expiry,
stale identity and context, a foreign sending process, mutated bytes/metadata,
unexpected descriptors and exact FD reclamation. The reply workers model wire
results only; this is an adapter test, not imported-classifier or original-Linux
TCP interoperability evidence. Existing source-admission tests separately run
the original classifier and original Linux TCP and retain PEER-to-DROP.

```sh
ctest --test-dir <build> --output-on-failure \
  -R '^native-rx-owner-relay-peer-transport$'
```

Local validation passed all 28 transport controls with GCC, Clang, and
ASan/UBSan, and passed the Release CTest with DPDK/native TCP disabled. The
source flow-map, admission, admission-revoke and PREPARED-failure CTests and
the existing owner-relay pump test also passed. Inventory audit and guards
retain 362 adapted, zero partial and one blocked entry.
