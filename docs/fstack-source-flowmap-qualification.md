# Original Nginx flow-map qualification slice

The private `native-nginx-companion-rx-source-flowmap` test builds a Ker-owned
alias module that textually includes the checksum-pinned, unchanged
`ngx_ff_module.c`. The original static `ngx_ff_flow_map_arm` registers the
original `ngx_ff_flow_map_dispatcher`; the alias does not copy that classifier
or install broker admission operations. The source-created reload block and
its test-only locked window use the original state APIs. The alias projects the
source state only after the unchanged `ff_mod_init` consistency check.

On the authenticated Nginx owner thread, the test exercises the original
registered callback against complete IPv4 and IPv6 TCP fixture frames. For each
family it checks a map miss, calls the original unprefixed process-local map's
admit operation, checks a hit, revokes the entry, and checks a miss again. The
fixture's C31 relay then observes a real client TCP ACK from a unique source
port. The original classifier returns `FF_DISPATCH_PEER`; the existing Ker
adaptation maps that result to an explicit DROP. The receipt records owner PID
and TID, both checksummed fixture frames, the relayed frame, and settled C31
counters.

This slice verifies classifier/map identity and relay disposition. Fixture
map entries are not populated by the original stack's SYN path or by broker
admission. The source's original flow-map producer is still not connected to
Ker admission, PEER packets are not forwarded to an older owner, and the
`graceful_reload=1` runtime gate remains closed. The test does not qualify the
full Nginx reload state machine or claim the F-Stack dataplane is implemented.

Run the bounded checks from the configured native build:

```sh
ctest --test-dir "$BUILD_DIR" -R '^native-nginx-companion-rx-(source-flowmap|owner-relay)$' --output-on-failure
```
