# Nginx RX owner relay prerequisite

The opt-in `--control-nginx-rx-relay` profile connects the C31 RX-decision
consumer to the authenticated Nginx worker owner loop. The broker application
copies each bounded full-frame lease before deferring it. The registered
`dispatch_func_context_t` callback runs on the authenticated Nginx worker's
`ff_run` thread; the C31 owner thread then completes the original lease. Both
ends bind the exchange to the run nonce, worker epoch, packet ID, deadline,
process start identities, and owner TID. Before relaying any frame, ker-run
also sends the validated C22 READY tuple and worker pidfd to the C31 app over a
separate supervisor-authenticated channel; the app acknowledges that exact
owner identity before ker-run sends APP_AUTH to the worker. A changed, stale,
late, or unsupported decision fails closed. Shutdown requires all deferred
leases to settle. If STOP arrives while a lease is pending and the original
lease deadline expires, the current behavior is a fail-closed timeout: native
shutdown can remain incomplete and the worker can report a shutdown discard.
This prerequisite does not promise successful asynchronous STOP completion or
permanent retention of actors after that failure.

The current qualification uses a test-only typed callback that returns the
unchanged queue and frame. A real post-READY HTTP request is correlated with
its full RX frame, exact owner echo, source port, and SHA-256 receipt. This
proves the owner-thread transport and callback ABI through original Linux; it
does not connect Nginx's original `ngx_ff_flow_map_dispatcher` or its map to
the Ker relay. That source classifier remains separate from the namespaced
candidate-admission map.

Consequently this prerequisite does not qualify the original source classifier,
PEER forwarding, graceful reload, or the broader F-Stack migration. The
`graceful_reload=1` preflight remains unsupported and fail-closed. Default
profiles retain their existing behavior; the relay requires explicit C31 and
authenticated C22 owner READY configuration.
