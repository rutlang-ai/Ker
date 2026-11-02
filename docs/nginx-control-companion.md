# Control-only Nginx companion

The opt-in `ker-run --broker-readiness --runtime-service --control-nginx-*`
profile starts one separately supervised Nginx master after the central native
broker has sent its authenticated READY record. The Nginx process does not
receive the native Linux packet, run, or runtime-service descriptors. Its
allowlisted environment contains the F-Stack preload, broker socket path, and
INI path; the profile hashes the binary, Nginx config, INI contents, prefix,
and allowlisted environment. It rejects `libker-posix` and requires an exact
`graceful_reload=0` broker configuration.

`ker-nginx-companion` is a dedicated child subreaper for the configured
`daemon off`, `master_process on`, one-worker Nginx subtree. It pins the helper,
supervisor, and actual Nginx master identities with process credentials,
start-time checks, executable hashes, and pidfds. It accepts only a correlated
reload request or a one-use STOP. STOP reports SETTLED only after the pinned
master and all adopted descendants have exited. An unknown or unresolved
subtree leaves `ker-run` in a retained-failure state with the native broker and
worker resources still held; explicit termination of that state is not a
successful cleanup proof.

A reload result confirms that the helper delivered SIGHUP to the pinned master;
it is not evidence that the new worker accepted traffic or that a graceful
reload generation was selected.

The broker READY/STOP exchange is separate from Nginx startup and cleanup.
`ker-run` advances its existing worker/application loop while waiting for
broker READY. On shutdown it settles the Nginx subtree first, then asks the
broker to stop and waits for the broker's normal native cleanup markers.
If the native application begins its own STOPPING/DONE sequence while the
companion is still active, `ker-run` rejects that order and retains the worker
resources; only the supervisor-controlled companion STOP followed by broker
STOP is treated as an orderly lifecycle.

This component is limited to a control-only, `graceful_reload=0` Nginx
companion profile. It does not enable `graceful_reload=1`, register the original
packet dispatcher, grant Nginx a primary runtime-service lease, or qualify the
full upstream graceful-reload entrypoint. The helper process test uses a small
non-networking executable to exercise pidfd and subreaper ownership; it does
not qualify real Nginx traffic, reload, or the upstream integration entrypoint.
