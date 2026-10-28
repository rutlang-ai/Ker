# M5 directory coordinates and same-generation handover

Four baseline-incomplete cases now complete the original M5 contracts. Together
with previous batches, the objective is **40/50**, with 10 still required.
Original Linux/DPDK and imported F-Stack sources remain unchanged. The optional
`ker::reload` component now has 45 public APIs; its new peer observation API
exposes original selected/published coordinates and the observer-owner predicate.
Imported helpers remain hidden. The caller owns EAL, all packet work, queue
initialization, control policy and process supervision.

| Source case | Independent CTest |
|---|---|
| `test_ut_nr_m5_gendir_arbitration` | `fstack-reload-m5-arbitration` |
| `test_ut_nr_m5_probe_epoch_fallback` | `fstack-reload-m5-probe` |
| `test_ut_nr_m5_cross_master_name_isolation` | `fstack-reload-m5-names` |
| `test_ut_nr_m5_cross_master_handover_sequence` | `fstack-reload-m5-handover` |

`tests/fstack-reload-m5-source.inc` contains all four complete original functions,
including every source assertion and its real fork/reaped-PID conditions. The
import guard compares the excerpt byte-for-byte with the pinned upstream
snapshot. The fixture compiles the actual production runtime TU for private
source preconditions; only cmocka's assertion host maps to CHECK. All selectors
pass in Debug/static and Release/shared. No fixture setter is installed.

## QUERY chooses actual control queues

The real primary calls the original message-fill adapter. With no active mirror,
QUERY chooses the newest real master, then the remaining master after the other
master/secondary exits, then epoch0 after both lifetimes end. With serving epoch4
and newer live epoch5, the explicit active word chooses epoch4. After handover it
chooses epoch5; after rollback it chooses epoch4 again.

Each nonempty QUERY result feeds the actual exported `ker::ipc` address selector,
allocation and send operation. A separate EAL secondary dequeues that exact FF
input ring and replies on its type-specific FF output ring. The original recv
and free APIs validate/return the same message, PID/cookie, nonce, sequence and
payload. The high process ID127 is used for every locator-driven QUERY. This
checks the consumer of the coordinate, rather than only printing the locator.

Each real master owns88 original FF-named rings: processes0/1/7/127, gen0/1,
one input and ten typed outputs per coordinate. Directory epochs4/5 use actual
slots1/2. The complete160-coordinate matrix performs real original IPC
send/receive and secondary consumption for both epochs, both generations, all
four processes and all ten output families. Together with six locator-driven
requests, each profile completes166 roundtrips and352 ring create/destroy
lifetimes across four epochs. Prior epochs and their consumers are fully reaped
before a recycled name is recreated. The typed original DPDK message pool
returns63/63 objects after each roundtrip and at final teardown.

Only FF_RELOAD QUERY is interpreted. Other families return EOPNOTSUPP while
transporting their payload and identity unchanged. These cases qualify complete
ring naming and typed transport, not FreeBSD command execution.

## Same generation, separate masters

The final two masters both run generation0 and borrow separate shared state
blocks. Both blocks locally name generation0 as owner, so only the original
directory can prevent double polling. A held old callback leaves the actual
PMD RX object queued; the foreign worker's poll is denied and its claim times
out. An old peer worker uses `ker_reload_directory_peer` to choose the real
foreign coordinate for release. The original production5s wait refuses while
the old callback is in flight and restores its local park state.

After callback completion and STOPPED proof, release transfers the coordinate
while preserving the directory park order. Both old and target polling passes
are denied until explicit claim. The adapter suppresses mirroring of the
unparked target-private block while a transferred directory park order remains;
otherwise the original mirror could clear that order before claim. Original
peer observations and liveness stamping continue during the denied pass.

Claim permits the new master's actual PMD receive/transmit. Observer-owner and
published peer coordinates match the serving master. Rollback is refused while
the new master lives. The test then SIGKILLs/reaps that actual master, adopts its
still-live worker through the established subreaper/FD-transfer fixture, obtains
STOPPED and real timestamp staleness, and reclaims for the old master. The old
hand-over target and local park state are cleared before serving resumes. The
surviving target worker remains denied and cannot steal through its own mirror.

Each profile checks the identical three PMD mbufs with nonce, sequence and all
payload bytes, PMD RX/TX3/3, callbacks/received `[2,0,1,0]`, empty queues, no
in-flight work and packet pool63/63. All actual participants are reaped before
primary destruction. The independently installed program uses the same caller
source, `find_package(ker)` and public Ker/DPDK interfaces; installed CMake/link,
source, library and executable hashes are bound in the package manifest.

## Evidence and limits

Fresh isolated guest12 at candidate
`3f2901371678d0923835ebdc0612d8c4fc372796` passes all nine runtime profiles,
including both new repository/installed profiles and all previous IPC, polling,
controller and directory consumers. Both old examples pass, followed by normal
guest power-down and QEMU exit0. Host shared-hugepage skip77 is not completion
evidence. Artifacts are outside worktrees at
`/home/hurricane/.local/state/ker-compat-work/fstack-unfinished-ipc-guest12`:

| Artifact | SHA256 |
|---|---|
| `actual-result-attempt1.json` | `34827d1f16daa4117b398599f7096b8e7da121638af1a86976758bfa46cbf4fa` |
| `package-manifest.json` | `24a8080acf05acb3c4add96216072b81ac007f4d68c7e9fab2dca9d52d170614` |
| `initramfs.cpio.gz` | `a3ba7b122c56a39c6a855e7121def0d69e6fc328be96d60035d2472fd450c068` |
| `serial-attempt1.log` | `9daab70224d171333c046a8a06b3b228a75672d845e0094191c20e576ef5f649` |
| `qemu-command-attempt1.json` | `a7570b4c185129a04d398b6b1efe6795cf4afba803cb7773355062e0d1e1ff07` |
| `qemu-host-attempt1.log` | `659fbea079cc86b145595394d5604d207a193b5bca774bb3a53bf6c144753757` |

This proves the named original M5 runtime contracts with a software PMD. It does
not qualify the remaining P1 live-slot case, physical NIC DMA, imported-Linux
packet delivery through this component, TCP continuity or full application
reload. Peer views are observations rather than one atomic global snapshot.
