# Real secondary attachment prerequisite

The generation design requires actual EAL secondaries. A primary starting or a
shared ring name existing is insufficient evidence. On the examined host with
original DPDK 26.11.0-rc0, a small independently compiled EAL diagnostic produced
these results before any PMD or application code ran:

| Profile | Observed result |
| --- | --- |
| Primary with `--no-huge`, 64 MB, no PCI | Initializes, reserves a named memzone, creates a named ring, publishes readiness and stays alive. |
| Secondary with the same namespace and `--no-huge` | Original EAL fails to open `<runtime>/dpdk/<prefix>/hugepage_data`, then reports `Cannot init memory`; it never reaches memzone/ring lookup. The primary remains alive and exits cleanly after the diagnostic. |
| Primary without `--no-huge`, otherwise the same | Original EAL reports no free 2048 kB hugepages and cannot obtain hugepage information. No readiness or shared lookup occurs. |

The command shape was `eal-attach --proc-type=primary|secondary
--lcores=0@<allowed-cpu> --no-pci --no-telemetry --iova-mode=va -m 64
--file-prefix=<private-prefix> [--no-huge]`, with one temporary
`RUNTIME_DIRECTORY` shared by the processes. The diagnostic links the existing
original DPDK install and directly calls `rte_eal_init`, then primary
`rte_memzone_reserve`/`rte_ring_create` or secondary lookup. Its failure return
10 is the diagnostic's exit code, not an EAL error number. Cleanup reaps its
exact children and removes only its own temporary runtime directory.

The host reported `HugePages_Total: 0` and `HugePages_Free: 0`; the existing
hugetlbfs mount is owned by root and ordinary-user privilege escalation is not
available. No global hugepage, ASLR, mount or NIC setting was changed. Anonymous
transparent hugepages in `/proc/meminfo` do not supply the missing hugetlb EAL
memory mode. This is a local qualification blocker, not a finding that original
DPDK secondaries are universally unsupported.

The original DPDK source agrees with the observed failure: no-huge uses legacy
memory, while the secondary legacy attach path opens the primary's
`hugepage_data`. Do not fabricate that file, patch upstream memory management,
claim a pass from independent primaries, or lift Ker's secondary rejection as a
workaround. The next executable gate needs usable shared hugepage memory and then actual
secondary/PMD lookup and packet delivery; the isolated guest investigation below
subsequently provides the shared-memory prerequisite. This diagnostic
does not test PMD secondary compatibility, generation ownership, two live
masters, original Linux networking or graceful reload.

Raw source, compile/run commands and captured stderr are recorded with the
implementation investigation in #218. All 79 actionable generation cases remain
blocked. Work on other source contracts continues independently of this host
prerequisite; the migration goal is not complete.

## Isolated guest removes the local shared-memory prerequisite blocker

A subsequent diagnostic used the installed unmodified QEMU10.2.2 with TCG, the
readable packaged Fedora7.2.11 kernel,512MiB guest RAM, one virtual CPU, no NIC,
and a small initramfs assembled from the host Python runtime, its actual shared
library dependencies, and the same independently compiled EAL diagnostic. The
guest kernel command line reserves64 ordinary2MiB hugepages inside guest RAM;
its root init mounts guest proc/sysfs/devtmpfs/hugetlbfs. This consumes no host
hugetlb pages and changes no host sysctl, ASLR, mount, permissions or NIC state.

```text
qemu-system-x86_64 -accel tcg -cpu max -smp 1 -m 512 \
  -nodefaults -no-reboot -display none -serial stdio -nic none \
  -kernel <readable-packaged-kernel> -initrd <diagnostic-initramfs> \
  -append 'console=ttyS0 rdinit=/init.py panic=-1 loglevel=4 hugepages=64'
```

Inside that guest, the original DPDK primary starts with64MB and creates the
named memzone and ring under `/run/dpdk/ker-guest`. A real secondary starts with
the same namespace and hugepage mount, looks up both shared objects and verifies
the primary's memzone sentinel. The secondary returns0, the primary remains
live, and after its explicit release the primary's cleanup returns0. The guest
then powers down and QEMU exits normally. Observed serial markers:

```text
PRIMARY_OUT PROBE_PRIMARY_READY
SECONDARY_RESULT {"exit": 0, "stdout": "PROBE_SECONDARY_ATTACHED_SHARED_OBJECTS\n", ...}
PRIMARY_END 0
GUEST_EAL_SHARED_ATTACH_PASS
```

The first initramfs lacked `libgcc_s.so.1`, which glibc dynamically needs for
pthread cancellation during cleanup; that run aborted and is not success
evidence. After including the real library, the complete lookup and both
cleanup paths above passed. The diagnostic sources/build script and full serial
logs are retained with the #218 investigation artifacts.

This changes the next implementation action: integrate supervised primary and
secondary lifetimes using this guest environment, then prove the actual two
simultaneously live master chains, registration, queue ownership and data
transport. Do not wait for host privilege escalation merely to retry the old
no-huge profile. It does not qualify any source case yet: no PMD/device is
configured here, no packets or ring tokens are exchanged, no epochs/generations
exist, and no original Linux application networking or graceful reload runs.
All79generation cases remain blocked until their actual implementation and
acceptance evidence exist.
