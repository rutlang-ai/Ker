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
workaround. The next executable gate needs a host with usable shared hugepage
memory and then actual secondary/PMD lookup and packet delivery. This diagnostic
does not test PMD secondary compatibility, generation ownership, two live
masters, original Linux networking or graceful reload.

Raw source, compile/run commands and captured stderr are recorded with the
implementation investigation in #218. All 79 actionable generation cases remain
blocked. Work on other source contracts continues independently of this host
prerequisite; the migration goal is not complete.
