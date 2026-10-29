# Standalone RSS thash qualification

Exactly two cases from F-Stack `646a641cfff77f4815e1e29829a09e1ed15a2999`
are qualified:

- `tests/unit/test_ff_dpdk_if.c::test_ff_rss_thash_equivalence_hitrate`
- `tests/unit/test_ff_dpdk_if.c::test_ff_rss_thash6_equivalence_hitrate`

The original cases already consume DPDK directly. No Ker production helper,
port allocator or protocol implementation is introduced. The complete source
bodies, dependent arithmetic helpers, key and seeds are retained in
`tests/fstack-rss-thash-source.inc`; `fstack-rss-thash-import` checks their bytes
against the immutable upstream snapshot. Linux, DPDK, imported F-Stack runtime
and the snapshot are unchanged.

`fstack-rss-thash-ipv4` and `fstack-rss-thash-ipv6` initialize actual primary EAL,
create real thash contexts and helpers, and execute every original assertion.
Each address family checks200 tuples for RETA128 and512. Adjustment success
must be positive and both full retry loops must reach200/200 with the original
independent software Toeplitz oracle. First-candidate rates are measured data;
they are not the full-loop threshold. The source's PRNG seeds are unchanged.
The adapter makes EAL failure and source skip fatal. Successful completion
additionally requires both context names absent and successful EAL cleanup.

The fixture uses the existing no-huge EAL helper, one CPU from the caller's
allowed affinity, a PID-specific namespace,64MiB, no PCI, no shared config and
VA IOVA. It runs as the unprivileged repository user without modifying host
hugepages. Qualification subprocesses use separate temporary runtime directories.

`fstack-rss-thash-quality-gates` repeats each family and requires identical
measured output. Its separate negative executable still calls the real DPDK
solver but rejects its results; each family must fail the unchanged
`adj128 > 0` assertion. An actual invalid EAL option must terminate unsuccessfully
without a pass marker, whether DPDK returns an error or exits from its parser.
No negative-control override is linked into the normal executable or Ker.

## Measured result

Local DPDK26.11.0-rc0, Release/shared configuration, strict C11 with extensions
disabled and `-Wall -Wextra -Werror`:

| Family | RETA | Adjustment success | First candidate software match | Full retry loop |
| --- | ---: | ---: | ---: | ---: |
| IPv4 |128|200/200|52/200|200/200|
| IPv4 |512|200/200|55/200|200/200|
| IPv6 |128|200/200|43/200|200/200|
| IPv6 |512|200/200|44/200|200/200|

GCC16.2.1 and Clang builds each passed all four focused CTests. The local
qualification manifest at
`/home/hurricane/.local/state/ker-compat-work/fstack-rss-thash-evidence/qualification-manifest.json`
(SHA-256 `c61afb68ef740d5a84c0731cfec77e2d7caaf5ef9132162b431473c039602255`)
binds the test sources, build logs, normal/negative binaries and raw repeat
results for both compilers to baseline `61fd8ce30092f90c044fd58db96f674b6b1082c8`.
It records the actual unprivileged UID1002.

The four focused CTests include the two source cases, qualification controls
and byte provenance. The catalog audit retains106 pinned files and433 cases;
its21 mutation/regression tests pass. The catalog changes270/12/81 to272/12/79
(adapted/partial/blocked), leaving91 behavioral cases incomplete. Issue220
retains29 cases:28 blocked and one partial.

This is dependency arithmetic qualification. No physical PMD RX queue, actual
packet distribution, source-port table or original Linux allocator integration
is observed. The source's word “landing” here refers to the software hash
predicate. Remaining requirements are in [RSS contracts](fstack-rss-contracts.md).

## Reproduce

Configure Ker with `BUILD_TESTING=ON`, `KER_WITH_DPDK=ON` and its supported
DPDK dependency. Then run:

```sh
cmake --build build --target ker-fstack-rss-thash-test ker-fstack-rss-thash-negative-test
ctest --test-dir build --output-on-failure -R '^fstack-rss-thash-'
python3 tests/fstack_migration.py
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -p test_fstack_migration.py
```

The qualification driver accepts `--evidence PATH` to retain raw stdout/stderr,
return codes, repeated measurements and negative results in a new JSON file.
It requires `--app` and `--negative-app` paths to the two built executables.
