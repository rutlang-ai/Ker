# Continuous integration

The GitHub Actions workflow runs on pull requests and pushes to `main` with a
read-only repository token. The Linux core matrix uses GCC and Clang, enables
`-Wall -Wextra -Werror`, and builds with `BUILD_TESTING` both enabled and
disabled. The enabled configuration runs the registered CTest suite and treats
an empty test set as a failure. The disabled configuration also checks that the
production library and examples install.

The core job checks out the Linux submodule at the commit recorded by the
repository and does not install DPDK. This matches the current CMake target graph:
the initial checksum and timer library does not consume DPDK.

A separate job builds the DPDK submodule at its recorded gitlink using Meson (or
the repository's pinned DPDK build script when present). It does not use a
distro DPDK package. If Ker's DPDK CMake integration is present, the job also
configures and tests Ker with that pinned installation while keeping the native
TCP runtime disabled. Otherwise, the standalone dependency build is the
available DPDK check. CTest cases that require unavailable host facilities may
report their configured skip status; this is not evidence of EAL, PMD,
native-network, or hardware runtime coverage.

The Python unit-test step runs only when `tests/unit/test_*.py` files exist; it
is skipped for this snapshot, which has no Python unit tests. The CTest suite is
the executed test suite here.
