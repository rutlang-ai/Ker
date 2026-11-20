# The imported directory and drain implementation is linked into this EAL
# caller so its test doubles cannot change the installed reload component.
find_library(ker_drain_vdev_bus NAMES rte_bus_vdev HINTS ${DPDK_LIBRARY_DIRS} NO_DEFAULT_PATH REQUIRED)
add_executable(ker-fstack-drain-source-test fstack-drain-source.c)
target_include_directories(ker-fstack-drain-source-test PRIVATE
    "${PROJECT_SOURCE_DIR}/tests/fstack-drain-compat"
    "${PROJECT_SOURCE_DIR}/third_party/fstack-reload"
    "${PROJECT_SOURCE_DIR}/third_party/fstack-ipc"
    "${PROJECT_SOURCE_DIR}/third_party/fstack-rss-table")
target_link_libraries(ker-fstack-drain-source-test PRIVATE
    ker::ipc "${KER_NET_RING_PMD}" "${ker_drain_vdev_bus}")
target_compile_options(ker-fstack-drain-source-test PRIVATE -Wall -Wextra -Werror)
target_link_options(ker-fstack-drain-source-test PRIVATE -Wl,--disable-new-dtags
    -Wl,--wrap=rte_eal_process_type -Wl,--wrap=rte_memzone_lookup -Wl,--wrap=rte_exit)
set_target_properties(ker-fstack-drain-source-test PROPERTIES BUILD_RPATH "${DPDK_LIBRARY_DIRS}")

add_test(NAME fstack-drain-queue-owner COMMAND ker-fstack-drain-source-test drain-owner)
add_test(NAME fstack-drain-queue-nonowner COMMAND ker-fstack-drain-source-test drain-nonowner)
add_test(NAME fstack-drain-peer-tx COMMAND ker-fstack-drain-source-test drain-peer)
add_test(NAME fstack-drain-foreign-epoch COMMAND ker-fstack-drain-source-test drain-foreign)
add_test(NAME fstack-drain-empty-qconf COMMAND ker-fstack-drain-source-test drain-empty)
add_test(NAME fstack-drain-full-visible COMMAND ker-fstack-drain-source-test drain-full-ring)
add_test(NAME fstack-drain-source-pair COMMAND ker-fstack-drain-source-test drain-pair)
add_test(NAME fstack-drain-rx15-orphans COMMAND ker-fstack-drain-source-test purge-orphans)
add_test(NAME fstack-directory-live-slot COMMAND ker-fstack-drain-source-test directory-live)
add_test(NAME fstack-directory-full COMMAND ker-fstack-drain-source-test directory-full)
add_test(NAME fstack-directory-missing COMMAND ker-fstack-drain-source-test directory-missing)
add_test(NAME fstack-directory-invalid COMMAND ker-fstack-drain-source-test directory-invalid)
add_test(NAME fstack-directory-success COMMAND ker-fstack-drain-source-test directory-success)
add_test(NAME fstack-directory-primary-busy COMMAND ker-fstack-drain-source-test directory-primary-busy)
add_test(NAME fstack-directory-slot-window COMMAND ker-fstack-drain-source-test slot-window)
add_test(NAME fstack-directory-slot-exhausted COMMAND ker-fstack-drain-source-test slot-exhausted)
set_tests_properties(fstack-drain-queue-owner fstack-drain-queue-nonowner fstack-drain-peer-tx
    fstack-drain-foreign-epoch fstack-drain-empty-qconf fstack-drain-full-visible
    fstack-drain-source-pair fstack-drain-rx15-orphans
    fstack-directory-live-slot fstack-directory-full fstack-directory-missing
    fstack-directory-invalid fstack-directory-success fstack-directory-primary-busy
    fstack-directory-slot-window fstack-directory-slot-exhausted PROPERTIES TIMEOUT 30 LABELS fstack)
add_test(NAME fstack-drain-import COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/fstack-drain-import.py")
set_tests_properties(fstack-drain-import PROPERTIES TIMEOUT 15 LABELS provenance)

set(ker_a14_include "${CMAKE_CURRENT_BINARY_DIR}/fstack-a14-source.inc")
add_custom_command(OUTPUT "${ker_a14_include}"
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/fstack-a14-source.py" "${ker_a14_include}"
    DEPENDS fstack-a14-source.py fstack-migration.json upstream/fstack/tests/integration/test_ff_gendir_mp_integration.c
    VERBATIM)
add_executable(ker-fstack-a14-multiprocess-test fstack-a14-multiprocess.c "${ker_a14_include}")
target_include_directories(ker-fstack-a14-multiprocess-test PRIVATE
    "${CMAKE_CURRENT_BINARY_DIR}" "${CMAKE_CURRENT_SOURCE_DIR}/fstack-drain-compat"
    "${PROJECT_SOURCE_DIR}/third_party/fstack-reload" "${PROJECT_SOURCE_DIR}/third_party/fstack-ipc"
    "${PROJECT_SOURCE_DIR}/third_party/fstack-rss-table")
target_link_libraries(ker-fstack-a14-multiprocess-test PRIVATE ker::ipc)
target_compile_options(ker-fstack-a14-multiprocess-test PRIVATE -Wall -Wextra -Werror -Wno-unused-parameter
    $<$<C_COMPILER_ID:GNU>:-Wno-format-truncation>)
target_link_options(ker-fstack-a14-multiprocess-test PRIVATE -Wl,--disable-new-dtags)
set_target_properties(ker-fstack-a14-multiprocess-test PROPERTIES BUILD_RPATH "${DPDK_LIBRARY_DIRS}")
list(GET DPDK_LIBRARY_DIRS 0 ker_a14_pmd_root)
add_test(NAME fstack-a14-original-multiprocess COMMAND "${Python3_EXECUTABLE}"
    "${CMAKE_CURRENT_SOURCE_DIR}/posix/fstack-a14.py" --app "$<TARGET_FILE:ker-fstack-a14-multiprocess-test>"
    --pmd-root "${ker_a14_pmd_root}")
set_tests_properties(fstack-a14-original-multiprocess PROPERTIES TIMEOUT 155 SKIP_RETURN_CODE 77 LABELS "fstack;dpdk")
