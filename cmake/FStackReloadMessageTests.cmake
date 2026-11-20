add_executable(ker-reload-message-test reload-message.c)
target_compile_options(ker-reload-message-test PRIVATE -Wall -Wextra -Werror)
target_link_libraries(ker-reload-message-test PRIVATE ker::reload)
target_link_options(ker-reload-message-test PRIVATE -Wl,--disable-new-dtags)
set_target_properties(ker-reload-message-test PROPERTIES BUILD_RPATH "${DPDK_LIBRARY_DIRS}")
add_test(NAME fstack-reload-message-serdes COMMAND ker-reload-message-test)
set_tests_properties(fstack-reload-message-serdes PROPERTIES TIMEOUT 30 LABELS fstack)
add_test(NAME fstack-reload-message-original-import
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/reload-import.py")
set_tests_properties(fstack-reload-message-original-import PROPERTIES
    TIMEOUT 30 LABELS "fstack;provenance")

# The retained source cases use the same private objects as ker::reload.
add_executable(ker-fstack-reload-source-test fstack-reload-case.c)
get_target_property(reload_symbols ker_reload_objects COMPILE_DEFINITIONS)
target_compile_definitions(ker-fstack-reload-source-test PRIVATE ${reload_symbols})
target_include_directories(ker-fstack-reload-source-test PRIVATE
    "${PROJECT_SOURCE_DIR}/third_party/fstack-ipc"
    "${PROJECT_SOURCE_DIR}/third_party/fstack-reload")
target_compile_options(ker-fstack-reload-source-test PRIVATE -Wall -Wextra -Werror)
target_link_libraries(ker-fstack-reload-source-test PRIVATE ker_reload_objects ker::ipc)
target_link_options(ker-fstack-reload-source-test PRIVATE -Wl,--disable-new-dtags)
set_target_properties(ker-fstack-reload-source-test PROPERTIES BUILD_RPATH "${DPDK_LIBRARY_DIRS}")

add_test(NAME fstack-reload-heartbeat
    COMMAND ker-fstack-reload-source-test test_ut_nr_22_heartbeat_and_rx_return)

add_test(NAME fstack-reload-rx-handover
    COMMAND ker-fstack-reload-source-test test_ut_nr_26_rx_handover_markers)

add_test(NAME fstack-reload-handover-barrier
    COMMAND ker-fstack-reload-source-test test_ut_nr_11_handover_barrier)

add_test(NAME fstack-reload-gendir-arbitration
    COMMAND ker-fstack-reload-source-test test_ut_nr_m5_gendir_arbitration)

add_test(NAME fstack-reload-probe-epoch-fallback
    COMMAND ker-fstack-reload-source-test test_ut_nr_m5_probe_epoch_fallback)

add_test(NAME fstack-reload-cross-master-handover
    COMMAND ker-fstack-reload-source-test test_ut_nr_m5_cross_master_handover_sequence)

add_test(NAME fstack-reload-hardware-user-proof
    COMMAND ker-fstack-reload-source-test test_p2_hw_user_proof)

add_test(NAME fstack-reload-reclaim-user-proof
    COMMAND ker-fstack-reload-source-test test_p2_reclaim_needs_user_proof)

add_test(NAME fstack-reload-release-user-proof
    COMMAND ker-fstack-reload-source-test test_p2_release_epoch_needs_proof)

add_test(NAME fstack-reload-orphan-epoch-liveness
    COMMAND ker-fstack-reload-source-test test_p2_orphan_workers_keep_epoch_live)

add_test(NAME fstack-reload-ring-user-census
    COMMAND ker-fstack-reload-source-test test_rx15_ring_user_census_and_purge_lock)

set_tests_properties(
    fstack-reload-heartbeat
    fstack-reload-rx-handover
    fstack-reload-handover-barrier
    fstack-reload-gendir-arbitration
    fstack-reload-probe-epoch-fallback
    fstack-reload-cross-master-handover
    fstack-reload-hardware-user-proof
    fstack-reload-reclaim-user-proof
    fstack-reload-release-user-proof
    fstack-reload-orphan-epoch-liveness
    fstack-reload-ring-user-census
    PROPERTIES TIMEOUT 30 LABELS fstack)
