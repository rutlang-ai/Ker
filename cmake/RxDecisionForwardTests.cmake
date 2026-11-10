if(NOT BUILD_TESTING)
    return()
endif()

add_executable(ker-io-worker-rx-metadata-test
    tests/posix/io-worker-rx-metadata.c
    src/posix/worker-exception.c
    src/posix/worker-exception-filter.c)
target_include_directories(ker-io-worker-rx-metadata-test PRIVATE
    "${PROJECT_SOURCE_DIR}/src/posix")
target_compile_features(ker-io-worker-rx-metadata-test PRIVATE c_std_11)
target_compile_options(ker-io-worker-rx-metadata-test PRIVATE
    -Wall -Wextra -Werror -ffunction-sections -fdata-sections)
target_link_options(ker-io-worker-rx-metadata-test PRIVATE
    -Wl,--gc-sections -Wl,--disable-new-dtags)
set_target_properties(ker-io-worker-rx-metadata-test PROPERTIES
    BUILD_RPATH "${DPDK_LIBRARY_DIRS}")
target_link_libraries(ker-io-worker-rx-metadata-test PRIVATE PkgConfig::DPDK)
add_test(NAME native-io-worker-rx-metadata-routing
    COMMAND "$<TARGET_FILE:ker-io-worker-rx-metadata-test>")
set_tests_properties(native-io-worker-rx-metadata-routing PROPERTIES
    TIMEOUT 5 LABELS "rx-decision;metadata;routing")

target_compile_definitions(ker-posix PRIVATE
    KER_C31_RX_DECISION_TESTING=1 KER_C31_FD_TABLE_TESTING=1)

# Consumer protocol cases that were added after the first C31 ABI commit.
foreach(case alive-uncertain dead-peer wrong-target wrong-worker-credential drop bad-action)
    add_test(NAME rx-decision-consumer-${case}
        COMMAND "$<TARGET_FILE:ker-rx-decision-consumer-test>" "${case}")
    set_tests_properties(rx-decision-consumer-${case} PROPERTIES
        LABELS "rx-decision;seqpacket;credentials;lifecycle" TIMEOUT 5)
endforeach()

add_executable(ker-rx-decision-forward-app tests/posix/rx-decision-forward-app.c)
target_include_directories(ker-rx-decision-forward-app PRIVATE
    "${PROJECT_SOURCE_DIR}/src/posix")
target_compile_features(ker-rx-decision-forward-app PRIVATE c_std_11)
target_compile_options(ker-rx-decision-forward-app PRIVATE -Wall -Wextra -Werror)
target_compile_definitions(ker-rx-decision-forward-app PRIVATE KER_C31_RX_DECISION_TESTING=1)
target_link_libraries(ker-rx-decision-forward-app PRIVATE ker-posix)

add_executable(ker-fd-table-shutdown-gate-test
    src/posix/fd-table.c tests/posix/fd-table-shutdown-gate.c)
target_include_directories(ker-fd-table-shutdown-gate-test PRIVATE
    "${PROJECT_SOURCE_DIR}/src/posix")
target_include_directories(ker-fd-table-shutdown-gate-test SYSTEM PRIVATE
    "${ker_native_source}/tools/lkl/include" "${ker_native_tools}/include")
target_compile_features(ker-fd-table-shutdown-gate-test PRIVATE c_std_11)
target_compile_definitions(ker-fd-table-shutdown-gate-test PRIVATE KER_C31_FD_TABLE_TESTING=1)
target_compile_options(ker-fd-table-shutdown-gate-test PRIVATE -Wall -Wextra -Werror)
target_link_libraries(ker-fd-table-shutdown-gate-test PRIVATE Threads::Threads)
add_test(NAME native-fd-table-shutdown-gate COMMAND "$<TARGET_FILE:ker-fd-table-shutdown-gate-test>")
set_tests_properties(native-fd-table-shutdown-gate PROPERTIES
    TIMEOUT 10 LABELS "posix;fd-table;shutdown;lifecycle")

# A separate, uninstalled worker binary contains the one-shot EAGAIN fault
# hook. The regular ker-io-worker has neither the hook nor its environment
# variable, including in BUILD_TESTING builds.
add_executable(ker-io-worker-rx-decision-test ${ker_io_worker_sources})
target_compile_features(ker-io-worker-rx-decision-test PRIVATE c_std_11)
target_compile_definitions(ker-io-worker-rx-decision-test PRIVATE KER_RX_DECISION_TESTING=1)
target_compile_options(ker-io-worker-rx-decision-test PRIVATE -Wall -Wextra -Werror)
target_link_libraries(ker-io-worker-rx-decision-test PRIVATE PkgConfig::DPDK ${CMAKE_DL_LIBS})
target_link_options(ker-io-worker-rx-decision-test PRIVATE -Wl,--disable-new-dtags)
set_target_properties(ker-io-worker-rx-decision-test PROPERTIES
    BUILD_RPATH "${DPDK_LIBRARY_DIRS}")

foreach(authority_case before-lease result-after-data)
    add_test(NAME rx-decision-producer-authority-${authority_case}
        COMMAND "$<TARGET_FILE:ker-io-worker-rx-decision-test>"
            --rx-decision-authority-test "${authority_case}")
    set_tests_properties(rx-decision-producer-authority-${authority_case} PROPERTIES
        TIMEOUT 5 LABELS "rx-decision;producer;authority;lifecycle")
endforeach()

list(GET DPDK_LIBRARY_DIRS 0 ker_rx_decision_dpdk_plugin_dir)
add_test(NAME native-rx-decision-forward-tap
    COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/posix/rx-decision-forward-tap.py"
        --launcher "${PROJECT_SOURCE_DIR}/tools/ker-run.py"
        --library "$<TARGET_FILE:ker-posix>"
        --worker "$<TARGET_FILE:ker-io-worker>"
        --test-worker "$<TARGET_FILE:ker-io-worker-rx-decision-test>"
        --app "$<TARGET_FILE:ker-rx-decision-forward-app>"
        --dpdk-plugin-dir "${ker_rx_decision_dpdk_plugin_dir}")
set_tests_properties(native-rx-decision-forward-tap PROPERTIES
    TIMEOUT 90 LABELS "native-tcp;rx-decision;dpdk-tap;original-linux")

add_test(NAME native-rx-decision-full-frame
    COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/posix/rx-decision-full-frame.py"
        --worker "$<TARGET_FILE:ker-io-worker-rx-decision-test>")
set_tests_properties(native-rx-decision-full-frame PROPERTIES
    TIMEOUT 30 LABELS "rx-decision;producer;mbuf;dpdk")

add_test(NAME native-rx-decision-producer-faults
    COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/posix/rx-decision-producer-faults.py"
        --worker "$<TARGET_FILE:ker-io-worker>"
        --dpdk-plugin-dir "${ker_rx_decision_dpdk_plugin_dir}")
set_tests_properties(native-rx-decision-producer-faults PROPERTIES
    TIMEOUT 90 LABELS "rx-decision;dpdk-tap;producer;fail-closed")

add_executable(ker-rx-decision-shutdown-retry-app
    tests/posix/rx-decision-shutdown-retry-app.c)
target_include_directories(ker-rx-decision-shutdown-retry-app PRIVATE
    "${PROJECT_SOURCE_DIR}/src/posix")
target_include_directories(ker-rx-decision-shutdown-retry-app SYSTEM PRIVATE
    "${ker_native_source}/include/uapi" "${ker_native_source}/include"
    "${ker_native_source}/arch/x86/include/uapi"
    "${ker_native_source}/arch/x86/include"
    "${ker_native_source}/tools/include")
target_compile_features(ker-rx-decision-shutdown-retry-app PRIVATE c_std_11)
target_compile_options(ker-rx-decision-shutdown-retry-app PRIVATE -Wall -Wextra -Werror)
target_compile_definitions(ker-rx-decision-shutdown-retry-app PRIVATE
    KER_C31_RX_DECISION_TESTING=1 __EXPORTED_HEADERS__)
target_link_libraries(ker-rx-decision-shutdown-retry-app PRIVATE ker-posix)
add_test(NAME native-rx-decision-shutdown-retry-tap
    COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/posix/rx-decision-shutdown-retry-tap.py"
        --launcher "${PROJECT_SOURCE_DIR}/tools/ker-run.py"
        --library "$<TARGET_FILE:ker-posix>"
        --worker "$<TARGET_FILE:ker-io-worker>"
        --app "$<TARGET_FILE:ker-rx-decision-shutdown-retry-app>"
        --dpdk-plugin-dir "${ker_rx_decision_dpdk_plugin_dir}")
set_tests_properties(native-rx-decision-shutdown-retry-tap PROPERTIES
    TIMEOUT 90 LABELS "native-tcp;rx-decision;dpdk-tap;original-linux;shutdown-retry")
foreach(blocking_mode IN ITEMS linger stdio)
    add_test(NAME native-rx-decision-blocking-${blocking_mode}-tap
        COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/posix/rx-decision-shutdown-retry-tap.py"
            --launcher "${PROJECT_SOURCE_DIR}/tools/ker-run.py"
            --library "$<TARGET_FILE:ker-posix>"
            --worker "$<TARGET_FILE:ker-io-worker>"
            --app "$<TARGET_FILE:ker-rx-decision-shutdown-retry-app>"
            --dpdk-plugin-dir "${ker_rx_decision_dpdk_plugin_dir}"
            --mode "${blocking_mode}")
    set_tests_properties(native-rx-decision-blocking-${blocking_mode}-tap PROPERTIES
        TIMEOUT 90 LABELS "native-tcp;rx-decision;dpdk-tap;original-linux;blocking-cleanup")
endforeach()
