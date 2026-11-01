# Included after the native POSIX targets are defined by NativeLinux.cmake.
if(BUILD_TESTING)
    add_executable(ker-tcp-request-revoke-abi-test
        "${PROJECT_SOURCE_DIR}/tests/posix/tcp-request-revoke-abi.c")
    target_include_directories(ker-tcp-request-revoke-abi-test PRIVATE
        "${PROJECT_SOURCE_DIR}/src/posix/lkl-overlay/arch/lkl/include/uapi")
    target_compile_features(ker-tcp-request-revoke-abi-test PRIVATE c_std_11)
    target_compile_options(ker-tcp-request-revoke-abi-test PRIVATE -Wall -Wextra -Werror)
    add_test(NAME tcp-request-revoke-private-abi
        COMMAND "$<TARGET_FILE:ker-tcp-request-revoke-abi-test>")
    set_tests_properties(tcp-request-revoke-private-abi PROPERTIES
        TIMEOUT 10 LABELS "native-tcp;private-abi")

    add_executable(ker-tcp-request-revoke-runtime-test
        "${PROJECT_SOURCE_DIR}/tests/posix/tcp-request-revoke-runtime.c")
    target_include_directories(ker-tcp-request-revoke-runtime-test PRIVATE
        "${PROJECT_SOURCE_DIR}/src/posix" "${PROJECT_SOURCE_DIR}/include")
    target_compile_features(ker-tcp-request-revoke-runtime-test PRIVATE c_std_11)
    target_compile_options(ker-tcp-request-revoke-runtime-test PRIVATE -Wall -Wextra -Werror)

    target_sources(ker-posix-member-census-test-runtime PRIVATE
        "${PROJECT_SOURCE_DIR}/src/posix/tcp-request-revoke.c")
    file(READ "${CMAKE_CURRENT_BINARY_DIR}/member-census-test-exports.map"
        ker_c14_test_export_map)
    string(REPLACE "ker_native_tcp_payload_snapshot_test_limit; local: *;"
        "ker_native_tcp_payload_snapshot_test_limit; ker_native_tcp_request_revoke; local: *;"
        ker_c14_test_export_map "${ker_c14_test_export_map}")
    file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/member-census-test-exports.map"
        "${ker_c14_test_export_map}")
    target_link_libraries(ker-tcp-request-revoke-runtime-test PRIVATE
        ker-posix-member-census-test-runtime)

    # C15's external TAP fixture drives the same preloaded LKL instance as the
    # application. Keep its test-only flow-map bootstrap/controller out of
    # the installed runtime and export only the fixture entry point.
    target_sources(ker-posix-member-census-test-runtime PRIVATE
        "${PROJECT_SOURCE_DIR}/tests/posix/c15-admission-test-runtime.c"
        "${PROJECT_SOURCE_DIR}/src/posix/ff-admission-channel.c")
    target_compile_definitions(ker-posix-member-census-test-runtime PRIVATE
        KER_C15_TEST_ACK_LOSS=1)
    target_include_directories(ker-posix-member-census-test-runtime PRIVATE
        "${PROJECT_SOURCE_DIR}/src/posix")
    file(READ "${CMAKE_CURRENT_BINARY_DIR}/member-census-test-exports.map"
        ker_c15_test_export_map)
    string(REPLACE "ker_native_tcp_request_revoke; local: *;"
        "ker_native_tcp_request_revoke; ker_c15_admission_test_run; local: *;"
        ker_c15_test_export_map "${ker_c15_test_export_map}")
    file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/member-census-test-exports.map"
        "${ker_c15_test_export_map}")

    add_executable(ker-c15-admission-tap-client
        "${PROJECT_SOURCE_DIR}/tests/posix/c15-admission-tap-client.c")
    target_compile_features(ker-c15-admission-tap-client PRIVATE c_std_11)
    target_compile_options(ker-c15-admission-tap-client PRIVATE -Wall -Wextra -Werror)
    target_link_libraries(ker-c15-admission-tap-client PRIVATE
        ker-posix-member-census-test-runtime)

    add_executable(ker-c15-admission-map-owner
        "${PROJECT_SOURCE_DIR}/tests/posix/c15-admission-map-owner.c"
        "${PROJECT_SOURCE_DIR}/src/posix/ff-admission-channel.c")
    target_include_directories(ker-c15-admission-map-owner PRIVATE
        "${PROJECT_SOURCE_DIR}/include" "${PROJECT_SOURCE_DIR}/src/compat"
        "${PROJECT_SOURCE_DIR}/src/posix"
        "${PROJECT_SOURCE_DIR}/third_party/fstack-reload"
        "${PROJECT_SOURCE_DIR}/third_party/fstack-ipc"
        "${PROJECT_SOURCE_DIR}/third_party/fstack-flow-map")
    target_include_directories(ker-c15-admission-map-owner SYSTEM PRIVATE ${DPDK_INCLUDE_DIRS})
    target_compile_features(ker-c15-admission-map-owner PRIVATE c_std_11)
    target_compile_options(ker-c15-admission-map-owner PRIVATE -Wall -Wextra -Werror)
    target_compile_definitions(ker-c15-admission-map-owner PRIVATE
        KER_C15_TEST_DELAY_PREPARED_REPLY=1)
    target_link_libraries(ker-c15-admission-map-owner PRIVATE
        ker::ipc PkgConfig::DPDK "${ker_controller_ring_pmd}" Threads::Threads)

    add_test(NAME native-c15-admission-tap-smoke
        COMMAND "${Python3_EXECUTABLE}"
            "${PROJECT_SOURCE_DIR}/tests/posix/c15-admission-tap-wire.py"
            --launcher "${PROJECT_SOURCE_DIR}/tools/ker-run.py"
            --library "$<TARGET_FILE:ker-posix-member-census-test-runtime>"
            --worker "$<TARGET_FILE:ker-io-worker>"
            --dpdk-plugin-dir "${ker_session_pmd_dir}"
            --client "$<TARGET_FILE:ker-c15-admission-tap-client>"
            --owner "$<TARGET_FILE:ker-c15-admission-map-owner>")
    set_tests_properties(native-c15-admission-tap-smoke PROPERTIES
        TIMEOUT 180 LABELS "native-tcp;admission;original-linux;tap;wire"
        ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")

    add_test(NAME native-c16-harness-wait-line-observer
        COMMAND "${Python3_EXECUTABLE}"
            "${PROJECT_SOURCE_DIR}/tests/posix/c16-broker-admission-wire.py"
            --wait-line-selftest)
    set_tests_properties(native-c16-harness-wait-line-observer PROPERTIES
        TIMEOUT 10 LABELS "native-tcp;admission;harness;observer"
        ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")

    # C16 separates the original-Linux broker process from the FF owner
    # process. The latter links the unchanged flow-map/reload sources and
    # talks to the broker through the opt-in owner capability.
    add_executable(ker-c16-admission-broker
        "${PROJECT_SOURCE_DIR}/tests/posix/c16-admission-broker.c")
    target_link_libraries(ker-c16-admission-broker PRIVATE ker::socket-broker-server)
    target_compile_features(ker-c16-admission-broker PRIVATE c_std_11)
    target_compile_options(ker-c16-admission-broker PRIVATE -Wall -Wextra -Werror)

    add_executable(ker-c16-admission-rpc-progress
        "${PROJECT_SOURCE_DIR}/tests/posix/c16-admission-rpc-progress.c")
    target_include_directories(ker-c16-admission-rpc-progress PRIVATE
        "${PROJECT_SOURCE_DIR}/src/posix")
    target_link_libraries(ker-c16-admission-rpc-progress PRIVATE ker::socket-client)
    target_compile_features(ker-c16-admission-rpc-progress PRIVATE c_std_11)
    target_compile_options(ker-c16-admission-rpc-progress PRIVATE -Wall -Wextra -Werror)

    if(TARGET ker-fstack-nginx-runtime)
        set(ker_c16_fstack_runtime_target ker-fstack-nginx-runtime)
    elseif(TARGET ker-c16-fstack-test-runtime)
        set(ker_c16_fstack_runtime_target ker-c16-fstack-test-runtime)
    endif()
    if(NOT ker_c16_fstack_runtime_target)
        message(FATAL_ERROR
            "C16 native admission tests require the FF runtime or its BUILD_TESTING-only target")
    endif()
    if(ker_c16_fstack_runtime_target)
        add_executable(ker-c16-admission-ff-app
            "${PROJECT_SOURCE_DIR}/tests/posix/c16-admission-ff-app.c"
            "${PROJECT_SOURCE_DIR}/src/compat/reload.c"
            "${PROJECT_SOURCE_DIR}/third_party/fstack-flow-map/ff_flow_map.c")
        target_include_directories(ker-c16-admission-ff-app PRIVATE
            "${PROJECT_SOURCE_DIR}/include" "${PROJECT_SOURCE_DIR}/src/posix"
            "${PROJECT_SOURCE_DIR}/src/compat"
            "${PROJECT_SOURCE_DIR}/third_party/fstack-address-policy"
            "${PROJECT_SOURCE_DIR}/third_party/fstack-reload"
            "${PROJECT_SOURCE_DIR}/third_party/fstack-ipc"
            "${PROJECT_SOURCE_DIR}/third_party/fstack-flow-map")
        target_include_directories(ker-c16-admission-ff-app SYSTEM PRIVATE ${DPDK_INCLUDE_DIRS})
        target_compile_features(ker-c16-admission-ff-app PRIVATE c_std_11)
        target_compile_options(ker-c16-admission-ff-app PRIVATE -Wall -Wextra -Werror)
        target_link_options(ker-c16-admission-ff-app PRIVATE -Wl,-E)
        target_link_libraries(ker-c16-admission-ff-app PRIVATE
            ker::ipc PkgConfig::DPDK "${ker_controller_ring_pmd}"
            ${ker_c16_fstack_runtime_target} ker-socket-preload Threads::Threads)

        add_test(NAME native-c16-broker-owner-admission-tap
            COMMAND "${Python3_EXECUTABLE}"
                "${PROJECT_SOURCE_DIR}/tests/posix/c16-broker-admission-wire.py"
                --launcher "${PROJECT_SOURCE_DIR}/tools/ker-run.py"
                --library "$<TARGET_FILE:ker-posix>"
                --worker "$<TARGET_FILE:ker-io-worker>"
                --dpdk-plugin-dir "${ker_session_pmd_dir}"
                --preload "$<TARGET_FILE:ker-socket-preload>"
                --broker "$<TARGET_FILE:ker-c16-admission-broker>"
                --client "$<TARGET_FILE:ker-c16-admission-ff-app>"
                --progress-client "$<TARGET_FILE:ker-c16-admission-rpc-progress>")
        set_tests_properties(native-c16-broker-owner-admission-tap PROPERTIES
            TIMEOUT 180 LABELS "native-tcp;admission;broker;original-linux;tap;wire"
            ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")

        add_test(NAME native-c16-finalized-timeout-quarantine
            COMMAND "${Python3_EXECUTABLE}"
                "${PROJECT_SOURCE_DIR}/tests/posix/c16-broker-admission-wire.py"
                --launcher "${PROJECT_SOURCE_DIR}/tools/ker-run.py"
                --library "$<TARGET_FILE:ker-posix>"
                --worker "$<TARGET_FILE:ker-io-worker>"
                --dpdk-plugin-dir "${ker_session_pmd_dir}"
                --preload "$<TARGET_FILE:ker-socket-preload>"
                --broker "$<TARGET_FILE:ker-c16-admission-broker>"
                --client "$<TARGET_FILE:ker-c16-admission-ff-app>"
                --progress-client "$<TARGET_FILE:ker-c16-admission-rpc-progress>"
                --finalized-timeout-only)
        set_tests_properties(native-c16-finalized-timeout-quarantine PROPERTIES
            TIMEOUT 90 LABELS "native-tcp;admission;broker;quarantine;negative"
            ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")

        add_test(NAME native-c16-cancel-unsent-timeout-quarantine
            COMMAND "${Python3_EXECUTABLE}"
                "${PROJECT_SOURCE_DIR}/tests/posix/c16-broker-admission-wire.py"
                --launcher "${PROJECT_SOURCE_DIR}/tools/ker-run.py"
                --library "$<TARGET_FILE:ker-posix>"
                --worker "$<TARGET_FILE:ker-io-worker>"
                --dpdk-plugin-dir "${ker_session_pmd_dir}"
                --preload "$<TARGET_FILE:ker-socket-preload>"
                --broker "$<TARGET_FILE:ker-c16-admission-broker>"
                --client "$<TARGET_FILE:ker-c16-admission-ff-app>"
                --progress-client "$<TARGET_FILE:ker-c16-admission-rpc-progress>"
                --cancel-unsent-timeout-only)
        set_tests_properties(native-c16-cancel-unsent-timeout-quarantine PROPERTIES
            TIMEOUT 90 LABELS "native-tcp;admission;broker;quarantine;negative"
            ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")

        add_test(NAME native-c16-owner-pump-failure
            COMMAND "${Python3_EXECUTABLE}"
                "${PROJECT_SOURCE_DIR}/tests/posix/c16-broker-admission-wire.py"
                --launcher "${PROJECT_SOURCE_DIR}/tools/ker-run.py"
                --library "$<TARGET_FILE:ker-posix>"
                --worker "$<TARGET_FILE:ker-io-worker>"
                --dpdk-plugin-dir "${ker_session_pmd_dir}"
                --preload "$<TARGET_FILE:ker-socket-preload>"
                --broker "$<TARGET_FILE:ker-c16-admission-broker>"
                --client "$<TARGET_FILE:ker-c16-admission-ff-app>"
                --progress-client "$<TARGET_FILE:ker-c16-admission-rpc-progress>"
                --pump-failure-only)
        set_tests_properties(native-c16-owner-pump-failure PROPERTIES
            TIMEOUT 90 LABELS "native-tcp;admission;broker;original-linux;owner-pump"
            ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")

        add_test(NAME native-c16-owner-auth-negative
            COMMAND "${Python3_EXECUTABLE}"
                "${PROJECT_SOURCE_DIR}/tests/posix/c16-broker-admission-wire.py"
                --launcher "${PROJECT_SOURCE_DIR}/tools/ker-run.py"
                --library "$<TARGET_FILE:ker-posix>"
                --worker "$<TARGET_FILE:ker-io-worker>"
                --dpdk-plugin-dir "${ker_session_pmd_dir}"
                --preload "$<TARGET_FILE:ker-socket-preload>"
                --broker "$<TARGET_FILE:ker-c16-admission-broker>"
                --client "$<TARGET_FILE:ker-c16-admission-ff-app>"
                --progress-client "$<TARGET_FILE:ker-c16-admission-rpc-progress>"
                --registration-negative-only)
        set_tests_properties(native-c16-owner-auth-negative PROPERTIES
            TIMEOUT 90 LABELS "native-tcp;admission;broker;owner-auth;negative"
            ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")

        add_test(NAME native-c16-owner-hello-fd-negative
            COMMAND "${Python3_EXECUTABLE}"
                "${PROJECT_SOURCE_DIR}/tests/posix/c16-broker-admission-wire.py"
                --launcher "${PROJECT_SOURCE_DIR}/tools/ker-run.py"
                --library "$<TARGET_FILE:ker-posix>"
                --worker "$<TARGET_FILE:ker-io-worker>"
                --dpdk-plugin-dir "${ker_session_pmd_dir}"
                --preload "$<TARGET_FILE:ker-socket-preload>"
                --broker "$<TARGET_FILE:ker-c16-admission-broker>"
                --client "$<TARGET_FILE:ker-c16-admission-ff-app>"
                --progress-client "$<TARGET_FILE:ker-c16-admission-rpc-progress>"
                --malformed-owner-hello-only)
        set_tests_properties(native-c16-owner-hello-fd-negative PROPERTIES
            TIMEOUT 90 LABELS "native-tcp;admission;broker;owner-auth;negative"
            ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")

        add_test(NAME native-c16-owner-death-cleanup
            COMMAND "${Python3_EXECUTABLE}"
                "${PROJECT_SOURCE_DIR}/tests/posix/c16-broker-admission-wire.py"
                --launcher "${PROJECT_SOURCE_DIR}/tools/ker-run.py"
                --library "$<TARGET_FILE:ker-posix>"
                --worker "$<TARGET_FILE:ker-io-worker>"
                --dpdk-plugin-dir "${ker_session_pmd_dir}"
                --preload "$<TARGET_FILE:ker-socket-preload>"
                --broker "$<TARGET_FILE:ker-c16-admission-broker>"
                --client "$<TARGET_FILE:ker-c16-admission-ff-app>"
                --progress-client "$<TARGET_FILE:ker-c16-admission-rpc-progress>"
                --owner-death-only)
        set_tests_properties(native-c16-owner-death-cleanup PROPERTIES
            TIMEOUT 90 LABELS "native-tcp;admission;broker;owner-lifecycle"
            ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")

        add_test(NAME native-c16-listener-close-cleanup
            COMMAND "${Python3_EXECUTABLE}"
                "${PROJECT_SOURCE_DIR}/tests/posix/c16-broker-admission-wire.py"
                --launcher "${PROJECT_SOURCE_DIR}/tools/ker-run.py"
                --library "$<TARGET_FILE:ker-posix>"
                --worker "$<TARGET_FILE:ker-io-worker>"
                --dpdk-plugin-dir "${ker_session_pmd_dir}"
                --preload "$<TARGET_FILE:ker-socket-preload>"
                --broker "$<TARGET_FILE:ker-c16-admission-broker>"
                --client "$<TARGET_FILE:ker-c16-admission-ff-app>"
                --progress-client "$<TARGET_FILE:ker-c16-admission-rpc-progress>"
                --listener-close-only)
        set_tests_properties(native-c16-listener-close-cleanup PROPERTIES
            TIMEOUT 90 LABELS "native-tcp;admission;broker;owner-lifecycle"
            ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")

        add_test(NAME native-c17-admission-window-cycles
            COMMAND "${Python3_EXECUTABLE}"
                "${PROJECT_SOURCE_DIR}/tests/posix/c16-broker-admission-wire.py"
                --launcher "${PROJECT_SOURCE_DIR}/tools/ker-run.py"
                --library "$<TARGET_FILE:ker-posix>"
                --worker "$<TARGET_FILE:ker-io-worker>"
                --dpdk-plugin-dir "${ker_session_pmd_dir}"
                --preload "$<TARGET_FILE:ker-socket-preload>"
                --broker "$<TARGET_FILE:ker-c16-admission-broker>"
                --client "$<TARGET_FILE:ker-c16-admission-ff-app>"
                --progress-client "$<TARGET_FILE:ker-c16-admission-rpc-progress>"
                --window-cycles-only)
        set_tests_properties(native-c17-admission-window-cycles PROPERTIES
            TIMEOUT 180 LABELS "native-tcp;admission;broker;original-linux;tap;window-cycles"
            ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")

        add_test(NAME native-c17-retire-pending-cancellation
            COMMAND "${Python3_EXECUTABLE}"
                "${PROJECT_SOURCE_DIR}/tests/posix/c16-broker-admission-wire.py"
                --launcher "${PROJECT_SOURCE_DIR}/tools/ker-run.py"
                --library "$<TARGET_FILE:ker-posix>"
                --worker "$<TARGET_FILE:ker-io-worker>"
                --dpdk-plugin-dir "${ker_session_pmd_dir}"
                --preload "$<TARGET_FILE:ker-socket-preload>"
                --broker "$<TARGET_FILE:ker-c16-admission-broker>"
                --client "$<TARGET_FILE:ker-c16-admission-ff-app>"
                --progress-client "$<TARGET_FILE:ker-c16-admission-rpc-progress>"
                --window-cancel-only)
        set_tests_properties(native-c17-retire-pending-cancellation PROPERTIES
            TIMEOUT 90 LABELS "native-tcp;admission;broker;original-linux;tap;retire-cancel"
            ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")

        add_test(NAME native-c16-explicit-stop-live-admission-listener
            COMMAND "${Python3_EXECUTABLE}"
                "${PROJECT_SOURCE_DIR}/tests/posix/c16-broker-admission-wire.py"
                --launcher "${PROJECT_SOURCE_DIR}/tools/ker-run.py"
                --library "$<TARGET_FILE:ker-posix>"
                --worker "$<TARGET_FILE:ker-io-worker>"
                --dpdk-plugin-dir "${ker_session_pmd_dir}"
                --preload "$<TARGET_FILE:ker-socket-preload>"
                --broker "$<TARGET_FILE:ker-c16-admission-broker>"
                --client "$<TARGET_FILE:ker-c16-admission-ff-app>"
                --progress-client "$<TARGET_FILE:ker-c16-admission-rpc-progress>"
                --explicit-stop-live-listener-only)
        set_tests_properties(native-c16-explicit-stop-live-admission-listener PROPERTIES
            TIMEOUT 90 LABELS "native-tcp;admission;broker;owner-lifecycle;shutdown"
            ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")
    endif()

    add_test(NAME native-tcp-request-revoke-wire
        COMMAND "${Python3_EXECUTABLE}"
            "${PROJECT_SOURCE_DIR}/tests/posix/tcp-request-revoke-wire.py"
            --launcher "${PROJECT_SOURCE_DIR}/tools/ker-run.py"
            --library "$<TARGET_FILE:ker-posix-member-census-test-runtime>"
            --worker "$<TARGET_FILE:ker-io-worker>"
            --dpdk-plugin-dir "${ker_session_pmd_dir}"
            --client "$<TARGET_FILE:ker-tcp-request-revoke-runtime-test>")
    set_tests_properties(native-tcp-request-revoke-wire PROPERTIES
        TIMEOUT 180 LABELS "native-tcp;request-revoke;original-linux"
        ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")
endif()
