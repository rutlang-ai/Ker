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
