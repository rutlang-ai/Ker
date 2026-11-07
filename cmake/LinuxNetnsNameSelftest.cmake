if(BUILD_TESTING AND KER_BUILD_LINUX_PROTOCOL_SELFTESTS AND ker_native_netns_name_profile)
    add_test(NAME linux-original-net-netns-name
        COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/posix/linux-netns-name-selftest.py"
            --server "$<TARGET_FILE:ker-linux-network-server>"
            --preload "$<TARGET_FILE:ker-linux-mptcp-diag-preload>" --tools "${KER_MPTCP_DIAG_TOOLS_DIR}"
            --launcher "${PROJECT_SOURCE_DIR}/tools/ker-run.py" --library "$<TARGET_FILE:ker-posix>"
            --worker "$<TARGET_FILE:ker-io-worker>" --pmd-dir "${ker_session_pmd_dir}"
            --manifest "${ker_native_manifest}"
            --evidence "${PROJECT_BINARY_DIR}/linux-original-net-netns-name.json")
    set_tests_properties(linux-original-net-netns-name PROPERTIES TIMEOUT 240 RUN_SERIAL TRUE
        LABELS "linux-upstream;original-linux;protocol-selftest;dpdk;netns-name-profile"
        ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")
endif()
