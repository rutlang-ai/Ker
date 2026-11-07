if(BUILD_TESTING AND KER_BUILD_LINUX_PROTOCOL_SELFTESTS AND ker_native_conntrack_profile)
    pkg_check_modules(KER_SELFTEST_MNL REQUIRED IMPORTED_TARGET libmnl)
    add_executable(ker-linux-conntrack-dump-flush
        "${ker_native_source}/tools/testing/selftests/net/netfilter/conntrack_dump_flush.c")
    target_compile_options(ker-linux-conntrack-dump-flush PRIVATE -Wno-error -UNDEBUG)
    target_link_libraries(ker-linux-conntrack-dump-flush PRIVATE PkgConfig::KER_SELFTEST_MNL)
    add_dependencies(ker-linux-conntrack-dump-flush ker-linux-network-server ker-linux-mptcp-diag-preload
        ker-linux-mptcp-socket-control)
    add_test(NAME linux-original-netfilter-conntrack-dump-flush
        COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/posix/linux-network-selftest.py"
            --program conntrack_dump_flush
            --binary "$<TARGET_FILE:ker-linux-conntrack-dump-flush>"
            --control "$<TARGET_FILE:ker-linux-mptcp-socket-control>"
            --server "$<TARGET_FILE:ker-linux-network-server>"
            --preload "$<TARGET_FILE:ker-linux-mptcp-diag-preload>"
            --launcher "${PROJECT_SOURCE_DIR}/tools/ker-run.py" --library "$<TARGET_FILE:ker-posix>"
            --worker "$<TARGET_FILE:ker-io-worker>" --pmd-dir "${ker_session_pmd_dir}"
            --manifest "${ker_native_manifest}"
            --evidence "${PROJECT_BINARY_DIR}/linux-original-netfilter-conntrack-dump-flush.json")
    set_tests_properties(linux-original-netfilter-conntrack-dump-flush PROPERTIES TIMEOUT 240 RUN_SERIAL TRUE
        LABELS "linux-upstream;original-linux;protocol-selftest;dpdk;conntrack"
        ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")
endif()
