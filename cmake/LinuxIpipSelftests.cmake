if(BUILD_TESTING AND KER_BUILD_LINUX_PROTOCOL_SELFTESTS AND ker_native_ipip_selftests_profile)
    add_library(ker-linux-ipip-preload SHARED tests/posix/linux-mptcp-socket-proxy.c)
    target_include_directories(ker-linux-ipip-preload PRIVATE "${ao_headers}")
    target_compile_options(ker-linux-ipip-preload PRIVATE -Wall -Wextra -Werror)
    target_compile_definitions(ker-linux-ipip-preload PRIVATE
        KER_MPTCP_DIAG_PRELOAD=1 KER_NETWORK_SELFTEST=1 KER_MIXED_POLL_SELFTEST=1)
    target_link_libraries(ker-linux-ipip-preload PRIVATE ${CMAKE_DL_LIBS})
    foreach(wrap IN LISTS diag_wraps ITEMS select)
        target_compile_definitions(ker-linux-ipip-preload PRIVATE "__wrap_${wrap}=${wrap}")
    endforeach()
    add_executable(ker-linux-ipip-server tests/posix/linux-mptcp-socket-server.c)
    target_compile_definitions(ker-linux-ipip-server PRIVATE KER_NETWORK_SELFTEST=1 KER_IPIP_SELFTEST=1)
    target_include_directories(ker-linux-ipip-server PRIVATE "${ao_headers}")
    target_compile_options(ker-linux-ipip-server PRIVATE -Wall -Wextra -Werror)
    target_link_libraries(ker-linux-ipip-server PRIVATE Threads::Threads ${CMAKE_DL_LIBS})
    add_executable(ker-linux-mixed-poll-control tests/posix/linux-mixed-poll-control.c)
    target_compile_options(ker-linux-mixed-poll-control PRIVATE -Wall -Wextra -Werror)
    add_executable(ker-linux-mixed-poll-timeout-control tests/posix/mixed-poll-timeout-control.c)
    target_include_directories(ker-linux-mixed-poll-timeout-control PRIVATE "${PROJECT_SOURCE_DIR}/tests/posix")
    target_compile_options(ker-linux-mixed-poll-timeout-control PRIVATE -Wall -Wextra -Werror)
    add_test(NAME linux-mixed-poll-timeout-control COMMAND ker-linux-mixed-poll-timeout-control)
    set_tests_properties(linux-mixed-poll-timeout-control PROPERTIES LABELS "ipip-profile;adapter-control")
    add_dependencies(ker-linux-ipip-server ker-posix ker-io-worker ker-app
        ker-linux-ipip-preload ker-linux-mixed-poll-control ker-linux-mixed-poll-timeout-control)
    add_test(NAME linux-original-netfilter-conntrack-ipip-mtu
        COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/posix/linux-ipip-selftest.py"
            --server "$<TARGET_FILE:ker-linux-ipip-server>"
            --poll-control "$<TARGET_FILE:ker-linux-mixed-poll-control>"
            --preload "$<TARGET_FILE:ker-linux-ipip-preload>" --tools "${KER_MPTCP_DIAG_TOOLS_DIR}"
            --launcher "${PROJECT_SOURCE_DIR}/tools/ker-run.py" --library "$<TARGET_FILE:ker-posix>"
            --worker "$<TARGET_FILE:ker-io-worker>" --pmd-dir "${ker_session_pmd_dir}"
            --manifest "${ker_native_manifest}"
            --evidence "${PROJECT_BINARY_DIR}/linux-original-netfilter-conntrack-ipip-mtu.json")
    set_tests_properties(linux-original-netfilter-conntrack-ipip-mtu PROPERTIES TIMEOUT 240 RUN_SERIAL TRUE
        LABELS "linux-upstream;original-linux;protocol-selftest;dpdk;ipip-profile"
        ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")
endif()
