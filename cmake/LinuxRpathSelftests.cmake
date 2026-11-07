if(BUILD_TESTING AND KER_BUILD_LINUX_PROTOCOL_SELFTESTS AND ker_native_rpath_selftests_profile)
    add_library(ker-linux-rpath-preload SHARED tests/posix/linux-mptcp-socket-proxy.c)
    target_include_directories(ker-linux-rpath-preload PRIVATE "${ao_headers}")
    target_compile_options(ker-linux-rpath-preload PRIVATE -Wall -Wextra -Werror)
    target_compile_definitions(ker-linux-rpath-preload PRIVATE KER_MPTCP_DIAG_PRELOAD=1 KER_SOCKET_FILTER_SELFTEST=1)
    target_link_libraries(ker-linux-rpath-preload PRIVATE ${CMAKE_DL_LIBS})
    foreach(wrap IN LISTS diag_wraps)
        target_compile_definitions(ker-linux-rpath-preload PRIVATE "__wrap_${wrap}=${wrap}")
    endforeach()
    add_executable(ker-linux-rpath-server tests/posix/linux-mptcp-socket-server.c)
    target_compile_definitions(ker-linux-rpath-server PRIVATE KER_NETWORK_SELFTEST=1 KER_SOCKET_FILTER_SELFTEST=1)
    target_include_directories(ker-linux-rpath-server PRIVATE "${ao_headers}")
    target_compile_options(ker-linux-rpath-server PRIVATE -Wall -Wextra -Werror)
    target_link_libraries(ker-linux-rpath-server PRIVATE Threads::Threads ${CMAKE_DL_LIBS})
    add_dependencies(ker-linux-rpath-server ker-posix ker-io-worker ker-app ker-linux-rpath-preload)
    add_test(NAME linux-original-netfilter-rpath
        COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/posix/linux-rpath-selftest.py"
            --server "$<TARGET_FILE:ker-linux-rpath-server>"
            --preload "$<TARGET_FILE:ker-linux-rpath-preload>" --tools "${KER_MPTCP_DIAG_TOOLS_DIR}"
            --launcher "${PROJECT_SOURCE_DIR}/tools/ker-run.py" --library "$<TARGET_FILE:ker-posix>"
            --worker "$<TARGET_FILE:ker-io-worker>" --pmd-dir "${ker_session_pmd_dir}"
            --manifest "${ker_native_manifest}"
            --evidence "${PROJECT_BINARY_DIR}/linux-original-netfilter-rpath.json")
    set_tests_properties(linux-original-netfilter-rpath PROPERTIES TIMEOUT 240 RUN_SERIAL TRUE
        LABELS "linux-upstream;original-linux;protocol-selftest;dpdk;rpath-profile"
        ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")
endif()
