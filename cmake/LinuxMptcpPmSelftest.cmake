if(BUILD_TESTING AND KER_BUILD_LINUX_PROTOCOL_SELFTESTS)
    set(pm_root "${ker_native_source}/tools/testing/selftests/net/mptcp")
    add_library(ker-linux-mptcp-pm-proxy OBJECT tests/posix/linux-mptcp-pm-proxy.c)
    target_compile_options(ker-linux-mptcp-pm-proxy PRIVATE -Wall -Wextra -Werror)
    add_executable(ker-linux-mptcp-pm-nl-ctl "${pm_root}/pm_nl_ctl.c"
        $<TARGET_OBJECTS:ker-linux-mptcp-pm-proxy>)
    target_include_directories(ker-linux-mptcp-pm-nl-ctl PRIVATE "${PROJECT_BINARY_DIR}/linux-selftest-uapi/include")
    target_compile_options(ker-linux-mptcp-pm-nl-ctl PRIVATE -Wno-error -UNDEBUG)
    foreach(wrap socket sendto recvfrom if_nametoindex if_indextoname close)
        target_link_options(ker-linux-mptcp-pm-nl-ctl PRIVATE "-Wl,--wrap=${wrap}")
    endforeach()
    add_executable(ker-linux-mptcp-pm-server tests/posix/linux-mptcp-pm-server.c)
    target_compile_options(ker-linux-mptcp-pm-server PRIVATE -Wall -Wextra -Werror)
    target_link_libraries(ker-linux-mptcp-pm-server PRIVATE ${CMAKE_DL_LIBS})
    add_dependencies(ker-linux-mptcp-pm-server ker-posix ker-io-worker ker-app)
    add_test(NAME linux-original-mptcp-pm-netlink
        COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/posix/linux-mptcp-pm-selftest.py"
            --server "$<TARGET_FILE:ker-linux-mptcp-pm-server>" --binary "$<TARGET_FILE:ker-linux-mptcp-pm-nl-ctl>"
            --launcher "${PROJECT_SOURCE_DIR}/tools/ker-run.py" --library "$<TARGET_FILE:ker-posix>"
            --worker "$<TARGET_FILE:ker-io-worker>" --pmd-dir "${ker_session_pmd_dir}"
            --manifest "${ker_native_manifest}" --evidence "${PROJECT_BINARY_DIR}/linux-original-mptcp-pm-netlink.json")
    set_tests_properties(linux-original-mptcp-pm-netlink PROPERTIES TIMEOUT 240
        LABELS "linux-upstream;original-linux;mptcp;protocol-selftest;dpdk"
        ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")
endif()
