if(BUILD_TESTING AND KER_BUILD_LINUX_PROTOCOL_SELFTESTS AND ker_native_netlink_dumps_profile)
    add_library(ker-linux-netlink-dumps-proxy OBJECT tests/posix/linux-mptcp-socket-proxy.c)
    target_compile_definitions(ker-linux-netlink-dumps-proxy PRIVATE
        KER_NETWORK_SELFTEST=1 KER_NETLINK_DUMPS_SELFTEST=1)
    target_include_directories(ker-linux-netlink-dumps-proxy PRIVATE "${ao_headers}")
    target_compile_options(ker-linux-netlink-dumps-proxy PRIVATE -Wall -Wextra -Werror)
    add_executable(ker-linux-netlink-dumps-server tests/posix/linux-mptcp-socket-server.c)
    target_compile_definitions(ker-linux-netlink-dumps-server PRIVATE
        KER_NETWORK_SELFTEST=1 KER_NETLINK_DUMPS_SELFTEST=1)
    target_include_directories(ker-linux-netlink-dumps-server PRIVATE "${ao_headers}")
    target_compile_options(ker-linux-netlink-dumps-server PRIVATE -Wall -Wextra -Werror)
    target_link_libraries(ker-linux-netlink-dumps-server PRIVATE Threads::Threads ${CMAKE_DL_LIBS})
    add_dependencies(ker-linux-netlink-dumps-server ker-posix ker-io-worker ker-app)
    add_executable(ker-linux-network-netlink-dumps
        "${ker_native_source}/tools/testing/selftests/net/netlink-dumps.c"
        $<TARGET_OBJECTS:ker-linux-netlink-dumps-proxy>)
    target_compile_definitions(ker-linux-network-netlink-dumps PRIVATE syscall=ker_netlink_syscall)
    target_include_directories(ker-linux-network-netlink-dumps PRIVATE "${ao_headers}")
    target_compile_options(ker-linux-network-netlink-dumps PRIVATE -Wno-error -UNDEBUG)
    target_link_libraries(ker-linux-network-netlink-dumps PRIVATE Threads::Threads ${CMAKE_DL_LIBS})
    foreach(wrap socket bind connect listen accept getsockname getpeername setsockopt getsockopt
            read write ioctl recvmsg sendmsg recvfrom sendto recv send fcntl shutdown poll close open if_nametoindex)
        target_link_options(ker-linux-network-netlink-dumps PRIVATE "-Wl,--wrap=${wrap}")
    endforeach()
    add_dependencies(ker-linux-network-netlink-dumps ker-linux-netlink-dumps-server ker-linux-mptcp-socket-control)
    add_test(NAME linux-original-net-netlink-dumps
        COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/posix/linux-network-selftest.py"
            --program netlink-dumps --binary "$<TARGET_FILE:ker-linux-network-netlink-dumps>"
            --server "$<TARGET_FILE:ker-linux-netlink-dumps-server>"
            --control "$<TARGET_FILE:ker-linux-mptcp-socket-control>"
            --launcher "${PROJECT_SOURCE_DIR}/tools/ker-run.py" --library "$<TARGET_FILE:ker-posix>"
            --worker "$<TARGET_FILE:ker-io-worker>" --pmd-dir "${ker_session_pmd_dir}"
            --manifest "${ker_native_manifest}"
            --evidence "${PROJECT_BINARY_DIR}/linux-original-net-netlink-dumps.json")
    set_tests_properties(linux-original-net-netlink-dumps PROPERTIES TIMEOUT 360 RUN_SERIAL TRUE
        LABELS "linux-upstream;original-linux;protocol-selftest;dpdk;netlink-dumps-profile"
        ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")
endif()
