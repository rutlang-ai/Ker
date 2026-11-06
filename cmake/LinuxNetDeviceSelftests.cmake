if(BUILD_TESTING AND KER_BUILD_LINUX_PROTOCOL_SELFTESTS AND ker_native_net_selftests_profile)
    add_library(ker-linux-net-device-proxy OBJECT tests/posix/linux-mptcp-socket-proxy.c)
    target_compile_definitions(ker-linux-net-device-proxy PRIVATE
        KER_NETWORK_SELFTEST=1 KER_NET_DEVICE_SELFTEST=1)
    target_include_directories(ker-linux-net-device-proxy PRIVATE "${ao_headers}")
    target_compile_options(ker-linux-net-device-proxy PRIVATE -Wall -Wextra -Werror)
    add_executable(ker-linux-net-device-server tests/posix/linux-mptcp-socket-server.c)
    target_compile_definitions(ker-linux-net-device-server PRIVATE
        KER_NETWORK_SELFTEST=1 KER_NET_DEVICE_SELFTEST=1)
    target_include_directories(ker-linux-net-device-server PRIVATE "${ao_headers}")
    target_compile_options(ker-linux-net-device-server PRIVATE -Wall -Wextra -Werror)
    target_link_libraries(ker-linux-net-device-server PRIVATE Threads::Threads ${CMAKE_DL_LIBS})
    add_dependencies(ker-linux-net-device-server ker-posix ker-io-worker ker-app)
    foreach(program tun reuseport_addr_any)
        add_executable(ker-linux-network-${program}
            "${ker_native_source}/tools/testing/selftests/net/${program}.c"
            $<TARGET_OBJECTS:ker-linux-net-device-proxy>)
        target_include_directories(ker-linux-network-${program} PRIVATE "${ao_headers}")
        target_compile_options(ker-linux-network-${program} PRIVATE -Wno-error -UNDEBUG)
        target_link_libraries(ker-linux-network-${program} PRIVATE Threads::Threads ${CMAKE_DL_LIBS})
        foreach(wrap socket bind connect listen accept getsockname getpeername setsockopt getsockopt
                read write ioctl recvmsg sendmsg recvfrom sendto recv send fcntl shutdown poll close
                open if_nametoindex epoll_create epoll_ctl epoll_wait)
            target_link_options(ker-linux-network-${program} PRIVATE "-Wl,--wrap=${wrap}")
        endforeach()
        add_dependencies(ker-linux-network-${program} ker-linux-net-device-server ker-linux-mptcp-socket-control)
        set(original ${program})
        if(program STREQUAL "reuseport_addr_any")
            set(original reuseport_addr_any.sh)
        endif()
        add_test(NAME linux-original-net-${program}
            COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/posix/linux-network-selftest.py"
                --program ${original} --binary "$<TARGET_FILE:ker-linux-network-${program}>"
                --server "$<TARGET_FILE:ker-linux-net-device-server>"
                --control "$<TARGET_FILE:ker-linux-mptcp-socket-control>"
                --launcher "${PROJECT_SOURCE_DIR}/tools/ker-run.py" --library "$<TARGET_FILE:ker-posix>"
                --worker "$<TARGET_FILE:ker-io-worker>" --pmd-dir "${ker_session_pmd_dir}"
                --manifest "${ker_native_manifest}"
                --evidence "${PROJECT_BINARY_DIR}/linux-original-net-${program}.json")
        set_tests_properties(linux-original-net-${program} PROPERTIES TIMEOUT 360 RUN_SERIAL TRUE
            LABELS "linux-upstream;original-linux;protocol-selftest;dpdk;net-profile"
            ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")
    endforeach()
endif()
