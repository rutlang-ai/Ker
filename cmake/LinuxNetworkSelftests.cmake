if(BUILD_TESTING AND KER_BUILD_LINUX_PROTOCOL_SELFTESTS)
    foreach(program reuseaddr_conflict sk_bind_sendto_listen bind_timewait bind_wildcard)
        add_executable(ker-linux-network-${program}
            "${ker_native_source}/tools/testing/selftests/net/${program}.c"
            $<TARGET_OBJECTS:ker-linux-mptcp-socket-proxy>)
        target_include_directories(ker-linux-network-${program} PRIVATE "${ao_headers}")
        target_compile_options(ker-linux-network-${program} PRIVATE -Wno-error -UNDEBUG)
        target_link_libraries(ker-linux-network-${program} PRIVATE Threads::Threads ${CMAKE_DL_LIBS})
        foreach(wrap socket bind connect listen accept getsockname getpeername setsockopt getsockopt
                read write ioctl recvmsg sendmsg recvfrom sendto recv send fcntl shutdown poll close)
            target_link_options(ker-linux-network-${program} PRIVATE "-Wl,--wrap=${wrap}")
        endforeach()
        add_dependencies(ker-linux-network-${program} ker-linux-mptcp-socket-server ker-linux-mptcp-socket-control)
        add_test(NAME linux-original-net-${program}
            COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/posix/linux-network-selftest.py"
                --program ${program} --binary "$<TARGET_FILE:ker-linux-network-${program}>"
                --server "$<TARGET_FILE:ker-linux-mptcp-socket-server>"
                --control "$<TARGET_FILE:ker-linux-mptcp-socket-control>"
                --launcher "${PROJECT_SOURCE_DIR}/tools/ker-run.py" --library "$<TARGET_FILE:ker-posix>"
                --worker "$<TARGET_FILE:ker-io-worker>" --pmd-dir "${ker_session_pmd_dir}"
                --manifest "${ker_native_manifest}"
                --evidence "${PROJECT_BINARY_DIR}/linux-original-net-${program}.json")
        set_tests_properties(linux-original-net-${program} PROPERTIES TIMEOUT 360 RUN_SERIAL TRUE
            LABELS "linux-upstream;original-linux;protocol-selftest;dpdk"
            ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")
    endforeach()
endif()
