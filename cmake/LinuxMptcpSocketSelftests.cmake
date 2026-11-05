if(BUILD_TESTING AND KER_BUILD_LINUX_PROTOCOL_SELFTESTS)
    set(mptcp_root "${ker_native_source}/tools/testing/selftests/net/mptcp")
    add_library(ker-linux-mptcp-socket-proxy OBJECT tests/posix/linux-mptcp-socket-proxy.c)
    target_include_directories(ker-linux-mptcp-socket-proxy PRIVATE "${ao_headers}")
    target_compile_options(ker-linux-mptcp-socket-proxy PRIVATE -Wall -Wextra -Werror)
    add_executable(ker-linux-mptcp-socket-server tests/posix/linux-mptcp-socket-server.c)
    target_include_directories(ker-linux-mptcp-socket-server PRIVATE "${ao_headers}")
    target_compile_options(ker-linux-mptcp-socket-server PRIVATE -Wall -Wextra -Werror)
    target_link_libraries(ker-linux-mptcp-socket-server PRIVATE Threads::Threads ${CMAKE_DL_LIBS})
    add_dependencies(ker-linux-mptcp-socket-server ker-posix ker-io-worker ker-app)
    add_executable(ker-linux-mptcp-socket-control tests/posix/linux-mptcp-socket-control.c
        $<TARGET_OBJECTS:ker-linux-mptcp-socket-proxy>)
    target_link_options(ker-linux-mptcp-socket-control PRIVATE -Wl,--wrap=socket -Wl,--wrap=close)
    foreach(program sockopt inq)
        add_executable(ker-linux-mptcp-${program} "${mptcp_root}/mptcp_${program}.c"
            $<TARGET_OBJECTS:ker-linux-mptcp-socket-proxy>)
        target_include_directories(ker-linux-mptcp-${program} PRIVATE "${ao_headers}" "${ker_native_source}/tools/include")
        target_compile_options(ker-linux-mptcp-${program} PRIVATE -Wno-error -UNDEBUG)
        foreach(wrap socket bind connect listen accept getsockname getpeername setsockopt getsockopt read write ioctl recvmsg close)
            target_link_options(ker-linux-mptcp-${program} PRIVATE "-Wl,--wrap=${wrap}")
        endforeach()
        foreach(family 4 6)
            add_test(NAME linux-original-mptcp-${program}-ipv${family}
                COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/posix/linux-mptcp-socket-selftest.py"
                    --server "$<TARGET_FILE:ker-linux-mptcp-socket-server>" --binary "$<TARGET_FILE:ker-linux-mptcp-${program}>"
                    --control "$<TARGET_FILE:ker-linux-mptcp-socket-control>"
                    --program ${program} --family ${family}
                    --launcher "${PROJECT_SOURCE_DIR}/tools/ker-run.py" --library "$<TARGET_FILE:ker-posix>"
                    --worker "$<TARGET_FILE:ker-io-worker>" --pmd-dir "${ker_session_pmd_dir}"
                    --manifest "${ker_native_manifest}"
                    --evidence "${PROJECT_BINARY_DIR}/linux-original-mptcp-${program}-ipv${family}.json")
            set_tests_properties(linux-original-mptcp-${program}-ipv${family} PROPERTIES TIMEOUT 180
                LABELS "linux-upstream;original-linux;mptcp;protocol-selftest;dpdk" ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")
        endforeach()
    endforeach()
endif()
