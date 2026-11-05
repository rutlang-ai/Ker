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
    target_link_libraries(ker-linux-mptcp-socket-control PRIVATE ${CMAKE_DL_LIBS})
    foreach(program sockopt inq)
        add_executable(ker-linux-mptcp-${program} "${mptcp_root}/mptcp_${program}.c"
            $<TARGET_OBJECTS:ker-linux-mptcp-socket-proxy>)
        target_include_directories(ker-linux-mptcp-${program} PRIVATE "${ao_headers}" "${ker_native_source}/tools/include")
        target_compile_options(ker-linux-mptcp-${program} PRIVATE -Wno-error -UNDEBUG)
        target_link_libraries(ker-linux-mptcp-${program} PRIVATE ${CMAKE_DL_LIBS})
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
    set(diag_wraps socket bind connect listen accept getsockname getpeername setsockopt getsockopt
        read write ioctl recvmsg sendmsg recvfrom sendto recv send fcntl shutdown poll close open fopen)
    add_executable(ker-linux-mptcp-diag-connect "${mptcp_root}/mptcp_connect.c"
        $<TARGET_OBJECTS:ker-linux-mptcp-socket-proxy>)
    target_include_directories(ker-linux-mptcp-diag-connect PRIVATE "${ao_headers}")
    target_compile_options(ker-linux-mptcp-diag-connect PRIVATE -Wno-error -UNDEBUG)
    target_link_libraries(ker-linux-mptcp-diag-connect PRIVATE ${CMAKE_DL_LIBS})
    add_library(ker-linux-mptcp-diag-preload SHARED tests/posix/linux-mptcp-socket-proxy.c)
    target_include_directories(ker-linux-mptcp-diag-preload PRIVATE "${ao_headers}")
    target_compile_options(ker-linux-mptcp-diag-preload PRIVATE -Wall -Wextra -Werror)
    target_compile_definitions(ker-linux-mptcp-diag-preload PRIVATE KER_MPTCP_DIAG_PRELOAD=1)
    target_link_libraries(ker-linux-mptcp-diag-preload PRIVATE ${CMAKE_DL_LIBS})
    foreach(wrap IN LISTS diag_wraps)
        target_link_options(ker-linux-mptcp-diag-connect PRIVATE "-Wl,--wrap=${wrap}")
        target_compile_definitions(ker-linux-mptcp-diag-preload PRIVATE "__wrap_${wrap}=${wrap}")
    endforeach()
    add_executable(ker-linux-mptcp-sockopt-pm "${mptcp_root}/pm_nl_ctl.c"
        $<TARGET_OBJECTS:ker-linux-mptcp-socket-proxy>)
    target_include_directories(ker-linux-mptcp-sockopt-pm PRIVATE "${ao_headers}")
    target_compile_options(ker-linux-mptcp-sockopt-pm PRIVATE -Wno-error -UNDEBUG)
    target_link_libraries(ker-linux-mptcp-sockopt-pm PRIVATE ${CMAKE_DL_LIBS})
    foreach(wrap IN LISTS diag_wraps)
        target_link_options(ker-linux-mptcp-sockopt-pm PRIVATE "-Wl,--wrap=${wrap}")
    endforeach()
    set(KER_MPTCP_DIAG_TOOLS_DIR "" CACHE PATH "Pinned iproute2 ss/nstat directory for original MPTCP diagnostics")
    add_test(NAME linux-original-mptcp-diag
        COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/posix/linux-mptcp-diag-selftest.py"
            --server "$<TARGET_FILE:ker-linux-mptcp-socket-server>" --binary "$<TARGET_FILE:ker-linux-mptcp-diag-connect>"
            --preload "$<TARGET_FILE:ker-linux-mptcp-diag-preload>" --tools "${KER_MPTCP_DIAG_TOOLS_DIR}"
            --launcher "${PROJECT_SOURCE_DIR}/tools/ker-run.py" --library "$<TARGET_FILE:ker-posix>"
            --worker "$<TARGET_FILE:ker-io-worker>" --pmd-dir "${ker_session_pmd_dir}" --manifest "${ker_native_manifest}"
            --evidence "${PROJECT_BINARY_DIR}/linux-original-mptcp-diag.json")
    set_tests_properties(linux-original-mptcp-diag PROPERTIES TIMEOUT 300
        LABELS "linux-upstream;original-linux;mptcp;protocol-selftest;dpdk" ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")
    if(ker_native_mptcp_sockopt_profile)
    add_test(NAME linux-original-mptcp-sockopt-shell
        COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/posix/linux-mptcp-diag-selftest.py"
            --suite sockopt --server "$<TARGET_FILE:ker-linux-mptcp-socket-server>"
            --binary "$<TARGET_FILE:ker-linux-mptcp-diag-connect>" --sockopt "$<TARGET_FILE:ker-linux-mptcp-sockopt>"
            --inq "$<TARGET_FILE:ker-linux-mptcp-inq>" --pm "$<TARGET_FILE:ker-linux-mptcp-sockopt-pm>"
            --preload "$<TARGET_FILE:ker-linux-mptcp-diag-preload>" --tools "${KER_MPTCP_DIAG_TOOLS_DIR}"
            --launcher "${PROJECT_SOURCE_DIR}/tools/ker-run.py" --library "$<TARGET_FILE:ker-posix>"
            --worker "$<TARGET_FILE:ker-io-worker>" --pmd-dir "${ker_session_pmd_dir}" --manifest "${ker_native_manifest}"
            --evidence "${PROJECT_BINARY_DIR}/linux-original-mptcp-sockopt-shell.json")
    set_tests_properties(linux-original-mptcp-sockopt-shell PROPERTIES TIMEOUT 300
        LABELS "linux-upstream;original-linux;mptcp;protocol-selftest;dpdk" ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")
    endif()
endif()
