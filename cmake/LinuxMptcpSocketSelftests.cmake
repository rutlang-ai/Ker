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
    target_link_options(ker-linux-mptcp-socket-control PRIVATE
        -Wl,--wrap=socket -Wl,--wrap=close -Wl,--wrap=__read_chk)
    target_link_libraries(ker-linux-mptcp-socket-control PRIVATE ${CMAKE_DL_LIBS})
    foreach(read_chk_mode static preload)
        add_executable(ker-linux-mptcp-read-chk-${read_chk_mode}-contract tests/posix/linux-mptcp-read-chk-contract.c)
        target_include_directories(ker-linux-mptcp-read-chk-${read_chk_mode}-contract PRIVATE "${ao_headers}")
        target_compile_options(ker-linux-mptcp-read-chk-${read_chk_mode}-contract PRIVATE -Wall -Wextra -Werror -UNDEBUG)
        target_link_libraries(ker-linux-mptcp-read-chk-${read_chk_mode}-contract PRIVATE Threads::Threads ${CMAKE_DL_LIBS})
        if(read_chk_mode STREQUAL preload)
            target_compile_definitions(ker-linux-mptcp-read-chk-${read_chk_mode}-contract PRIVATE
                KER_MPTCP_DIAG_PRELOAD=1 __wrap___read_chk=__read_chk)
        else()
            target_link_options(ker-linux-mptcp-read-chk-${read_chk_mode}-contract PRIVATE -Wl,--wrap=__read_chk)
        endif()
        add_test(NAME linux-mptcp-read-chk-${read_chk_mode}-contract
            COMMAND "$<TARGET_FILE:ker-linux-mptcp-read-chk-${read_chk_mode}-contract>")
        set_tests_properties(linux-mptcp-read-chk-${read_chk_mode}-contract PROPERTIES TIMEOUT 10
            LABELS "linux-upstream-control;mptcp")
    endforeach()
    add_test(NAME linux-mptcp-fixture-shutdown
        COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/posix/linux-mptcp-fixture-shutdown.py"
            --server "$<TARGET_FILE:ker-linux-mptcp-socket-server>"
            --launcher "${PROJECT_SOURCE_DIR}/tools/ker-run.py" --library "$<TARGET_FILE:ker-posix>"
            --worker "$<TARGET_FILE:ker-io-worker>" --pmd-dir "${ker_session_pmd_dir}"
            --manifest "${ker_native_manifest}"
            --evidence "${PROJECT_BINARY_DIR}/linux-mptcp-fixture-shutdown.json")
    set_tests_properties(linux-mptcp-fixture-shutdown PROPERTIES TIMEOUT 60 RUN_SERIAL TRUE
        LABELS "linux-upstream-control;runtime;dpdk" ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")
    foreach(program sockopt inq)
        add_executable(ker-linux-mptcp-${program} "${mptcp_root}/mptcp_${program}.c"
            $<TARGET_OBJECTS:ker-linux-mptcp-socket-proxy>)
        target_include_directories(ker-linux-mptcp-${program} PRIVATE "${ao_headers}" "${ker_native_source}/tools/include")
        target_compile_options(ker-linux-mptcp-${program} PRIVATE -Wno-error -UNDEBUG)
        target_link_libraries(ker-linux-mptcp-${program} PRIVATE ${CMAKE_DL_LIBS})
        foreach(wrap socket bind connect listen accept getsockname getpeername setsockopt getsockopt read __read_chk write ioctl recvmsg close)
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
        read __read_chk write ioctl recvmsg sendmsg recvfrom sendto recv send fcntl shutdown poll close open fopen if_nametoindex if_indextoname)
    add_executable(ker-linux-mptcp-diag-connect "${mptcp_root}/mptcp_connect.c"
        $<TARGET_OBJECTS:ker-linux-mptcp-socket-proxy>)
    target_include_directories(ker-linux-mptcp-diag-connect PRIVATE "${ao_headers}")
    target_compile_options(ker-linux-mptcp-diag-connect PRIVATE -O2 -Wno-error -UNDEBUG)
    target_link_libraries(ker-linux-mptcp-diag-connect PRIVATE ${CMAKE_DL_LIBS})
    target_link_options(ker-linux-mptcp-diag-connect PRIVATE -Wl,--wrap=sendfile)
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
    target_link_options(ker-linux-mptcp-sockopt-pm PRIVATE -Wl,--wrap=select)
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
    add_test(NAME linux-original-mptcp-simult-flows
        COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/posix/linux-mptcp-diag-selftest.py"
            --suite simult --server "$<TARGET_FILE:ker-linux-mptcp-socket-server>"
            --binary "$<TARGET_FILE:ker-linux-mptcp-diag-connect>" --sockopt "$<TARGET_FILE:ker-linux-mptcp-sockopt>"
            --inq "$<TARGET_FILE:ker-linux-mptcp-inq>" --pm "$<TARGET_FILE:ker-linux-mptcp-sockopt-pm>"
            --preload "$<TARGET_FILE:ker-linux-mptcp-diag-preload>" --tools "${KER_MPTCP_DIAG_TOOLS_DIR}"
            --launcher "${PROJECT_SOURCE_DIR}/tools/ker-run.py" --library "$<TARGET_FILE:ker-posix>"
            --worker "$<TARGET_FILE:ker-io-worker>" --pmd-dir "${ker_session_pmd_dir}" --manifest "${ker_native_manifest}"
            --evidence "${PROJECT_BINARY_DIR}/linux-original-mptcp-simult-flows.json")
    set_tests_properties(linux-original-mptcp-simult-flows PROPERTIES TIMEOUT 300
        LABELS "linux-upstream;original-linux;mptcp;protocol-selftest;dpdk" ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")
    add_test(NAME linux-original-mptcp-userspace-pm
        COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/posix/linux-mptcp-diag-selftest.py"
            --suite userspace --server "$<TARGET_FILE:ker-linux-mptcp-socket-server>"
            --binary "$<TARGET_FILE:ker-linux-mptcp-diag-connect>" --sockopt "$<TARGET_FILE:ker-linux-mptcp-sockopt>"
            --inq "$<TARGET_FILE:ker-linux-mptcp-inq>" --pm "$<TARGET_FILE:ker-linux-mptcp-sockopt-pm>"
            --preload "$<TARGET_FILE:ker-linux-mptcp-diag-preload>" --tools "${KER_MPTCP_DIAG_TOOLS_DIR}"
            --launcher "${PROJECT_SOURCE_DIR}/tools/ker-run.py" --library "$<TARGET_FILE:ker-posix>"
            --worker "$<TARGET_FILE:ker-io-worker>" --pmd-dir "${ker_session_pmd_dir}" --manifest "${ker_native_manifest}"
            --evidence "${PROJECT_BINARY_DIR}/linux-original-mptcp-userspace-pm.json")
    set_tests_properties(linux-original-mptcp-userspace-pm PROPERTIES TIMEOUT 300
        LABELS "linux-upstream;original-linux;mptcp;protocol-selftest;dpdk" ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")
    if(ker_native_mptcp_connect_profile)
        set(mptcp_shell_suites connect mmap sendfile checksum)
        if(ker_native_mptcp_join_profile)
            list(APPEND mptcp_shell_suites join)
        endif()
        foreach(suite IN LISTS mptcp_shell_suites)
            if(suite STREQUAL join)
                set(mptcp_shell_test linux-original-mptcp-join)
            else()
                set(mptcp_shell_test linux-original-mptcp-connect-${suite})
            endif()
            add_test(NAME ${mptcp_shell_test}
                COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/posix/linux-mptcp-diag-selftest.py"
                    --suite ${suite} --server "$<TARGET_FILE:ker-linux-mptcp-socket-server>"
                    --binary "$<TARGET_FILE:ker-linux-mptcp-diag-connect>" --sockopt "$<TARGET_FILE:ker-linux-mptcp-sockopt>"
                    --inq "$<TARGET_FILE:ker-linux-mptcp-inq>" --pm "$<TARGET_FILE:ker-linux-mptcp-sockopt-pm>"
                    --preload "$<TARGET_FILE:ker-linux-mptcp-diag-preload>" --tools "${KER_MPTCP_DIAG_TOOLS_DIR}"
                    --launcher "${PROJECT_SOURCE_DIR}/tools/ker-run.py" --library "$<TARGET_FILE:ker-posix>"
                    --worker "$<TARGET_FILE:ker-io-worker>" --pmd-dir "${ker_session_pmd_dir}" --manifest "${ker_native_manifest}"
                    --evidence "${PROJECT_BINARY_DIR}/${mptcp_shell_test}.json")
            set_tests_properties(${mptcp_shell_test} PROPERTIES TIMEOUT 3700
                RUN_SERIAL TRUE LABELS "linux-upstream;original-linux;mptcp;protocol-selftest;dpdk"
                ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")
        endforeach()
    endif()
endif()
