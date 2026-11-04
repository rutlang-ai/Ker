option(KER_BUILD_LINUX_PROTOCOL_SELFTESTS "Run unchanged pinned Linux protocol selftests on the imported kernel" OFF)
if(BUILD_TESTING AND KER_BUILD_LINUX_PROTOCOL_SELFTESTS)
    function(ker_add_linux_protocol_selftest case_name source_name)
        set(source "${ker_native_source}/tools/testing/selftests/net/${source_name}.c")
        if(NOT TARGET ker-linux-selftest-${source_name})
            add_executable(ker-linux-selftest-${source_name} "${source}")
            target_link_libraries(ker-linux-selftest-${source_name} PRIVATE Threads::Threads)
            # Preserve upstream test sources; do not impose Ker's -Werror on them.
            target_compile_options(ker-linux-selftest-${source_name} PRIVATE -Wno-error)
        endif()
        set(arguments)
        foreach(argument IN LISTS ARGN)
            list(APPEND arguments "--case-arg=${argument}")
        endforeach()
        set(command "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/posix/linux-original-selftest.py"
                --launcher "${PROJECT_SOURCE_DIR}/tools/ker-run.py"
                --library "$<TARGET_FILE:ker-posix>" --worker "$<TARGET_FILE:ker-io-worker>"
                --binary "$<TARGET_FILE:ker-linux-selftest-${source_name}>" --source "${source}"
                --pmd-dir "${ker_session_pmd_dir}" --manifest "${ker_native_manifest}" ${arguments})
        add_test(NAME linux-original-${case_name} COMMAND ${command}
            --evidence "${PROJECT_BINARY_DIR}/linux-original-${case_name}.json")
        if(case_name STREQUAL "sk-connect-zero-addr")
            # A host pass with an idle imported kernel cannot count as kernel coverage.
            add_test(NAME linux-original-reject-host-only COMMAND ${command}
                --host-control --evidence "${PROJECT_BINARY_DIR}/linux-original-host-only-control.json")
            set_tests_properties(linux-original-reject-host-only PROPERTIES TIMEOUT 100
                LABELS "linux-upstream-control;provenance" ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")
        endif()
        set_tests_properties(linux-original-${case_name} PROPERTIES
            TIMEOUT 100 LABELS "linux-upstream;protocol-selftest;original-linux"
            ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")
    endfunction()
    ker_add_linux_protocol_selftest(sk-connect-zero-addr sk_connect_zero_addr)
    ker_add_linux_protocol_selftest(tcp-inq-ipv4 tcp_inq -4)
    ker_add_linux_protocol_selftest(tcp-inq-ipv6 tcp_inq -6)
endif()
