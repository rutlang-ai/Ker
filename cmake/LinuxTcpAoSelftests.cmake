if(BUILD_TESTING AND KER_BUILD_LINUX_PROTOCOL_SELFTESTS)
    # The shutdown trace exists only in this diagnostic selftest build; the
    # runtime still requires an explicit opt-in from the selected CTest.
    target_compile_definitions(ker-posix PRIVATE KER_TCP_AO_FINALIZE_DIAGNOSTIC=1)
    set(ao_root "${ker_native_source}/tools/testing/selftests/net/tcp_ao")
    # These are userspace headers for the host x86-64 ABI, generated from the
    # same pinned tree. LKL's prefixed internal headers are not a UAPI SDK.
    set(ao_headers "${PROJECT_BINARY_DIR}/linux-selftest-uapi/include")
    find_program(ao_make NAMES make gmake REQUIRED)
    execute_process(COMMAND "${ao_make}" -s -C "${ker_native_source}" ARCH=x86
        "O=${PROJECT_BINARY_DIR}/linux-selftest-uapi-build" headers_install
        "INSTALL_HDR_PATH=${PROJECT_BINARY_DIR}/linux-selftest-uapi"
        RESULT_VARIABLE ao_header_status OUTPUT_QUIET ERROR_VARIABLE ao_header_error)
    if(NOT ao_header_status EQUAL 0)
        message(FATAL_ERROR "Pinned selftest UAPI export failed: ${ao_header_error}")
    endif()
    add_library(ker-linux-tcp-ao-adapter OBJECT tests/posix/linux-tcp-ao-adapter.c)
    target_compile_options(ker-linux-tcp-ao-adapter PRIVATE -Wall -Wextra -Werror)
    set(ao_lib_sources)
    foreach(source ftrace ftrace-tcp kconfig netlink proc repair setup sock utils)
        list(APPEND ao_lib_sources "${ao_root}/lib/${source}.c")
    endforeach()
    # Upstream builds this shared support library once, without IPV6_TEST.
    add_library(ker-linux-tcp-ao-support STATIC ${ao_lib_sources})
    target_include_directories(ker-linux-tcp-ao-support PRIVATE "${ao_headers}" "${ker_native_source}/tools/include")
    target_compile_definitions(ker-linux-tcp-ao-support PRIVATE _GNU_SOURCE)
    target_compile_options(ker-linux-tcp-ao-support PRIVATE -Wno-error -UNDEBUG -fno-strict-aliasing)
    set(ao_programs bench-lookups connect connect-deny icmps-accept icmps-discard
        key-management restore rst self-connect seq-ext setsockopt-closed unsigned-md5)
    foreach(program IN LISTS ao_programs)
        foreach(family 4 6)
            set(target ker-linux-tcp-ao-${program}-ipv${family})
            set(ao_trace_args)
            if(program STREQUAL "rst" AND family EQUAL 6)
                list(APPEND ao_trace_args --finalize-trace)
            endif()
            add_executable(${target} "${ao_root}/${program}.c" $<TARGET_OBJECTS:ker-linux-tcp-ao-adapter>)
            target_include_directories(${target} PRIVATE "${ao_root}/lib" "${ao_headers}" "${ker_native_source}/tools/include")
            target_compile_definitions(${target} PRIVATE _GNU_SOURCE)
            target_compile_options(${target} PRIVATE -Wno-error -UNDEBUG -fno-strict-aliasing)
            if(family EQUAL 6)
                target_compile_definitions(${target} PRIVATE IPV6_TEST)
            endif()
            if(program STREQUAL "icmps-accept")
                target_compile_definitions(${target} PRIVATE TEST_ICMPS_ACCEPT)
            endif()
            foreach(wrap unshare setns open fopen access mkdtemp rmdir mount umount socket send setsockopt pthread_create exit test_add_destructor recv sendto accept bind connect listen close getsockopt select poll)
                target_link_options(${target} PRIVATE "-Wl,--wrap=${wrap}")
            endforeach()
            target_link_libraries(${target} PRIVATE ker-linux-tcp-ao-support Threads::Threads ${CMAKE_DL_LIBS} m)
            add_dependencies(${target} ker-app ker-posix ker-io-worker)
            add_test(NAME linux-original-tcp-ao-${program}-ipv${family}
                COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/posix/linux-tcp-ao-selftest.py"
                    --binary "$<TARGET_FILE:${target}>" --source "${ao_root}/${program}.c"
                    --launcher "${PROJECT_SOURCE_DIR}/tools/ker-run.py" --library "$<TARGET_FILE:ker-posix>"
                    --worker "$<TARGET_FILE:ker-io-worker>" --pmd-dir "${ker_session_pmd_dir}"
                    --manifest "${ker_native_manifest}" --family ${family}
                    ${ao_trace_args}
                    --evidence "${PROJECT_BINARY_DIR}/linux-original-tcp-ao-${program}-ipv${family}.json")
            set_tests_properties(linux-original-tcp-ao-${program}-ipv${family} PROPERTIES TIMEOUT 900
                LABELS "linux-upstream;original-linux;tcp-ao;protocol-selftest;dpdk"
                ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")
        endforeach()
    endforeach()
endif()
