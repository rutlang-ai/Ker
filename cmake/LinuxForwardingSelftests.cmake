if(BUILD_TESTING AND KER_BUILD_LINUX_PROTOCOL_SELFTESTS AND ker_native_forwarding_profile)
    add_library(ker-linux-forwarding-preload SHARED tests/posix/linux-mptcp-socket-proxy.c)
    target_include_directories(ker-linux-forwarding-preload PRIVATE "${ao_headers}")
    target_compile_options(ker-linux-forwarding-preload PRIVATE -Wall -Wextra -Werror)
    target_compile_definitions(ker-linux-forwarding-preload PRIVATE KER_MPTCP_DIAG_PRELOAD=1 KER_FORWARDING_SELFTEST=1)
    target_link_libraries(ker-linux-forwarding-preload PRIVATE ${CMAKE_DL_LIBS})
    foreach(wrap IN LISTS diag_wraps)
        target_compile_definitions(ker-linux-forwarding-preload PRIVATE "__wrap_${wrap}=${wrap}")
    endforeach()
    add_library(ker-linux-broadcast-preload SHARED tests/posix/linux-mptcp-socket-proxy.c)
    target_include_directories(ker-linux-broadcast-preload PRIVATE "${ao_headers}")
    target_compile_options(ker-linux-broadcast-preload PRIVATE -Wall -Wextra -Werror)
    target_compile_definitions(ker-linux-broadcast-preload PRIVATE
        KER_MPTCP_DIAG_PRELOAD=1 KER_FORWARDING_SELFTEST=1 KER_BROADCAST_SELFTEST=1)
    target_link_libraries(ker-linux-broadcast-preload PRIVATE ${CMAKE_DL_LIBS})
    foreach(wrap IN LISTS diag_wraps)
        target_compile_definitions(ker-linux-broadcast-preload PRIVATE "__wrap_${wrap}=${wrap}")
    endforeach()
    target_compile_definitions(ker-linux-broadcast-preload PRIVATE __wrap_gettimeofday=gettimeofday)
    target_compile_definitions(ker-linux-network-server PRIVATE KER_BROADCAST_SELFTEST=1)
    add_executable(ker-broadcast-realtime-wrapper-test tests/posix/bridge-realtime-wrapper-test.c)
    target_compile_options(ker-broadcast-realtime-wrapper-test PRIVATE -Wall -Wextra -Werror)
    add_dependencies(ker-broadcast-realtime-wrapper-test ker-linux-broadcast-preload)
    add_dependencies(ker-linux-network-server ker-linux-broadcast-preload ker-broadcast-realtime-wrapper-test)
    add_test(NAME broadcast-realtime-wrapper-contract COMMAND ker-broadcast-realtime-wrapper-test)
    set_tests_properties(broadcast-realtime-wrapper-contract PROPERTIES
        ENVIRONMENT "LD_PRELOAD=$<TARGET_FILE:ker-linux-broadcast-preload>")
    add_test(NAME linux-original-forwarding-router-broadcast
        COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/posix/linux-forwarding-selftest.py"
            --program router_broadcast.sh --server "$<TARGET_FILE:ker-linux-network-server>"
            --preload "$<TARGET_FILE:ker-linux-broadcast-preload>" --tools "${KER_MPTCP_DIAG_TOOLS_DIR}"
            --launcher "${PROJECT_SOURCE_DIR}/tools/ker-run.py" --library "$<TARGET_FILE:ker-posix>"
            --worker "$<TARGET_FILE:ker-io-worker>" --pmd-dir "${ker_session_pmd_dir}"
            --manifest "${ker_native_manifest}"
            --evidence "${PROJECT_BINARY_DIR}/linux-original-forwarding-router-broadcast.json")
    set_tests_properties(linux-original-forwarding-router-broadcast PROPERTIES TIMEOUT 240 RUN_SERIAL TRUE
        LABELS "linux-upstream;original-linux;protocol-selftest;dpdk;forwarding"
        ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")
    foreach(program router_vid_1.sh min_max_mtu.sh)
        if(program STREQUAL "router_vid_1.sh")
            set(suffix router-vid1)
        else()
            set(suffix mtu)
        endif()
        add_test(NAME linux-original-forwarding-${suffix}
            COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/posix/linux-forwarding-selftest.py"
                --program "${program}" --server "$<TARGET_FILE:ker-linux-network-server>"
                --preload "$<TARGET_FILE:ker-linux-forwarding-preload>" --tools "${KER_MPTCP_DIAG_TOOLS_DIR}"
                --launcher "${PROJECT_SOURCE_DIR}/tools/ker-run.py" --library "$<TARGET_FILE:ker-posix>"
                --worker "$<TARGET_FILE:ker-io-worker>" --pmd-dir "${ker_session_pmd_dir}"
                --manifest "${ker_native_manifest}"
                --evidence "${PROJECT_BINARY_DIR}/linux-original-forwarding-${suffix}.json")
        set_tests_properties(linux-original-forwarding-${suffix} PROPERTIES TIMEOUT 240 RUN_SERIAL TRUE
            LABELS "linux-upstream;original-linux;protocol-selftest;dpdk;forwarding"
            ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")
    endforeach()
endif()
