if(BUILD_TESTING AND KER_BUILD_LINUX_PROTOCOL_SELFTESTS AND ker_native_bridge_profile)
    add_library(ker-linux-bridge-preload SHARED tests/posix/linux-mptcp-socket-proxy.c)
    target_include_directories(ker-linux-bridge-preload PRIVATE "${ao_headers}")
    target_compile_options(ker-linux-bridge-preload PRIVATE -Wall -Wextra -Werror)
    target_compile_definitions(ker-linux-bridge-preload PRIVATE
        KER_MPTCP_DIAG_PRELOAD=1 KER_FORWARDING_SELFTEST=1 KER_BRIDGE_SELFTEST=1)
    target_link_libraries(ker-linux-bridge-preload PRIVATE ${CMAKE_DL_LIBS})
    foreach(wrap IN LISTS diag_wraps)
        target_compile_definitions(ker-linux-bridge-preload PRIVATE "__wrap_${wrap}=${wrap}")
    endforeach()
    target_compile_definitions(ker-linux-bridge-preload PRIVATE __wrap_gettimeofday=gettimeofday)
    target_compile_definitions(ker-linux-network-server PRIVATE KER_BRIDGE_SELFTEST=1)
    add_dependencies(ker-linux-network-server ker-linux-bridge-preload)
    add_executable(ker-bridge-realtime-wrapper-test tests/posix/bridge-realtime-wrapper-test.c)
    target_compile_options(ker-bridge-realtime-wrapper-test PRIVATE -Wall -Wextra -Werror)
    add_dependencies(ker-bridge-realtime-wrapper-test ker-linux-bridge-preload)
    add_dependencies(ker-linux-network-server ker-bridge-realtime-wrapper-test)
    add_test(NAME bridge-realtime-wrapper-contract COMMAND ker-bridge-realtime-wrapper-test)
    set_tests_properties(bridge-realtime-wrapper-contract PROPERTIES
        ENVIRONMENT "LD_PRELOAD=$<TARGET_FILE:ker-linux-bridge-preload>")
    foreach(program router_bridge router_bridge_vlan router_bridge_1d router_bridge_vlan_upper router_bridge_pvid_vlan_upper)
        string(REPLACE "_" "-" test_suffix "${program}")
        add_test(NAME linux-original-forwarding-${test_suffix}
            COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/posix/linux-bridge-selftest.py"
                --program "${program}.sh"
                --server "$<TARGET_FILE:ker-linux-network-server>"
                --preload "$<TARGET_FILE:ker-linux-bridge-preload>" --tools "${KER_MPTCP_DIAG_TOOLS_DIR}"
                --launcher "${PROJECT_SOURCE_DIR}/tools/ker-run.py" --library "$<TARGET_FILE:ker-posix>"
                --worker "$<TARGET_FILE:ker-io-worker>" --pmd-dir "${ker_session_pmd_dir}"
                --manifest "${ker_native_manifest}"
                --evidence "${PROJECT_BINARY_DIR}/linux-original-forwarding-${test_suffix}.json")
        set_tests_properties(linux-original-forwarding-${test_suffix} PROPERTIES TIMEOUT 240 RUN_SERIAL TRUE
            LABELS "linux-upstream;original-linux;protocol-selftest;dpdk;bridge-profile"
            ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")
    endforeach()
endif()
