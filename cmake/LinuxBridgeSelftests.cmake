if(BUILD_TESTING AND KER_BUILD_LINUX_PROTOCOL_SELFTESTS AND ker_native_bridge_profile)
    add_library(ker-linux-bridge-preload SHARED tests/posix/linux-mptcp-socket-proxy.c)
    target_include_directories(ker-linux-bridge-preload PRIVATE "${ao_headers}")
    target_compile_options(ker-linux-bridge-preload PRIVATE -Wall -Wextra -Werror)
    target_compile_definitions(ker-linux-bridge-preload PRIVATE
        KER_MPTCP_DIAG_PRELOAD=1 KER_FORWARDING_SELFTEST=1 KER_BRIDGE_SELFTEST=1
        KER_MIXED_POLL_SELFTEST=1)
    target_link_libraries(ker-linux-bridge-preload PRIVATE ${CMAKE_DL_LIBS})
    foreach(wrap IN LISTS diag_wraps ITEMS select)
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
    add_executable(ker-linux-bridge-filter-control tests/posix/linux-bridge-filter-control.c)
    target_compile_options(ker-linux-bridge-filter-control PRIVATE -Wall -Wextra -Werror)
    target_link_libraries(ker-linux-bridge-filter-control PRIVATE ${CMAKE_DL_LIBS})
    add_dependencies(ker-linux-network-server ker-linux-bridge-filter-control)
    add_library(ker-linux-bridge-packet-preload SHARED tests/posix/linux-mptcp-socket-proxy.c)
    target_include_directories(ker-linux-bridge-packet-preload PRIVATE "${ao_headers}")
    target_compile_options(ker-linux-bridge-packet-preload PRIVATE -Wall -Wextra -Werror)
    target_compile_definitions(ker-linux-bridge-packet-preload PRIVATE
        KER_MPTCP_DIAG_PRELOAD=1 KER_FORWARDING_SELFTEST=1 KER_BRIDGE_PACKET_SELFTEST=1
        KER_BRIDGE_SELFTEST=1 __wrap_gettimeofday=gettimeofday)
    target_link_libraries(ker-linux-bridge-packet-preload PRIVATE ${CMAKE_DL_LIBS})
    foreach(wrap IN LISTS diag_wraps)
        target_compile_definitions(ker-linux-bridge-packet-preload PRIVATE "__wrap_${wrap}=${wrap}")
    endforeach()
    add_dependencies(ker-bridge-realtime-wrapper-test ker-linux-bridge-packet-preload)
    add_test(NAME bridge-packet-realtime-wrapper-contract COMMAND ker-bridge-realtime-wrapper-test)
    set_tests_properties(bridge-packet-realtime-wrapper-contract PROPERTIES
        ENVIRONMENT "LD_PRELOAD=$<TARGET_FILE:ker-linux-bridge-packet-preload>")
    add_test(NAME linux-pedit-ip-contract-unit
        COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/posix/test_linux_pedit_ip_contract.py")
    set_tests_properties(linux-pedit-ip-contract-unit PROPERTIES
        LABELS "bridge-profile;protocol-selftest"
        ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")
    target_compile_definitions(ker-linux-network-server PRIVATE KER_BRIDGE_PACKET_SELFTEST=1)
    add_dependencies(ker-linux-network-server ker-linux-bridge-packet-preload)
    # The unchanged traceroute6 multiplexes several native UDP descriptors.
    # Reuse the existing host/native poll/select adapter and exercise it in
    # the same resident fixture before running the original IPv6 entry.
    add_executable(ker-linux-forwarding-instats-poll-control tests/posix/linux-mixed-poll-control.c)
    target_compile_definitions(ker-linux-forwarding-instats-poll-control PRIVATE KER_MIXED_CONTROL_IPV6=1)
    target_compile_options(ker-linux-forwarding-instats-poll-control PRIVATE -Wall -Wextra -Werror)
    add_dependencies(ker-linux-network-server ker-linux-forwarding-instats-poll-control)
    foreach(program router_bridge router_bridge_vlan router_bridge_1d router_bridge_vlan_upper
            router_bridge_pvid_vlan_upper router_bridge_vlan_upper_pvid bridge_mdb_host bridge_sticky_fdb bridge_fdb_learning_limit bridge_mdb_port_down bridge_port_isolation bridge_vlan_unaware bridge_vlan_aware bridge_locked_port bridge_vlan_mcast ip6_forward_instats_vrf bridge_igmp bridge_mld bridge_mdb bridge_mdb_max pedit_ip pedit_l4port pedit_dsfield tc_flower_port_range tc_flower_l2_miss tc_flower_cfm)
        if(program STREQUAL "bridge_sticky_fdb" OR program STREQUAL "bridge_mdb_port_down" OR program STREQUAL "bridge_port_isolation" OR program STREQUAL "bridge_vlan_unaware" OR program STREQUAL "bridge_vlan_aware" OR program STREQUAL "bridge_locked_port" OR program STREQUAL "bridge_vlan_mcast" OR program STREQUAL "bridge_igmp" OR program STREQUAL "bridge_mld" OR program STREQUAL "bridge_mdb" OR program STREQUAL "bridge_mdb_max" OR program STREQUAL "pedit_ip" OR program STREQUAL "pedit_l4port" OR program STREQUAL "pedit_dsfield" OR program STREQUAL "tc_flower_port_range" OR program STREQUAL "tc_flower_l2_miss" OR program STREQUAL "tc_flower_cfm")
            set(bridge_selftest_preload ker-linux-bridge-packet-preload)
        else()
            set(bridge_selftest_preload ker-linux-bridge-preload)
        endif()
        set(forwarding_selftest_extra)
        set(forwarding_selftest_runner "${PROJECT_SOURCE_DIR}/tests/posix/linux-bridge-selftest.py")
        if(program STREQUAL "bridge_locked_port")
            list(APPEND forwarding_selftest_extra --filter-control "$<TARGET_FILE:ker-linux-bridge-filter-control>")
        endif()
        if(program STREQUAL "ip6_forward_instats_vrf")
            set(forwarding_selftest_runner "${PROJECT_SOURCE_DIR}/tests/posix/linux-forwarding-selftest.py")
            set(forwarding_selftest_extra --poll-control "$<TARGET_FILE:ker-linux-forwarding-instats-poll-control>")
        elseif(program STREQUAL "pedit_ip" OR program STREQUAL "pedit_l4port" OR program STREQUAL "pedit_dsfield")
            set(forwarding_selftest_extra --packet-observer "${PROJECT_SOURCE_DIR}/tests/posix/linux-pedit-packet-observer.py")
        endif()
        string(REPLACE "_" "-" test_suffix "${program}")
        add_test(NAME linux-original-forwarding-${test_suffix}
            COMMAND "${Python3_EXECUTABLE}" "${forwarding_selftest_runner}"
                --program "${program}.sh" ${forwarding_selftest_extra}
                --server "$<TARGET_FILE:ker-linux-network-server>"
                --preload "$<TARGET_FILE:${bridge_selftest_preload}>" --tools "${KER_MPTCP_DIAG_TOOLS_DIR}"
                --launcher "${PROJECT_SOURCE_DIR}/tools/ker-run.py" --library "$<TARGET_FILE:ker-posix>"
                --worker "$<TARGET_FILE:ker-io-worker>" --pmd-dir "${ker_session_pmd_dir}"
                --manifest "${ker_native_manifest}"
                --evidence "${PROJECT_BINARY_DIR}/linux-original-forwarding-${test_suffix}.json")
        set(original_entry_budget 240)
        if(program STREQUAL "bridge_igmp" OR program STREQUAL "bridge_mld" OR program STREQUAL "bridge_mdb" OR program STREQUAL "bridge_mdb_max" OR program STREQUAL "pedit_ip" OR program STREQUAL "pedit_l4port" OR program STREQUAL "pedit_dsfield" OR program STREQUAL "tc_flower_port_range" OR program STREQUAL "tc_flower_l2_miss" OR program STREQUAL "tc_flower_cfm")
            set(original_entry_budget 900)
        endif()
        set_tests_properties(linux-original-forwarding-${test_suffix} PROPERTIES TIMEOUT ${original_entry_budget} RUN_SERIAL TRUE
            LABELS "linux-upstream;original-linux;protocol-selftest;dpdk;bridge-profile"
            ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")
    endforeach()
endif()
