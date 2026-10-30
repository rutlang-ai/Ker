add_executable(ker-checksum-test checksum.c)
target_link_libraries(ker-checksum-test PRIVATE ker::ker ker_port_headers ker_linux_port)
add_test(NAME checksum COMMAND ker-checksum-test)

add_executable(ker-timer-test timer.c)
target_link_libraries(ker-timer-test PRIVATE ker_port_headers ker_linux_port)
add_test(NAME timer COMMAND ker-timer-test)

add_executable(ker-refcount-test refcount.c)
target_link_libraries(ker-refcount-test PRIVATE ker_port_headers ker_linux_port Threads::Threads)
add_test(NAME refcount COMMAND ker-refcount-test)

if(KER_WITH_DPDK)
    include("${PROJECT_SOURCE_DIR}/cmake/FStackConfigSourceTests.cmake")
    file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/fstack-config-cases.txt" config_source_cases)
    foreach(source_case IN LISTS config_source_cases)
        set(config_target "ker-${source_case}")
        add_executable(${config_target} fstack-config-case.c)
        target_compile_definitions(${config_target} PRIVATE
            "SOURCE_INCLUDE=fstack-config-source/${source_case}.inc" "SOURCE_FUNCTION=${source_case}")
        target_link_libraries(${config_target} PRIVATE ker-example-fstack-config)
        target_link_options(${config_target} PRIVATE -Wl,--wrap=calloc)
        if(source_case STREQUAL "test_ff_load_config_portlist_nonint")
            target_compile_definitions(${config_target} PRIVATE FSTACK_CONFIG_TEST_WRAP_STRSPLIT)
            target_link_options(${config_target} PRIVATE -Wl,--wrap=rte_strsplit)
        endif()
        target_compile_options(${config_target} PRIVATE -Wall -Wextra -Werror)
        set_target_properties(${config_target} PROPERTIES C_STANDARD 11 C_STANDARD_REQUIRED YES C_EXTENSIONS OFF)
    endforeach()
    add_executable(ker-fstack-config-unload-test fstack-config-unload.c)
    target_link_libraries(ker-fstack-config-unload-test PRIVATE ker-example-fstack-config)
    target_compile_options(ker-fstack-config-unload-test PRIVATE -Wall -Wextra -Werror)
    set_target_properties(ker-fstack-config-unload-test PROPERTIES
        C_STANDARD 11 C_STANDARD_REQUIRED YES C_EXTENSIONS OFF)
    add_test(NAME fstack-config-original-unload COMMAND ker-fstack-config-unload-test)
    set_tests_properties(fstack-config-original-unload PROPERTIES
        WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/upstream/fstack/tests/unit" TIMEOUT 30)
    add_test(NAME fstack-config-original-import COMMAND "${Python3_EXECUTABLE}"
        "${CMAKE_CURRENT_SOURCE_DIR}/fstack-config-import.py")
    add_executable(ker-fstack-config-preflight-test fstack-config-preflight.c)
    target_link_libraries(ker-fstack-config-preflight-test PRIVATE ker-example-fstack-config)
    target_compile_options(ker-fstack-config-preflight-test PRIVATE -Wall -Wextra -Werror)
    set_target_properties(ker-fstack-config-preflight-test PROPERTIES
        C_STANDARD 11 C_STANDARD_REQUIRED YES C_EXTENSIONS OFF)
    add_test(NAME fstack-config-capacity-preflight COMMAND ker-fstack-config-preflight-test)
    set_tests_properties(fstack-config-capacity-preflight PROPERTIES TIMEOUT 30 LABELS "fstack;dpdk")
    add_executable(ker-fstack-a10-dispatch-test fstack-a10-dispatch.c)
    target_link_libraries(ker-fstack-a10-dispatch-test PRIVATE ker-example-a10-dispatch "${ker_controller_ring_pmd}")
    target_compile_options(ker-fstack-a10-dispatch-test PRIVATE -Wall -Wextra -Werror)
    set_target_properties(ker-fstack-a10-dispatch-test PROPERTIES C_STANDARD 11 C_STANDARD_REQUIRED YES C_EXTENSIONS OFF)
    add_test(NAME fstack-a10-halfopen-dispatch COMMAND ker-fstack-a10-dispatch-test dispatch)
    add_test(NAME fstack-a10-window-mechanism COMMAND ker-fstack-a10-dispatch-test mechanism)
    add_test(NAME fstack-a10-classifier-bounds COMMAND ker-fstack-a10-dispatch-test bounds)
    add_test(NAME fstack-a10-source-import COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/a10-dispatch-import.py")
    set_tests_properties(fstack-a10-halfopen-dispatch fstack-a10-window-mechanism fstack-a10-classifier-bounds
        fstack-a10-source-import PROPERTIES TIMEOUT 30 LABELS "fstack;dpdk")
endif()

if(KER_WITH_DPDK)
    add_executable(ker-fstack-parked-tx-test fstack-parked-tx.c)
    target_link_libraries(ker-fstack-parked-tx-test PRIVATE ker::reload_tx ker::packet_dispatcher "${ker_controller_ring_pmd}")
    target_compile_options(ker-fstack-parked-tx-test PRIVATE -Wall -Wextra -Werror)
    set_target_properties(ker-fstack-parked-tx-test PROPERTIES C_STANDARD 11 C_STANDARD_REQUIRED YES C_EXTENSIONS OFF)
    add_test(NAME fstack-parked-tx-divert COMMAND ker-fstack-parked-tx-test divert)
    add_test(NAME fstack-parked-tx-watermark COMMAND ker-fstack-parked-tx-test watermark)
    add_test(NAME fstack-parked-tx-guard COMMAND ker-fstack-parked-tx-test guard)
    add_test(NAME fstack-parked-tx-pass COMMAND ker-fstack-parked-tx-test pass)
    add_test(NAME fstack-parked-tx-ownership COMMAND ker-fstack-parked-tx-test ownership)
    set_tests_properties(fstack-parked-tx-divert fstack-parked-tx-watermark fstack-parked-tx-guard
        fstack-parked-tx-pass fstack-parked-tx-ownership PROPERTIES TIMEOUT 30 LABELS "fstack;dpdk")
endif()

if(KER_WITH_DPDK)
    add_executable(ker-fstack-peer-dispatch-test fstack-peer-dispatch.c)
    target_link_libraries(ker-fstack-peer-dispatch-test PRIVATE ker::peer_dispatcher "${ker_controller_ring_pmd}")
    target_compile_options(ker-fstack-peer-dispatch-test PRIVATE -Wall -Wextra -Werror)
    set_target_properties(ker-fstack-peer-dispatch-test PROPERTIES C_STANDARD 11 C_STANDARD_REQUIRED YES C_EXTENSIONS OFF)
    add_test(NAME fstack-peer-dispatch-ownership COMMAND ker-fstack-peer-dispatch-test)
    set_tests_properties(fstack-peer-dispatch-ownership PROPERTIES TIMEOUT 30 LABELS "fstack;dpdk")
endif()

if(KER_WITH_DPDK)
    add_test(NAME fstack-flow-map-router COMMAND ker-flow-map-router)
    set_tests_properties(fstack-flow-map-router PROPERTIES TIMEOUT 30 LABELS "fstack;flow-map;dpdk")
    add_executable(ker-fstack-flow-map-test fstack-flow-map.c)
    target_include_directories(ker-fstack-flow-map-test PRIVATE
        "${PROJECT_SOURCE_DIR}/third_party/fstack-reload" "${PROJECT_SOURCE_DIR}/third_party/fstack-ipc")
    target_link_libraries(ker-fstack-flow-map-test PRIVATE ker-example-flow-map)
    target_compile_options(ker-fstack-flow-map-test PRIVATE -Wall -Wextra -Werror)
    set_target_properties(ker-fstack-flow-map-test PROPERTIES
        C_STANDARD 11 C_STANDARD_REQUIRED YES C_EXTENSIONS OFF)
    add_test(NAME fstack-flow-map-basic COMMAND ker-fstack-flow-map-test basic)
    add_test(NAME fstack-flow-map-single-phase COMMAND ker-fstack-flow-map-test single-phase)
    add_test(NAME fstack-flow-map-admission COMMAND ker-fstack-flow-map-test admission)
    add_test(NAME fstack-flow-map-revoke COMMAND ker-fstack-flow-map-test revoke)
    add_test(NAME fstack-flow-map-growth COMMAND ker-fstack-flow-map-test growth)
    add_test(NAME fstack-flow-map-import COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/flow-map-import.py")
    set_tests_properties(fstack-flow-map-basic fstack-flow-map-single-phase fstack-flow-map-admission
        fstack-flow-map-revoke fstack-flow-map-growth fstack-flow-map-import
        PROPERTIES TIMEOUT 15 LABELS "fstack;flow-map")
endif()

if(KER_WITH_DPDK)
    add_executable(ker-fstack-rss-thash-test fstack-rss-thash.c)
    target_link_libraries(ker-fstack-rss-thash-test PRIVATE PkgConfig::DPDK)
    target_compile_options(ker-fstack-rss-thash-test PRIVATE -Wall -Wextra -Werror)
    add_executable(ker-fstack-rss-thash-negative-test fstack-rss-thash.c)
    target_compile_definitions(ker-fstack-rss-thash-negative-test PRIVATE KER_THASH_TEST_REJECT_ADJUST)
    target_link_libraries(ker-fstack-rss-thash-negative-test PRIVATE PkgConfig::DPDK)
    target_compile_options(ker-fstack-rss-thash-negative-test PRIVATE -Wall -Wextra -Werror)
    add_test(NAME fstack-rss-thash-ipv4 COMMAND ker-fstack-rss-thash-test ipv4)
    add_test(NAME fstack-rss-thash-ipv6 COMMAND ker-fstack-rss-thash-test ipv6)
    add_test(NAME fstack-rss-thash-quality-gates
        COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/posix/fstack-rss-thash.py"
            --app "$<TARGET_FILE:ker-fstack-rss-thash-test>"
            --negative-app "$<TARGET_FILE:ker-fstack-rss-thash-negative-test>")
    set_tests_properties(fstack-rss-thash-ipv4 fstack-rss-thash-ipv6
        fstack-rss-thash-quality-gates PROPERTIES TIMEOUT 60 LABELS "fstack;dpdk")
    add_test(NAME fstack-rss-thash-import
        COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/rss-thash-import.py")
    set_tests_properties(fstack-rss-thash-import PROPERTIES TIMEOUT 15 LABELS provenance)
    add_executable(ker-ipv4-fields-test ipv4-fields.c)
    target_include_directories(ker-ipv4-fields-test PRIVATE "${PROJECT_SOURCE_DIR}/src")
    target_compile_definitions(ker-ipv4-fields-test PRIVATE _GNU_SOURCE)
    target_link_libraries(ker-ipv4-fields-test PRIVATE ker_skb_headers ker_eth_headers
        ker_udp_create_port ker_tcp_create_port ker_icmp_echo_create_port
        ker_linux_port ker_dpdk_port ker_skb_port PkgConfig::DPDK Threads::Threads)
    add_test(NAME ipv4-fields COMMAND ker-ipv4-fields-test)
    set_tests_properties(ipv4-fields PROPERTIES TIMEOUT 30)
    add_executable(ker-dpdk-memory-test dpdk-memory.c)
    target_compile_definitions(ker-dpdk-memory-test PRIVATE _GNU_SOURCE)
    target_link_libraries(ker-dpdk-memory-test PRIVATE
        ker_port_headers ker_linux_port ker_dpdk_port PkgConfig::DPDK Threads::Threads)
    add_test(NAME dpdk-memory COMMAND ker-dpdk-memory-test)
    add_executable(ker-worker-test worker.c)
    target_compile_definitions(ker-worker-test PRIVATE _GNU_SOURCE)
    target_link_libraries(ker-worker-test PRIVATE
        ker_port_headers ker_linux_port ker_dpdk_port PkgConfig::DPDK Threads::Threads)
    add_test(NAME worker COMMAND ker-worker-test)
    add_executable(ker-flow-test flow.c)
    target_compile_definitions(ker-flow-test PRIVATE _GNU_SOURCE)
    target_link_libraries(ker-flow-test PRIVATE
        ker_port_headers ker_linux_port ker_dpdk_port PkgConfig::DPDK Threads::Threads)
    add_test(NAME flow COMMAND ker-flow-test)
    set_tests_properties(flow PROPERTIES TIMEOUT 30)
    add_executable(ker-flow-chain-test flow-chain.c)
    target_compile_definitions(ker-flow-chain-test PRIVATE _GNU_SOURCE)
    target_link_libraries(ker-flow-chain-test PRIVATE
        ker_port_headers ker_linux_port ker_dpdk_port PkgConfig::DPDK Threads::Threads)
    add_test(NAME flow-chain COMMAND ker-flow-chain-test)
    set_tests_properties(flow-chain PROPERTIES TIMEOUT 30)
    add_executable(ker-flow-ip-options-test flow-ip-options.c)
    target_compile_definitions(ker-flow-ip-options-test PRIVATE _GNU_SOURCE)
    target_link_libraries(ker-flow-ip-options-test PRIVATE
        ker_port_headers ker_linux_port ker_dpdk_port PkgConfig::DPDK Threads::Threads)
    add_test(NAME flow-ip-options COMMAND ker-flow-ip-options-test)
    set_tests_properties(flow-ip-options PROPERTIES TIMEOUT 30)
    add_executable(ker-flow-icmpv4-test flow-icmpv4.c)
    target_compile_definitions(ker-flow-icmpv4-test PRIVATE _GNU_SOURCE)
    target_link_libraries(ker-flow-icmpv4-test PRIVATE
        ker_port_headers ker_linux_port ker_dpdk_port PkgConfig::DPDK Threads::Threads)
    add_test(NAME flow-icmpv4 COMMAND ker-flow-icmpv4-test)
    set_tests_properties(flow-icmpv4 PROPERTIES TIMEOUT 30)
    add_executable(ker-flow-buckets-test flow-buckets.c)
    target_compile_definitions(ker-flow-buckets-test PRIVATE _GNU_SOURCE)
    target_link_libraries(ker-flow-buckets-test PRIVATE
        ker_port_headers ker_linux_port ker_dpdk_port PkgConfig::DPDK Threads::Threads)
    add_test(NAME flow-buckets COMMAND ker-flow-buckets-test)
    set_tests_properties(flow-buckets PROPERTIES TIMEOUT 60)
    add_executable(ker-flow-steering-test flow-steering.c)
    target_compile_definitions(ker-flow-steering-test PRIVATE _GNU_SOURCE)
    target_link_libraries(ker-flow-steering-test PRIVATE
        ker_port_headers ker_linux_port ker_dpdk_port PkgConfig::DPDK Threads::Threads)
    add_test(NAME flow-matrix COMMAND ker-flow-steering-test --matrix)
    add_test(NAME flow-multicore COMMAND ker-flow-steering-test --multicore)
    set_tests_properties(flow-matrix PROPERTIES TIMEOUT 30)
    set_tests_properties(flow-multicore PROPERTIES TIMEOUT 45 SKIP_RETURN_CODE 77)
    set_tests_properties(worker PROPERTIES TIMEOUT 30)
    add_executable(ker-skb-test skb.c)
    target_compile_definitions(ker-skb-test PRIVATE _GNU_SOURCE)
    target_link_libraries(ker-skb-test PRIVATE
        ker_skb_headers ker_linux_port ker_dpdk_port ker_skb_port Threads::Threads)
    add_test(NAME skb COMMAND ker-skb-test)
    add_executable(ker-ethernet-test ethernet.c)
    target_compile_definitions(ker-ethernet-test PRIVATE _GNU_SOURCE)
    target_link_libraries(ker-ethernet-test PRIVATE ker_eth_headers ker_eth_port
        ker_linux_port ker_dpdk_port ker_skb_port Threads::Threads)
    add_test(NAME ethernet COMMAND ker-ethernet-test)
    set_tests_properties(ethernet PROPERTIES TIMEOUT 30)
    add_executable(ker-fstack-ipv4-ingress-test fstack-ipv4-ingress.c)
    target_include_directories(ker-fstack-ipv4-ingress-test PRIVATE "${PROJECT_SOURCE_DIR}/src")
    target_compile_definitions(ker-fstack-ipv4-ingress-test PRIVATE _GNU_SOURCE)
    target_link_libraries(ker-fstack-ipv4-ingress-test PRIVATE ker_ipv4_view_port ker_eth_headers ker_eth_port
        ker_linux_port ker_dpdk_port ker_skb_port PkgConfig::DPDK Threads::Threads)
    add_test(NAME fstack-ipv4-ingress-validation COMMAND ker-fstack-ipv4-ingress-test)
    set_tests_properties(fstack-ipv4-ingress-validation PROPERTIES TIMEOUT 30)
    add_executable(ker-fstack-udp-ingress-test fstack-udp-ingress.c)
    target_include_directories(ker-fstack-udp-ingress-test PRIVATE "${PROJECT_SOURCE_DIR}/src")
    target_compile_definitions(ker-fstack-udp-ingress-test PRIVATE _GNU_SOURCE)
    target_link_libraries(ker-fstack-udp-ingress-test PRIVATE ker_udp_view_port ker_ipv4_view_port ker_eth_headers ker_eth_port
        ker_linux_port ker_dpdk_port ker_skb_port PkgConfig::DPDK Threads::Threads)
    add_test(NAME fstack-udp-ingress-validation COMMAND ker-fstack-udp-ingress-test)
    set_tests_properties(fstack-udp-ingress-validation PROPERTIES TIMEOUT 30)
    add_test(NAME fstack-udp-minimal-boundaries COMMAND ker-fstack-udp-ingress-test minimal-boundaries)
    set_tests_properties(fstack-udp-minimal-boundaries PROPERTIES TIMEOUT 30)
    add_executable(ker-fstack-tcp-ingress-test fstack-tcp-ingress.c)
    target_include_directories(ker-fstack-tcp-ingress-test PRIVATE "${PROJECT_SOURCE_DIR}/src")
    target_compile_definitions(ker-fstack-tcp-ingress-test PRIVATE _GNU_SOURCE)
    target_link_libraries(ker-fstack-tcp-ingress-test PRIVATE ker_tcp_view_port ker_ipv4_view_port ker_eth_headers ker_eth_port
        ker_linux_port ker_dpdk_port ker_skb_port PkgConfig::DPDK Threads::Threads)
    add_test(NAME fstack-tcp-ingress-validation COMMAND ker-fstack-tcp-ingress-test)
    set_tests_properties(fstack-tcp-ingress-validation PROPERTIES TIMEOUT 30)
    add_executable(ker-transport-receive-test transport-receive.c)
    target_include_directories(ker-transport-receive-test PRIVATE "${PROJECT_SOURCE_DIR}/src")
    target_compile_definitions(ker-transport-receive-test PRIVATE _GNU_SOURCE)
    target_link_libraries(ker-transport-receive-test PRIVATE ker_transport_receive_port
        ker_icmpv4_view_port ker_icmp_echo_view_port ker_tcp_view_port ker_udp_view_port ker_ipv4_view_port ker_receive_port
        ker_receive_headers ker_eth_headers ker_eth_port ker_linux_port ker_dpdk_port ker_skb_port Threads::Threads)
    add_executable(ker-fstack-flow-receive-test fstack-flow-receive.c)
    target_include_directories(ker-fstack-flow-receive-test PRIVATE "${PROJECT_SOURCE_DIR}/src")
    target_compile_definitions(ker-fstack-flow-receive-test PRIVATE _GNU_SOURCE)
    target_link_libraries(ker-fstack-flow-receive-test PRIVATE ker_transport_receive_port
        ker_flow_ring_port ker_tx_ring_port
        ker_icmpv4_view_port ker_icmp_echo_view_port ker_tcp_view_port ker_udp_view_port ker_ipv4_view_port ker_receive_port
        ker_receive_headers ker_eth_headers ker_skb_headers ker_neighbor_headers ker_eth_port ker_linux_port ker_dpdk_port ker_skb_port Threads::Threads)
    add_test(NAME fstack-flow-receive COMMAND ker-fstack-flow-receive-test)
    set_tests_properties(fstack-flow-receive PROPERTIES TIMEOUT 30)
    add_executable(ker-fstack-flow-owner-receive-test fstack-flow-owner-receive.c)
    target_include_directories(ker-fstack-flow-owner-receive-test PRIVATE "${PROJECT_SOURCE_DIR}/src")
    target_compile_definitions(ker-fstack-flow-owner-receive-test PRIVATE _GNU_SOURCE)
    target_link_libraries(ker-fstack-flow-owner-receive-test PRIVATE ker_flow_receive_port
        ker_transport_receive_port ker_flow_ring_port ker_rx_ring_port ker_tx_ring_port ker_receive_port
        ker_ipv4_view_port ker_udp_view_port ker_tcp_view_port ker_icmpv4_view_port ker_icmp_echo_view_port
        ker_receive_headers ker_eth_headers ker_skb_headers ker_neighbor_headers ker_eth_port
        ker_linux_port ker_dpdk_port ker_skb_port ker_address_port ker_neighbor_port PkgConfig::DPDK Threads::Threads)
    add_test(NAME fstack-flow-owner-receive COMMAND ker-fstack-flow-owner-receive-test)
    set_tests_properties(fstack-flow-owner-receive PROPERTIES TIMEOUT 30)
    add_executable(ker-fstack-flow-concurrent-receive-test fstack-flow-concurrent-receive.c)
    target_include_directories(ker-fstack-flow-concurrent-receive-test PRIVATE "${PROJECT_SOURCE_DIR}/src")
    target_compile_definitions(ker-fstack-flow-concurrent-receive-test PRIVATE _GNU_SOURCE)
    target_link_libraries(ker-fstack-flow-concurrent-receive-test PRIVATE ker_transport_receive_port
        ker_flow_ring_port ker_tx_ring_port ker_icmpv4_view_port ker_icmp_echo_view_port ker_tcp_view_port ker_udp_view_port ker_ipv4_view_port
        ker_receive_port ker_receive_headers ker_eth_headers ker_skb_headers ker_neighbor_headers ker_eth_port
        ker_linux_port ker_dpdk_port ker_skb_port ker_address_port ker_neighbor_port PkgConfig::DPDK Threads::Threads)
    add_test(NAME fstack-flow-concurrent-receive COMMAND ker-fstack-flow-concurrent-receive-test)
    set_tests_properties(fstack-flow-concurrent-receive PROPERTIES TIMEOUT 45 SKIP_RETURN_CODE 77)
    add_test(NAME transport-receive COMMAND ker-transport-receive-test)
    set_tests_properties(transport-receive PROPERTIES TIMEOUT 30)
    add_executable(ker-icmp-echo-test icmp-echo.c)
    target_include_directories(ker-icmp-echo-test PRIVATE "${PROJECT_SOURCE_DIR}/src")
    target_compile_definitions(ker-icmp-echo-test PRIVATE _GNU_SOURCE)
    target_link_libraries(ker-icmp-echo-test PRIVATE ker_icmpv4_create_port ker_icmpv4_view_port ker_icmp_echo_view_port ker_icmp_echo_create_port
        ker_ipv4_view_port ker_eth_headers ker_skb_headers ker_eth_port ker_linux_port ker_dpdk_port
        ker_skb_port PkgConfig::DPDK Threads::Threads)
    add_test(NAME icmp-echo COMMAND ker-icmp-echo-test)
    set_tests_properties(icmp-echo PROPERTIES TIMEOUT 30)
    add_executable(ker-tx-export-test tx-export.c)
    target_include_directories(ker-tx-export-test PRIVATE "${PROJECT_SOURCE_DIR}/src")
    target_compile_definitions(ker-tx-export-test PRIVATE _GNU_SOURCE)
    target_link_libraries(ker-tx-export-test PRIVATE ker_neighbor_headers ker_timer_list_port ker_linux_port ker_dpdk_port ker_address_port ker_neighbor_port ker_skb_port ker_udp_create_port ker_tx_export_port Threads::Threads)
    add_test(NAME tx-export COMMAND ker-tx-export-test)
    set_tests_properties(tx-export PROPERTIES TIMEOUT 30)
    add_executable(ker-tx-export-chain-test tx-export-chain.c)
    target_include_directories(ker-tx-export-chain-test PRIVATE "${PROJECT_SOURCE_DIR}/src")
    target_compile_definitions(ker-tx-export-chain-test PRIVATE _GNU_SOURCE)
    target_link_libraries(ker-tx-export-chain-test PRIVATE ker_neighbor_headers ker_timer_list_port
        ker_receive_headers ker_eth_headers ker_ipv4_view_port ker_udp_view_port ker_tcp_view_port
        ker_icmpv4_view_port ker_icmp_echo_view_port ker_transport_receive_port ker_receive_port ker_eth_port ker_linux_port ker_dpdk_port
        ker_address_port ker_neighbor_port ker_skb_port ker_udp_create_port ker_tcp_create_port
        ker_tx_export_port Threads::Threads)
    add_test(NAME tx-export-chain COMMAND ker-tx-export-chain-test)
    set_tests_properties(tx-export-chain PROPERTIES TIMEOUT 30)
    add_executable(ker-ethdev-tx-test ethdev-tx.c)
    file(GLOB KER_NET_RING_PMD_CANDIDATES
        "${KER_DPDK_PKGCONFIG_DIR}/../dpdk/pmds-*/librte_net_ring.so")
    if(NOT KER_NET_RING_PMD_CANDIDATES)
        message(FATAL_ERROR "ethdev-tx requires the pinned DPDK net_ring PMD; build with KER_DPDK_DRIVERS=mempool/ring,net/ring")
    endif()
    list(GET KER_NET_RING_PMD_CANDIDATES 0 KER_NET_RING_PMD)
    target_include_directories(ker-ethdev-tx-test PRIVATE "${PROJECT_SOURCE_DIR}/src"
        "${PROJECT_SOURCE_DIR}/third_party/dpdk/drivers/net/ring")
    target_compile_definitions(ker-ethdev-tx-test PRIVATE _GNU_SOURCE)
    target_link_libraries(ker-ethdev-tx-test PRIVATE ker_ethdev_tx_port ker_skb_headers
        ker_neighbor_headers ker_linux_port ker_dpdk_port ker_skb_port ker_address_port ker_neighbor_port
        ker_udp_create_port ker_tcp_create_port ker_tx_export_port
        "${KER_NET_RING_PMD}" PkgConfig::DPDK Threads::Threads)
    add_test(NAME ethdev-tx COMMAND ker-ethdev-tx-test)
    string(JOIN ":" KER_ETHDEV_TEST_LIBRARY_PATH ${DPDK_LIBRARY_DIRS})
    set_tests_properties(ethdev-tx PROPERTIES TIMEOUT 30
        ENVIRONMENT "LD_LIBRARY_PATH=${KER_ETHDEV_TEST_LIBRARY_PATH}:$ENV{LD_LIBRARY_PATH}")
    add_executable(ker-ethdev-rx-test ethdev-rx.c)
    target_include_directories(ker-ethdev-rx-test PRIVATE "${PROJECT_SOURCE_DIR}/src"
        "${PROJECT_SOURCE_DIR}/third_party/dpdk/drivers/net/ring")
    target_compile_definitions(ker-ethdev-rx-test PRIVATE _GNU_SOURCE)
    target_link_libraries(ker-ethdev-rx-test PRIVATE "${KER_NET_RING_PMD}"
        ker_linux_port ker_skb_port ker_dpdk_port)
    target_link_libraries(ker-ethdev-rx-test PRIVATE ker_ethdev_rx_port ker_receive_port
        ker_receive_headers ker_eth_headers ker_skb_headers ker_neighbor_headers
        ker_rx_ring_port ker_tx_ring_port ker_eth_port ker_neighbor_port ker_address_port
        PkgConfig::DPDK Threads::Threads)
    add_test(NAME ethdev-rx COMMAND ker-ethdev-rx-test)
    set_tests_properties(ethdev-rx PROPERTIES TIMEOUT 30
        ENVIRONMENT "LD_LIBRARY_PATH=${KER_ETHDEV_TEST_LIBRARY_PATH}:$ENV{LD_LIBRARY_PATH}")
    add_executable(ker-ethdev-rx-metadata-test ethdev-rx-metadata.c)
    target_include_directories(ker-ethdev-rx-metadata-test PRIVATE "${PROJECT_SOURCE_DIR}/src"
        "${PROJECT_SOURCE_DIR}/third_party/dpdk/drivers/net/ring")
    target_compile_definitions(ker-ethdev-rx-metadata-test PRIVATE _GNU_SOURCE)
    target_link_libraries(ker-ethdev-rx-metadata-test PRIVATE "${KER_NET_RING_PMD}"
        ker_ethdev_rx_port ker_transport_receive_port ker_receive_port ker_receive_headers
        ker_eth_headers ker_skb_headers ker_icmpv4_view_port ker_ipv4_view_port ker_udp_view_port
        ker_tcp_view_port ker_icmp_echo_view_port ker_eth_port ker_linux_port
        ker_dpdk_port ker_skb_port PkgConfig::DPDK Threads::Threads)
    add_test(NAME ethdev-rx-metadata COMMAND ker-ethdev-rx-metadata-test)
    set_tests_properties(ethdev-rx-metadata PROPERTIES TIMEOUT 30
        ENVIRONMENT "LD_LIBRARY_PATH=${KER_ETHDEV_TEST_LIBRARY_PATH}:$ENV{LD_LIBRARY_PATH}")
    add_executable(ker-ethdev-external-lifetime-test ethdev-external-lifetime.c)
    target_include_directories(ker-ethdev-external-lifetime-test PRIVATE "${PROJECT_SOURCE_DIR}/src"
        "${PROJECT_SOURCE_DIR}/third_party/dpdk/drivers/net/ring")
    target_compile_definitions(ker-ethdev-external-lifetime-test PRIVATE _GNU_SOURCE)
    target_link_libraries(ker-ethdev-external-lifetime-test PRIVATE "${KER_NET_RING_PMD}"
        ker_ethdev_rx_port ker_receive_port ker_receive_headers ker_eth_headers ker_skb_headers
        ker_eth_port ker_address_port ker_linux_port ker_dpdk_port ker_skb_port
        PkgConfig::DPDK Threads::Threads)
    add_test(NAME ethdev-external-lifetime COMMAND ker-ethdev-external-lifetime-test)
    set_tests_properties(ethdev-external-lifetime PROPERTIES TIMEOUT 30
        ENVIRONMENT "LD_LIBRARY_PATH=${KER_ETHDEV_TEST_LIBRARY_PATH}:$ENV{LD_LIBRARY_PATH}")
    add_executable(ker-ethdev-rx-capacity-test ethdev-rx-capacity.c)
    target_include_directories(ker-ethdev-rx-capacity-test PRIVATE "${PROJECT_SOURCE_DIR}/src"
        "${PROJECT_SOURCE_DIR}/third_party/dpdk/drivers/net/ring")
    target_compile_definitions(ker-ethdev-rx-capacity-test PRIVATE _GNU_SOURCE)
    target_link_libraries(ker-ethdev-rx-capacity-test PRIVATE "${KER_NET_RING_PMD}"
        ker_ethdev_rx_port ker_receive_port ker_receive_headers ker_eth_headers ker_skb_headers
        ker_eth_port ker_address_port ker_linux_port ker_dpdk_port ker_skb_port
        PkgConfig::DPDK Threads::Threads)
    add_test(NAME ethdev-rx-capacity COMMAND ker-ethdev-rx-capacity-test)
    set_tests_properties(ethdev-rx-capacity PROPERTIES TIMEOUT 30
        ENVIRONMENT "LD_LIBRARY_PATH=${KER_ETHDEV_TEST_LIBRARY_PATH}:$ENV{LD_LIBRARY_PATH}")
    add_executable(ker-ethdev-rx-fanout-test ethdev-rx-fanout.c)
    target_include_directories(ker-ethdev-rx-fanout-test PRIVATE "${PROJECT_SOURCE_DIR}/src"
        "${PROJECT_SOURCE_DIR}/third_party/dpdk/drivers/net/ring")
    target_compile_definitions(ker-ethdev-rx-fanout-test PRIVATE _GNU_SOURCE)
    target_link_libraries(ker-ethdev-rx-fanout-test PRIVATE "${KER_NET_RING_PMD}"
        ker_ethdev_rx_port ker_receive_port ker_receive_headers ker_eth_headers ker_skb_headers
        ker_eth_port ker_address_port ker_linux_port ker_dpdk_port ker_skb_port
        PkgConfig::DPDK Threads::Threads)
    add_test(NAME ethdev-rx-fanout COMMAND ker-ethdev-rx-fanout-test)
    set_tests_properties(ethdev-rx-fanout PROPERTIES TIMEOUT 30
        ENVIRONMENT "LD_LIBRARY_PATH=${KER_ETHDEV_TEST_LIBRARY_PATH}:$ENV{LD_LIBRARY_PATH}")
    add_executable(ker-ethdev-rebind-test ethdev-rebind.c)
    target_include_directories(ker-ethdev-rebind-test PRIVATE "${PROJECT_SOURCE_DIR}/src"
        "${PROJECT_SOURCE_DIR}/third_party/dpdk/drivers/net/ring")
    target_compile_definitions(ker-ethdev-rebind-test PRIVATE _GNU_SOURCE)
    target_link_libraries(ker-ethdev-rebind-test PRIVATE "${KER_NET_RING_PMD}"
        ker_ethdev_rx_port ker_receive_port ker_receive_headers ker_eth_headers ker_skb_headers
        ker_eth_port ker_address_port ker_linux_port ker_dpdk_port ker_skb_port
        PkgConfig::DPDK Threads::Threads)
    add_test(NAME ethdev-rebind COMMAND ker-ethdev-rebind-test)
    set_tests_properties(ethdev-rebind PROPERTIES TIMEOUT 30
        ENVIRONMENT "LD_LIBRARY_PATH=${KER_ETHDEV_TEST_LIBRARY_PATH}:$ENV{LD_LIBRARY_PATH}")
    add_executable(ker-ethdev-duplex-test ethdev-duplex.c)
    target_include_directories(ker-ethdev-duplex-test PRIVATE "${PROJECT_SOURCE_DIR}/src"
        "${PROJECT_SOURCE_DIR}/third_party/dpdk/drivers/net/ring")
    target_compile_definitions(ker-ethdev-duplex-test PRIVATE _GNU_SOURCE)
    target_link_libraries(ker-ethdev-duplex-test PRIVATE "${KER_NET_RING_PMD}"
        ker_ethdev_tx_port ker_ethdev_rx_port ker_skb_headers ker_neighbor_headers
        ker_receive_headers ker_eth_headers ker_linux_port ker_skb_port ker_dpdk_port
        ker_eth_port ker_receive_port ker_neighbor_port ker_address_port
        ker_ipv4_view_port ker_udp_view_port ker_tcp_view_port ker_icmpv4_view_port
        ker_icmp_echo_view_port ker_transport_receive_port ker_udp_create_port
        ker_tcp_create_port ker_tx_export_port ker_timer_list_port
        PkgConfig::DPDK Threads::Threads)
    add_test(NAME ethdev-duplex COMMAND ker-ethdev-duplex-test)
    set_tests_properties(ethdev-duplex PROPERTIES TIMEOUT 30
        ENVIRONMENT "LD_LIBRARY_PATH=${KER_ETHDEV_TEST_LIBRARY_PATH}:$ENV{LD_LIBRARY_PATH}")
    add_executable(ker-ethdev-multiqueue-test ethdev-multiqueue.c)
    target_include_directories(ker-ethdev-multiqueue-test PRIVATE "${PROJECT_SOURCE_DIR}/src"
        "${PROJECT_SOURCE_DIR}/third_party/dpdk/drivers/net/ring")
    target_compile_definitions(ker-ethdev-multiqueue-test PRIVATE _GNU_SOURCE)
    target_link_libraries(ker-ethdev-multiqueue-test PRIVATE "${KER_NET_RING_PMD}"
        ker_ethdev_tx_port ker_ethdev_rx_port ker_skb_headers ker_neighbor_headers
        ker_receive_headers ker_eth_headers ker_linux_port ker_skb_port ker_dpdk_port
        ker_eth_port ker_receive_port ker_neighbor_port ker_address_port
        ker_ipv4_view_port ker_udp_view_port ker_tcp_view_port ker_icmpv4_view_port
        ker_icmp_echo_view_port ker_transport_receive_port ker_udp_create_port
        ker_tcp_create_port ker_tx_export_port ker_timer_list_port
        PkgConfig::DPDK Threads::Threads)
    add_test(NAME ethdev-multiqueue COMMAND ker-ethdev-multiqueue-test)
    set_tests_properties(ethdev-multiqueue PROPERTIES TIMEOUT 45 SKIP_RETURN_CODE 77
        ENVIRONMENT "LD_LIBRARY_PATH=${KER_ETHDEV_TEST_LIBRARY_PATH}:$ENV{LD_LIBRARY_PATH}")
    add_test(NAME ethdev-ethernet-abi-boundary COMMAND "${Python3_EXECUTABLE}"
        "${CMAKE_CURRENT_SOURCE_DIR}/ethernet-abi-boundary.py" "${PROJECT_SOURCE_DIR}")
    add_executable(ker-tx-ring-test tx-ring.c)
    target_include_directories(ker-tx-ring-test PRIVATE "${PROJECT_SOURCE_DIR}/src")
    target_compile_definitions(ker-tx-ring-test PRIVATE _GNU_SOURCE)
    target_link_libraries(ker-tx-ring-test PRIVATE ker_tx_ring_port ker_tx_export_port
        ker_skb_headers ker_neighbor_headers ker_receive_headers ker_eth_headers
        ker_neighbor_port ker_address_port ker_skb_port ker_eth_port ker_receive_port
        ker_ipv4_view_port ker_udp_view_port ker_tcp_view_port ker_icmpv4_view_port ker_icmp_echo_view_port ker_transport_receive_port
        ker_udp_create_port ker_tcp_create_port ker_timer_list_port ker_linux_port
        ker_dpdk_port PkgConfig::DPDK Threads::Threads)
    add_test(NAME tx-ring COMMAND ker-tx-ring-test)
    set_tests_properties(tx-ring PROPERTIES TIMEOUT 30)
    add_executable(ker-flow-ring-test flow-ring.c)
    target_include_directories(ker-flow-ring-test PRIVATE "${PROJECT_SOURCE_DIR}/src")
    target_compile_definitions(ker-flow-ring-test PRIVATE _GNU_SOURCE)
    target_link_libraries(ker-flow-ring-test PRIVATE ker_flow_ring_port ker_tx_ring_port
        ker_port_headers ker_skb_headers ker_neighbor_headers ker_linux_port ker_dpdk_port PkgConfig::DPDK Threads::Threads)
    add_test(NAME flow-ring COMMAND ker-flow-ring-test)
    set_tests_properties(flow-ring PROPERTIES TIMEOUT 30)
    add_executable(ker-rx-ring-test rx-ring.c)
    target_include_directories(ker-rx-ring-test PRIVATE "${PROJECT_SOURCE_DIR}/src")
    target_compile_definitions(ker-rx-ring-test PRIVATE _GNU_SOURCE)
    target_link_libraries(ker-rx-ring-test PRIVATE ker_rx_ring_port ker_skb_headers ker_neighbor_headers
        ker_receive_headers ker_eth_headers ker_tx_export_port ker_tx_ring_port
        ker_skb_port ker_eth_port ker_receive_port ker_neighbor_port ker_address_port
        ker_ipv4_view_port ker_udp_view_port ker_tcp_view_port ker_icmpv4_view_port ker_icmp_echo_view_port ker_transport_receive_port
        ker_udp_create_port ker_tcp_create_port ker_icmp_echo_create_port ker_timer_list_port ker_linux_port
        ker_dpdk_port PkgConfig::DPDK Threads::Threads)
    add_test(NAME rx-ring COMMAND ker-rx-ring-test)
    set_tests_properties(rx-ring PROPERTIES TIMEOUT 30)
    add_executable(ker-cross-worker-ring-test cross-worker-ring.c)
    target_include_directories(ker-cross-worker-ring-test PRIVATE "${PROJECT_SOURCE_DIR}/src")
    target_compile_definitions(ker-cross-worker-ring-test PRIVATE _GNU_SOURCE)
    target_link_libraries(ker-cross-worker-ring-test PRIVATE ker_rx_ring_port ker_skb_headers
        ker_neighbor_headers ker_receive_headers ker_eth_headers ker_tx_export_port ker_tx_ring_port
        ker_skb_port ker_eth_port ker_receive_port ker_ipv4_view_port ker_udp_view_port ker_tcp_view_port
        ker_icmpv4_view_port ker_icmp_echo_view_port ker_transport_receive_port ker_udp_create_port ker_tcp_create_port
        ker_neighbor_port ker_address_port ker_timer_list_port ker_linux_port ker_dpdk_port
        PkgConfig::DPDK Threads::Threads)
    add_test(NAME cross-worker-ring COMMAND ker-cross-worker-ring-test)
    set_tests_properties(cross-worker-ring PROPERTIES TIMEOUT 30)
    add_executable(ker-fstack-concurrent-ring-test fstack-concurrent-ring.c)
    target_include_directories(ker-fstack-concurrent-ring-test PRIVATE "${PROJECT_SOURCE_DIR}/src" "${KER_ADDR_IMPORT}")
    target_compile_definitions(ker-fstack-concurrent-ring-test PRIVATE _GNU_SOURCE)
    target_link_libraries(ker-fstack-concurrent-ring-test PRIVATE ker_rx_ring_port ker_skb_headers
        ker_neighbor_headers ker_receive_headers ker_eth_headers ker_tx_export_port ker_tx_ring_port
        ker_skb_port ker_eth_port ker_receive_port ker_ipv4_view_port ker_udp_view_port ker_tcp_view_port
        ker_icmpv4_view_port ker_icmp_echo_view_port ker_icmp_echo_create_port ker_transport_receive_port ker_udp_create_port ker_tcp_create_port
        ker_udp_configured_create_port ker_tcp_configured_create_port ker_icmp_echo_configured_create_port
        ker_neighbor_port ker_address_port ker_timer_list_port ker_linux_port ker_dpdk_port
        PkgConfig::DPDK Threads::Threads)
    add_test(NAME fstack-concurrent-ring COMMAND ker-fstack-concurrent-ring-test)
    set_tests_properties(fstack-concurrent-ring PROPERTIES TIMEOUT 30)
    add_executable(ker-fstack-chain-export-test fstack-chain-export.c)
    target_include_directories(ker-fstack-chain-export-test PRIVATE "${PROJECT_SOURCE_DIR}/src")
    target_compile_definitions(ker-fstack-chain-export-test PRIVATE _GNU_SOURCE)
    target_link_libraries(ker-fstack-chain-export-test PRIVATE ker_skb_headers ker_eth_headers ker_neighbor_headers ker_address_port ker_skb_port
        ker_eth_port ker_dpdk_port ker_linux_port ker_udp_create_port ker_tcp_create_port
        ker_icmpv4_view_port ker_icmp_echo_view_port ker_transport_receive_port ker_receive_port ker_receive_headers ker_ipv4_view_port
        ker_udp_view_port ker_tcp_view_port ker_neighbor_port PkgConfig::DPDK Threads::Threads)
    add_test(NAME fstack-chain-export COMMAND ker-fstack-chain-export-test)
    set_tests_properties(fstack-chain-export PROPERTIES TIMEOUT 30)
    add_executable(ker-fstack-chain-checksum-test fstack-chain-checksum.c)
    target_include_directories(ker-fstack-chain-checksum-test PRIVATE "${PROJECT_SOURCE_DIR}/src")
    target_compile_definitions(ker-fstack-chain-checksum-test PRIVATE _GNU_SOURCE)
    target_link_libraries(ker-fstack-chain-checksum-test PRIVATE ker_skb_headers ker_eth_headers
        ker_receive_headers ker_neighbor_headers ker_linux_port ker_dpdk_port ker_skb_port ker_eth_port
        ker_receive_port ker_address_port ker_ipv4_view_port ker_udp_view_port ker_tcp_view_port
        ker_icmpv4_view_port ker_icmp_echo_view_port ker_transport_receive_port ker_udp_create_port ker_tcp_create_port ker_neighbor_port
        ker_tx_export_port Threads::Threads)
    add_test(NAME fstack-chain-checksum COMMAND ker-fstack-chain-checksum-test)
    set_tests_properties(fstack-chain-checksum PROPERTIES TIMEOUT 30)
    add_executable(ker-tcp-options-test tcp-options.c)
    target_include_directories(ker-tcp-options-test PRIVATE "${PROJECT_SOURCE_DIR}/src")
    target_compile_definitions(ker-tcp-options-test PRIVATE _GNU_SOURCE)
    target_link_libraries(ker-tcp-options-test PRIVATE ker_skb_headers ker_eth_headers ker_neighbor_headers ker_timer_list_port ker_linux_port ker_dpdk_port ker_address_port ker_neighbor_port ker_skb_port ker_tx_export_port ker_tcp_create_port ker_tcp_view_port ker_udp_view_port ker_ipv4_view_port ker_icmpv4_view_port ker_icmp_echo_view_port ker_transport_receive_port ker_receive_port ker_receive_headers ker_eth_port Threads::Threads)
    add_test(NAME tcp-options COMMAND ker-tcp-options-test)
    set_tests_properties(tcp-options PROPERTIES TIMEOUT 30)
    add_executable(ker-tcp-create-test tcp-create.c)
    target_include_directories(ker-tcp-create-test PRIVATE "${PROJECT_SOURCE_DIR}/src")
    target_compile_definitions(ker-tcp-create-test PRIVATE _GNU_SOURCE)
    target_link_libraries(ker-tcp-create-test PRIVATE ker_skb_headers ker_eth_headers ker_neighbor_headers ker_timer_list_port ker_linux_port ker_dpdk_port ker_address_port ker_neighbor_port ker_skb_port ker_tx_export_port ker_tcp_create_port ker_tcp_view_port ker_udp_view_port ker_ipv4_view_port ker_icmpv4_view_port ker_icmp_echo_view_port ker_transport_receive_port ker_receive_port ker_receive_headers ker_eth_port Threads::Threads)
    add_test(NAME tcp-create COMMAND ker-tcp-create-test)
    set_tests_properties(tcp-create PROPERTIES TIMEOUT 30)
    add_executable(ker-tcp-ip-options-test tcp-ip-options.c)
    target_include_directories(ker-tcp-ip-options-test PRIVATE "${PROJECT_SOURCE_DIR}/src")
    target_compile_definitions(ker-tcp-ip-options-test PRIVATE _GNU_SOURCE)
    target_link_libraries(ker-tcp-ip-options-test PRIVATE ker_skb_headers ker_eth_headers
        ker_receive_headers ker_neighbor_headers ker_tcp_create_port ker_icmpv4_view_port ker_icmp_echo_view_port ker_transport_receive_port
        ker_ipv4_view_port ker_udp_view_port ker_tcp_view_port ker_receive_port ker_skb_port
        ker_eth_port ker_neighbor_port ker_address_port ker_tx_export_port ker_tx_ring_port
        ker_rx_ring_port ker_linux_port ker_dpdk_port PkgConfig::DPDK Threads::Threads)
    add_test(NAME tcp-ip-options COMMAND ker-tcp-ip-options-test)
    set_tests_properties(tcp-ip-options PROPERTIES TIMEOUT 30)
    add_executable(ker-tcp-neighbor-create-test tcp-neighbor-create.c)
    target_include_directories(ker-tcp-neighbor-create-test PRIVATE "${PROJECT_SOURCE_DIR}/src")
    target_compile_definitions(ker-tcp-neighbor-create-test PRIVATE _GNU_SOURCE)
    target_link_libraries(ker-tcp-neighbor-create-test PRIVATE ker_skb_headers ker_eth_headers ker_neighbor_headers
        ker_timer_list_port ker_linux_port ker_dpdk_port ker_address_port ker_neighbor_port ker_skb_port
        ker_tx_export_port ker_tcp_create_port ker_tcp_neighbor_create_port ker_tcp_view_port ker_udp_view_port ker_ipv4_view_port
        ker_icmpv4_view_port ker_icmp_echo_view_port ker_transport_receive_port ker_receive_port ker_receive_headers ker_eth_port Threads::Threads)
    add_test(NAME tcp-neighbor-create COMMAND ker-tcp-neighbor-create-test)
    set_tests_properties(tcp-neighbor-create PROPERTIES TIMEOUT 30)
    add_executable(ker-udp-create-test udp-create.c)
    target_include_directories(ker-udp-create-test PRIVATE "${PROJECT_SOURCE_DIR}/src")
    target_compile_definitions(ker-udp-create-test PRIVATE _GNU_SOURCE)
    target_link_libraries(ker-udp-create-test PRIVATE ker_udp_create_port ker_icmpv4_view_port ker_icmp_echo_view_port ker_transport_receive_port
        ker_udp_view_port ker_tcp_view_port ker_ipv4_view_port ker_receive_port ker_receive_headers ker_eth_headers
        ker_eth_port ker_linux_port ker_dpdk_port ker_skb_port Threads::Threads)
    add_test(NAME udp-create COMMAND ker-udp-create-test)
    set_tests_properties(udp-create PROPERTIES TIMEOUT 30)
    add_executable(ker-udp-configured-create-test udp-configured-create.c)
    target_include_directories(ker-udp-configured-create-test PRIVATE "${PROJECT_SOURCE_DIR}/src" "${KER_ADDR_IMPORT}")
    target_compile_definitions(ker-udp-configured-create-test PRIVATE _GNU_SOURCE)
    target_link_libraries(ker-udp-configured-create-test PRIVATE ker_skb_headers ker_address_headers
        ker_udp_configured_create_port ker_udp_create_port ker_address_port
        ker_eth_port ker_linux_port ker_dpdk_port ker_skb_port Threads::Threads)
    add_test(NAME udp-configured-create COMMAND ker-udp-configured-create-test)
    set_tests_properties(udp-configured-create PROPERTIES TIMEOUT 30)
    add_executable(ker-tcp-configured-create-test tcp-configured-create.c)
    target_include_directories(ker-tcp-configured-create-test PRIVATE "${PROJECT_SOURCE_DIR}/src" "${KER_ADDR_IMPORT}")
    target_compile_definitions(ker-tcp-configured-create-test PRIVATE _GNU_SOURCE)
    target_link_libraries(ker-tcp-configured-create-test PRIVATE ker_skb_headers ker_address_headers
        ker_tcp_configured_create_port ker_tcp_create_port ker_address_port
        ker_eth_port ker_linux_port ker_dpdk_port ker_skb_port Threads::Threads)
    add_test(NAME tcp-configured-create COMMAND ker-tcp-configured-create-test)
    set_tests_properties(tcp-configured-create PROPERTIES TIMEOUT 30)
    add_executable(ker-icmp-echo-configured-create-test icmp-echo-configured-create.c)
    target_include_directories(ker-icmp-echo-configured-create-test PRIVATE "${PROJECT_SOURCE_DIR}/src" "${KER_ADDR_IMPORT}")
    target_compile_definitions(ker-icmp-echo-configured-create-test PRIVATE _GNU_SOURCE)
    target_link_libraries(ker-icmp-echo-configured-create-test PRIVATE ker_skb_headers ker_address_headers
        ker_icmp_echo_configured_create_port ker_icmp_echo_create_port ker_udp_configured_create_port
        ker_udp_create_port ker_tcp_configured_create_port ker_tcp_create_port ker_address_port
        ker_eth_port ker_linux_port ker_dpdk_port ker_skb_port Threads::Threads)
    add_test(NAME icmp-echo-configured-create COMMAND ker-icmp-echo-configured-create-test)
    set_tests_properties(icmp-echo-configured-create PROPERTIES TIMEOUT 30)
    add_executable(ker-udp-ip-options-test udp-ip-options.c)
    target_include_directories(ker-udp-ip-options-test PRIVATE "${PROJECT_SOURCE_DIR}/src")
    target_compile_definitions(ker-udp-ip-options-test PRIVATE _GNU_SOURCE)
    target_link_libraries(ker-udp-ip-options-test PRIVATE ker_skb_headers ker_eth_headers
        ker_receive_headers ker_neighbor_headers ker_udp_create_port ker_icmpv4_view_port ker_icmp_echo_view_port ker_transport_receive_port
        ker_ipv4_view_port ker_udp_view_port ker_tcp_view_port ker_receive_port ker_skb_port
        ker_eth_port ker_neighbor_port ker_address_port ker_tx_export_port ker_tx_ring_port
        ker_linux_port ker_dpdk_port PkgConfig::DPDK Threads::Threads)
    add_test(NAME udp-ip-options COMMAND ker-udp-ip-options-test)
    set_tests_properties(udp-ip-options PROPERTIES TIMEOUT 30)
    add_executable(ker-udp-neighbor-create-test udp-neighbor-create.c)
    target_link_libraries(ker-udp-neighbor-create-test PRIVATE ker_icmp_echo_neighbor_create_port ker_icmp_echo_create_port
        ker_tcp_neighbor_create_port ker_tcp_create_port)
    target_include_directories(ker-udp-neighbor-create-test PRIVATE "${PROJECT_SOURCE_DIR}/src")
    target_compile_definitions(ker-udp-neighbor-create-test PRIVATE _GNU_SOURCE)
    target_link_libraries(ker-udp-neighbor-create-test PRIVATE ker_neighbor_headers ker_address_port ker_neighbor_port
        ker_udp_neighbor_create_port ker_udp_create_port ker_icmpv4_view_port ker_icmp_echo_view_port ker_transport_receive_port ker_udp_view_port ker_tcp_view_port ker_ipv4_view_port
        ker_receive_port ker_receive_headers ker_eth_headers ker_eth_port ker_linux_port ker_dpdk_port
        ker_skb_port ker_tx_export_port Threads::Threads)
    add_test(NAME udp-neighbor-create COMMAND ker-udp-neighbor-create-test)
    set_tests_properties(udp-neighbor-create PROPERTIES TIMEOUT 30)
    add_test(NAME ethernet-import COMMAND "${Python3_EXECUTABLE}"
        "${CMAKE_CURRENT_SOURCE_DIR}/ethernet-import.py" "${PROJECT_SOURCE_DIR}"
        "${CMAKE_C_COMPILER}" "${KER_LINUX_INCLUDE}" "${KER_SKB_IMPORT}" ${DPDK_INCLUDE_DIRS})
    add_executable(ker-napi-test napi.c)
    target_compile_definitions(ker-napi-test PRIVATE _GNU_SOURCE)
    target_link_libraries(ker-napi-test PRIVATE ker_napi_headers ker_napi_port ker_eth_port
        ker_linux_port ker_dpdk_port ker_skb_port Threads::Threads)
    add_test(NAME napi COMMAND ker-napi-test)
    set_tests_properties(napi PROPERTIES TIMEOUT 30)
    add_test(NAME napi-import COMMAND "${Python3_EXECUTABLE}"
        "${CMAKE_CURRENT_SOURCE_DIR}/napi-import.py" "${PROJECT_SOURCE_DIR}"
        "${CMAKE_C_COMPILER}" "${KER_LINUX_INCLUDE}" "${KER_SKB_IMPORT}" "${KER_ETH_IMPORT}" ${DPDK_INCLUDE_DIRS})
    add_executable(ker-receive-test receive.c)
    target_compile_definitions(ker-receive-test PRIVATE _GNU_SOURCE)
    target_link_libraries(ker-receive-test PRIVATE ker_receive_headers ker_receive_port ker_napi_port
        ker_eth_port ker_linux_port ker_dpdk_port ker_skb_port Threads::Threads)
    add_test(NAME receive COMMAND ker-receive-test)
    set_tests_properties(receive PROPERTIES TIMEOUT 30)
    add_test(NAME receive-import COMMAND "${Python3_EXECUTABLE}"
        "${CMAKE_CURRENT_SOURCE_DIR}/receive-import.py" "${PROJECT_SOURCE_DIR}"
        "${CMAKE_C_COMPILER}" "${KER_LINUX_INCLUDE}" "${KER_SKB_IMPORT}" "${KER_ETH_IMPORT}" "${KER_NAPI_IMPORT}" ${DPDK_INCLUDE_DIRS})
    add_executable(ker-arp-test arp.c)
    target_compile_definitions(ker-arp-test PRIVATE _GNU_SOURCE)
    target_link_libraries(ker-arp-test PRIVATE ker_arp_headers ker_arp_port ker_receive_headers
        ker_receive_port ker_napi_port ker_eth_port ker_linux_port ker_dpdk_port ker_skb_port Threads::Threads)
    add_test(NAME arp COMMAND ker-arp-test)
    set_tests_properties(arp PROPERTIES TIMEOUT 30)
    add_executable(ker-arp-configured-test arp-configured.c)
    target_include_directories(ker-arp-configured-test PRIVATE "${PROJECT_SOURCE_DIR}/src")
    target_compile_definitions(ker-arp-configured-test PRIVATE _GNU_SOURCE)
    target_link_libraries(ker-arp-configured-test PRIVATE ker_arp_headers ker_arp_port
        ker_address_headers ker_address_port ker_eth_port ker_linux_port ker_dpdk_port ker_skb_port
        PkgConfig::DPDK Threads::Threads)
    add_test(NAME arp-configured COMMAND ker-arp-configured-test)
    set_tests_properties(arp-configured PROPERTIES TIMEOUT 30)
    add_test(NAME arp-import COMMAND "${Python3_EXECUTABLE}"
        "${CMAKE_CURRENT_SOURCE_DIR}/arp-import.py" "${PROJECT_SOURCE_DIR}"
        "${CMAKE_C_COMPILER}" "${KER_LINUX_INCLUDE}" "${KER_SKB_IMPORT}" "${KER_ETH_IMPORT}" ${DPDK_INCLUDE_DIRS})
    add_executable(ker-address-test ipv4-address.c)
    target_compile_definitions(ker-address-test PRIVATE _GNU_SOURCE)
    target_link_libraries(ker-address-test PRIVATE ker_address_headers ker_address_port ker_arp_headers
        ker_arp_port ker_receive_headers ker_receive_port ker_napi_port ker_eth_port
        ker_linux_port ker_dpdk_port ker_skb_port Threads::Threads)
    add_test(NAME ipv4-address COMMAND ker-address-test)
    set_tests_properties(ipv4-address PROPERTIES TIMEOUT 30)
    add_test(NAME address-import COMMAND "${Python3_EXECUTABLE}"
        "${CMAKE_CURRENT_SOURCE_DIR}/address-import.py" "${PROJECT_SOURCE_DIR}"
        "${CMAKE_C_COMPILER}" "${KER_LINUX_INCLUDE}" "${KER_SKB_IMPORT}" "${KER_ETH_IMPORT}" ${DPDK_INCLUDE_DIRS})
    add_executable(ker-neighbor-timer-test neighbor-timer.c)
    target_include_directories(ker-neighbor-timer-test PRIVATE "${KER_ARP_PROBE_IMPORT}" "${KER_NEIGH_UPDATE_IMPORT}" "${KER_NEIGH_EVENT_SEND_IMPORT}")
    target_compile_definitions(ker-neighbor-timer-test PRIVATE _GNU_SOURCE)
    target_link_libraries(ker-neighbor-timer-test PRIVATE ker_neighbor_timer_headers
        ker_neighbor_timer_port ker_timer_list_port ker_neighbor_port
        ker_neighbor_update_headers ker_neighbor_update_port ker_neighbor_event_send_headers ker_neighbor_event_send_port ker_address_port ker_arp_headers ker_arp_port ker_arp_probe_port ker_eth_port ker_linux_port ker_dpdk_port ker_skb_port Threads::Threads)
    target_link_libraries(ker-neighbor-timer-test PRIVATE ker_udp_create_port ker_udp_configured_create_port ker_tx_export_port)
    add_test(NAME neighbor-timer COMMAND ker-neighbor-timer-test)
    set_tests_properties(neighbor-timer PROPERTIES TIMEOUT 30)
    add_test(NAME neighbor-timer-import COMMAND "${Python3_EXECUTABLE}"
        "${CMAKE_CURRENT_SOURCE_DIR}/neighbor-timer-import.py" "${PROJECT_SOURCE_DIR}"
        "${CMAKE_C_COMPILER}" "${KER_LINUX_INCLUDE}" "${KER_SKB_IMPORT}" "${KER_ETH_IMPORT}"
        "${KER_ADDR_IMPORT}" "${KER_NAPI_IMPORT}" "${KER_NEIGH_IMPORT}" "${KER_TIMER_LIST_IMPORT}" ${DPDK_INCLUDE_DIRS})
    add_test(NAME arp-probe-import COMMAND "${Python3_EXECUTABLE}"
        "${CMAKE_CURRENT_SOURCE_DIR}/arp-probe-import.py" "${KER_LINUX_DIR}"
        "${KER_ARP_PROBE_MANIFEST}" "${KER_ARP_PROBE_IMPORT}"
        "${PROJECT_SOURCE_DIR}/tools/import-linux-arp-probe.py")
    add_test(NAME neighbor-update-import COMMAND "${Python3_EXECUTABLE}"
        "${CMAKE_CURRENT_SOURCE_DIR}/neighbor-update-import.py" "${KER_LINUX_DIR}"
        "${KER_NEIGH_UPDATE_MANIFEST}" "${KER_NEIGH_UPDATE_IMPORT}"
        "${PROJECT_SOURCE_DIR}/tools/import-linux-neighbor-update.py")
    add_test(NAME neighbor-event-send-import COMMAND "${Python3_EXECUTABLE}"
        "${CMAKE_CURRENT_SOURCE_DIR}/neighbor-event-send-import.py" "${KER_LINUX_DIR}"
        "${KER_NEIGH_EVENT_SEND_MANIFEST}" "${KER_NEIGH_EVENT_SEND_IMPORT}"
        "${PROJECT_SOURCE_DIR}/tools/import-linux-neighbor-event-send.py")
    add_test(NAME neighbor-output-import COMMAND "${Python3_EXECUTABLE}"
        "${CMAKE_CURRENT_SOURCE_DIR}/neighbor-output-import.py" "${KER_LINUX_DIR}"
        "${KER_NEIGH_OUTPUT_MANIFEST}" "${KER_NEIGH_OUTPUT_IMPORT}"
        "${PROJECT_SOURCE_DIR}/tools/import-linux-neighbor-output.py")
    add_executable(ker-neighbor-test neighbor.c)
    target_compile_definitions(ker-neighbor-test PRIVATE _GNU_SOURCE)
    target_link_libraries(ker-neighbor-test PRIVATE ker_neighbor_headers ker_neighbor_port ker_receive_headers
        ker_address_port ker_arp_headers ker_arp_port ker_receive_port ker_napi_port ker_eth_port
        ker_linux_port ker_dpdk_port ker_skb_port Threads::Threads)
    add_test(NAME neighbor COMMAND ker-neighbor-test)
    set_tests_properties(neighbor PROPERTIES TIMEOUT 30)
    add_test(NAME neighbor-import COMMAND "${Python3_EXECUTABLE}"
        "${CMAKE_CURRENT_SOURCE_DIR}/neighbor-import.py" "${PROJECT_SOURCE_DIR}"
        "${CMAKE_C_COMPILER}" "${KER_LINUX_INCLUDE}" "${KER_SKB_IMPORT}" "${KER_ETH_IMPORT}"
        "${KER_ADDR_IMPORT}" "${KER_NAPI_IMPORT}" ${DPDK_INCLUDE_DIRS})
    add_executable(ker-arp-receive-test arp-receive.c)
    target_include_directories(ker-arp-receive-test PRIVATE "${KER_NEIGH_UPDATE_IMPORT}")
    target_compile_definitions(ker-arp-receive-test PRIVATE _GNU_SOURCE)
    target_link_libraries(ker-arp-receive-test PRIVATE ker_arp_rx_headers ker_arp_rx_port
        ker_arp_neighbor_feedback_port ker_neighbor_timer_headers ker_neighbor_timer_port
        ker_neighbor_update_headers ker_neighbor_update_port ker_neighbor_event_send_port ker_timer_list_port ker_neighbor_port
        ker_address_port ker_arp_port ker_receive_port ker_napi_port ker_eth_port ker_tx_export_port
        ker_linux_port ker_dpdk_port ker_skb_port Threads::Threads)
    add_test(NAME arp-receive COMMAND ker-arp-receive-test)
    set_tests_properties(arp-receive PROPERTIES TIMEOUT 30)
    add_test(NAME arp-receive-import COMMAND "${Python3_EXECUTABLE}"
        "${CMAKE_CURRENT_SOURCE_DIR}/arp-receive-import.py" "${PROJECT_SOURCE_DIR}"
        "${CMAKE_C_COMPILER}" "${KER_LINUX_INCLUDE}" "${KER_SKB_IMPORT}" "${KER_ETH_IMPORT}"
        "${KER_NAPI_IMPORT}" "${KER_RX_IMPORT}" "${KER_ARP_IMPORT}" ${DPDK_INCLUDE_DIRS})
    add_executable(ker-fstack-arp-chain-test fstack-arp-chain.c)
    target_include_directories(ker-fstack-arp-chain-test PRIVATE "${KER_NEIGH_UPDATE_IMPORT}" "${KER_ARP_PROBE_IMPORT}")
    target_compile_definitions(ker-fstack-arp-chain-test PRIVATE _GNU_SOURCE)
    target_link_libraries(ker-fstack-arp-chain-test PRIVATE ker_arp_rx_headers ker_arp_rx_port
        ker_arp_neighbor_feedback_port ker_neighbor_timer_headers ker_neighbor_timer_port
        ker_neighbor_update_headers ker_neighbor_update_port ker_neighbor_event_send_port ker_timer_list_port
        ker_neighbor_port ker_address_port ker_arp_port ker_receive_port ker_napi_port ker_eth_port ker_tx_export_port
        ker_arp_probe_port ker_udp_create_port ker_udp_configured_create_port
        ker_linux_port ker_dpdk_port ker_skb_port Threads::Threads)
    add_test(NAME fstack-arp-chain-feedback COMMAND ker-fstack-arp-chain-test)
    set_tests_properties(fstack-arp-chain-feedback PROPERTIES TIMEOUT 30)
    add_executable(ker-arp-ring-test arp-ring.c)
    target_include_directories(ker-arp-ring-test PRIVATE "${KER_NEIGH_UPDATE_IMPORT}")
    target_compile_definitions(ker-arp-ring-test PRIVATE _GNU_SOURCE)
    target_link_libraries(ker-arp-ring-test PRIVATE ker_arp_rx_headers ker_arp_rx_port
        ker_arp_neighbor_feedback_port ker_neighbor_timer_headers ker_neighbor_timer_port
        ker_neighbor_update_headers ker_neighbor_update_port ker_neighbor_event_send_port ker_timer_list_port
        ker_neighbor_port ker_address_port ker_arp_port ker_receive_port ker_napi_port ker_eth_port
        ker_rx_ring_port ker_tx_export_port ker_tx_ring_port ker_linux_port ker_dpdk_port ker_skb_port Threads::Threads)
    add_test(NAME arp-ring COMMAND ker-arp-ring-test)
    set_tests_properties(arp-ring PROPERTIES TIMEOUT 30)
    add_executable(ker-arp-responder-test arp-responder.c)
    target_include_directories(ker-arp-responder-test PRIVATE "${PROJECT_SOURCE_DIR}/src"
        "${KER_NEIGH_UPDATE_IMPORT}")
    target_compile_definitions(ker-arp-responder-test PRIVATE _GNU_SOURCE)
    target_link_libraries(ker-arp-responder-test PRIVATE ker_arp_rx_headers ker_arp_rx_port ker_arp_responder_port ker_neighbor_headers
        ker_eth_headers ker_eth_port ker_address_port ker_arp_port ker_receive_port ker_transport_receive_port
        ker_ipv4_view_port ker_udp_view_port ker_tcp_view_port ker_icmpv4_view_port ker_icmp_echo_view_port
        ker_neighbor_timer_headers ker_neighbor_timer_port ker_neighbor_update_headers ker_neighbor_update_port
        ker_neighbor_event_send_port ker_timer_list_port ker_arp_neighbor_feedback_port ker_arp_probe_port
        ker_neighbor_port ker_rx_ring_port ker_tx_export_port ker_tx_ring_port ker_udp_configured_create_port
        ker_udp_create_port ker_linux_port ker_dpdk_port ker_skb_port PkgConfig::DPDK Threads::Threads)
    add_test(NAME arp-responder COMMAND ker-arp-responder-test)
    set_tests_properties(arp-responder PROPERTIES TIMEOUT 30)
    add_executable(ker-fstack-icmp-echo-service-test fstack-icmp-echo-service.c)
    target_include_directories(ker-fstack-icmp-echo-service-test PRIVATE "${PROJECT_SOURCE_DIR}/src"
        "${KER_NEIGH_UPDATE_IMPORT}")
    target_compile_definitions(ker-fstack-icmp-echo-service-test PRIVATE _GNU_SOURCE)
    target_link_libraries(ker-fstack-icmp-echo-service-test PRIVATE ker_arp_rx_headers ker_arp_rx_port
        ker_arp_responder_port ker_address_headers ker_address_port ker_neighbor_headers ker_neighbor_port
        ker_neighbor_timer_headers ker_neighbor_timer_port ker_neighbor_update_headers ker_neighbor_update_port
        ker_neighbor_event_send_port ker_timer_list_port ker_arp_neighbor_feedback_port ker_arp_probe_port
        ker_arp_port ker_receive_headers ker_receive_port ker_transport_receive_port ker_icmp_echo_service_port
        ker_eth_headers ker_eth_port ker_rx_ring_port ker_tx_export_port ker_tx_ring_port
        ker_ipv4_view_port ker_udp_view_port ker_tcp_view_port ker_icmpv4_view_port ker_icmp_echo_view_port
        ker_icmp_echo_configured_create_port ker_udp_configured_create_port ker_tcp_configured_create_port
        ker_icmp_echo_create_port ker_udp_create_port ker_tcp_create_port ker_skb_port ker_linux_port
        ker_dpdk_port PkgConfig::DPDK Threads::Threads)
    add_test(NAME fstack-icmp-echo-service COMMAND ker-fstack-icmp-echo-service-test)
    set_tests_properties(fstack-icmp-echo-service PROPERTIES TIMEOUT 30)

    add_executable(ker-icmpv4-service-test icmpv4-service.c)
    target_include_directories(ker-icmpv4-service-test PRIVATE "${PROJECT_SOURCE_DIR}/src"
        "${KER_NEIGH_UPDATE_IMPORT}")
    target_compile_definitions(ker-icmpv4-service-test PRIVATE _GNU_SOURCE)
    target_link_libraries(ker-icmpv4-service-test PRIVATE ker_arp_rx_headers ker_arp_rx_port
        ker_arp_responder_port ker_address_headers ker_address_port ker_neighbor_headers ker_neighbor_port
        ker_neighbor_timer_headers ker_neighbor_timer_port ker_neighbor_update_headers ker_neighbor_update_port
        ker_neighbor_event_send_port ker_timer_list_port ker_arp_neighbor_feedback_port ker_arp_probe_port
        ker_arp_port ker_receive_headers ker_receive_port ker_transport_receive_port ker_icmpv4_service_port
        ker_icmpv4_create_port ker_eth_headers ker_eth_port ker_rx_ring_port ker_tx_export_port ker_tx_ring_port
        ker_ipv4_view_port ker_udp_view_port ker_tcp_view_port ker_icmpv4_view_port ker_icmp_echo_view_port
        ker_udp_configured_create_port ker_tcp_configured_create_port ker_udp_create_port ker_tcp_create_port
        ker_icmp_echo_create_port ker_icmp_echo_configured_create_port ker_skb_port ker_linux_port
        ker_dpdk_port PkgConfig::DPDK Threads::Threads)
    add_test(NAME icmpv4-service COMMAND ker-icmpv4-service-test)
    set_tests_properties(icmpv4-service PROPERTIES TIMEOUT 30)
    add_executable(ker-arp-concurrent-ring-test arp-concurrent-ring.c)
    target_include_directories(ker-arp-concurrent-ring-test PRIVATE "${KER_NEIGH_UPDATE_IMPORT}")
    target_compile_definitions(ker-arp-concurrent-ring-test PRIVATE _GNU_SOURCE)
    target_link_libraries(ker-arp-concurrent-ring-test PRIVATE ker_arp_rx_headers ker_arp_rx_port
        ker_neighbor_headers ker_neighbor_port ker_address_port ker_arp_port ker_receive_port ker_napi_port ker_eth_port
        ker_rx_ring_port ker_tx_export_port ker_tx_ring_port ker_linux_port ker_dpdk_port ker_skb_port
        Threads::Threads)
    add_test(NAME arp-concurrent-ring COMMAND ker-arp-concurrent-ring-test)
    set_tests_properties(arp-concurrent-ring PROPERTIES TIMEOUT 30)
    add_executable(ker-configured-ring-test configured-ring.c)
    target_include_directories(ker-configured-ring-test PRIVATE "${PROJECT_SOURCE_DIR}/src"
        "${KER_ADDR_IMPORT}" "${KER_NEIGH_UPDATE_IMPORT}")
    target_compile_definitions(ker-configured-ring-test PRIVATE _GNU_SOURCE)
    target_link_libraries(ker-configured-ring-test PRIVATE ker_arp_rx_headers ker_arp_rx_port
        ker_address_headers ker_address_port ker_arp_port ker_receive_headers ker_receive_port
        ker_eth_headers ker_neighbor_headers ker_neighbor_port ker_timer_list_port
        ker_eth_port ker_rx_ring_port ker_tx_export_port ker_tx_ring_port
        ker_udp_configured_create_port ker_tcp_configured_create_port ker_icmp_echo_configured_create_port
        ker_udp_create_port ker_tcp_create_port ker_icmp_echo_create_port ker_transport_receive_port
        ker_ipv4_view_port ker_udp_view_port ker_tcp_view_port ker_icmpv4_view_port ker_icmp_echo_view_port
        ker_linux_port ker_dpdk_port ker_skb_port PkgConfig::DPDK Threads::Threads)
    add_test(NAME configured-ring COMMAND ker-configured-ring-test)
    set_tests_properties(configured-ring PROPERTIES TIMEOUT 30)
    add_executable(ker-timer-list-test timer-list.c)
    target_compile_definitions(ker-timer-list-test PRIVATE _GNU_SOURCE)
    target_link_libraries(ker-timer-list-test PRIVATE ker_timer_list_headers ker_timer_list_port
        ker_linux_port ker_dpdk_port Threads::Threads)
    add_test(NAME timer-list COMMAND ker-timer-list-test)
    set_tests_properties(timer-list PROPERTIES TIMEOUT 30)
    add_test(NAME timer-list-import COMMAND "${Python3_EXECUTABLE}"
        "${CMAKE_CURRENT_SOURCE_DIR}/timer-list-import.py" "${PROJECT_SOURCE_DIR}"
        "${CMAKE_C_COMPILER}" "${KER_LINUX_INCLUDE}" "${KER_SKB_IMPORT}" "${KER_ETH_IMPORT}" ${DPDK_INCLUDE_DIRS})
    add_executable(ker-skb-queue-test skb-queue.c)
    target_include_directories(ker-skb-queue-test PRIVATE "${PROJECT_SOURCE_DIR}/src")
    target_compile_definitions(ker-skb-queue-test PRIVATE _GNU_SOURCE)
    target_link_libraries(ker-skb-queue-test PRIVATE ker_tcp_view_port ker_udp_view_port ker_ipv4_view_port ker_neighbor_headers ker_neighbor_port
        ker_address_port ker_napi_port ker_eth_port ker_linux_port ker_dpdk_port ker_skb_port Threads::Threads)
    add_test(NAME skb-queue COMMAND ker-skb-queue-test)
    set_tests_properties(skb-queue PROPERTIES TIMEOUT 30)
    add_executable(ker-fstack-adapted-test fstack-adapted.c)
    target_compile_definitions(ker-fstack-adapted-test PRIVATE _GNU_SOURCE)
    target_link_libraries(ker-fstack-adapted-test PRIVATE ker_neighbor_headers ker_neighbor_port
        ker_receive_headers ker_receive_port ker_address_port ker_napi_port ker_eth_port
        ker_linux_port ker_dpdk_port ker_skb_port Threads::Threads)
    foreach(fstack_case mbuf-release clock-monotonic empty-export null-context packet-export
            multiseg-boundary queue-isolation queue-full-ownership export-exhaustion-retry
            offload-metadata-rejection headroom-export multiseg-copy multiseg-ethernet-ingress
            software-checksum-completion)
        add_test(NAME fstack-${fstack_case} COMMAND ker-fstack-adapted-test ${fstack_case})
        set_tests_properties(fstack-${fstack_case} PROPERTIES TIMEOUT 30)
        list(APPEND ker_fstack_tests fstack-${fstack_case})
    endforeach()
    add_test(NAME skb-import COMMAND "${Python3_EXECUTABLE}"
        "${CMAKE_CURRENT_SOURCE_DIR}/skb-import.py" "${PROJECT_SOURCE_DIR}"
        "${CMAKE_C_COMPILER}" "${KER_LINUX_INCLUDE}" ${DPDK_INCLUDE_DIRS})
    set_tests_properties(skb PROPERTIES TIMEOUT 30)
    set_tests_properties(dpdk-memory PROPERTIES TIMEOUT 30)
    list(JOIN DPDK_LIBRARY_DIRS ":" ker_dpdk_library_path)
    set_tests_properties(icmpv4-service checksum timer refcount dpdk-memory skb worker flow flow-buckets flow-chain flow-ip-options flow-icmpv4 fstack-flow-receive fstack-flow-owner-receive fstack-flow-concurrent-receive flow-matrix flow-multicore ethernet fstack-ipv4-ingress-validation fstack-udp-ingress-validation fstack-udp-minimal-boundaries fstack-tcp-ingress-validation ipv4-fields transport-receive icmp-echo icmp-echo-configured-create fstack-chain-export fstack-chain-checksum udp-create udp-configured-create tcp-configured-create udp-ip-options udp-neighbor-create tcp-create tcp-ip-options tcp-neighbor-create tcp-options napi receive arp arp-configured arp-ring arp-responder fstack-icmp-echo-service arp-concurrent-ring configured-ring ipv4-address neighbor-timer neighbor arp-receive fstack-arp-chain-feedback skb-queue timer-list arp-probe-import neighbor-update-import tx-export tx-export-chain tx-ring rx-ring flow-ring cross-worker-ring fstack-concurrent-ring ${ker_fstack_tests} PROPERTIES
        ENVIRONMENT "LD_LIBRARY_PATH=${ker_dpdk_library_path}:$ENV{LD_LIBRARY_PATH}")
endif()

if(KER_WITH_DPDK)
    add_executable(ker-tcp-control-test tcp-control.c)
    target_include_directories(ker-tcp-control-test PRIVATE "${PROJECT_SOURCE_DIR}/src")
    target_compile_definitions(ker-tcp-control-test PRIVATE _GNU_SOURCE)
    target_link_libraries(ker-tcp-control-test PRIVATE ker_skb_headers ker_eth_headers ker_neighbor_headers ker_timer_list_port ker_linux_port ker_dpdk_port ker_address_port ker_neighbor_port ker_skb_port ker_tx_export_port ker_tcp_create_port ker_tcp_view_port ker_udp_view_port ker_ipv4_view_port ker_icmpv4_view_port ker_icmp_echo_view_port ker_transport_receive_port ker_receive_port ker_receive_headers ker_eth_port Threads::Threads)
    target_link_libraries(ker-tcp-control-test PRIVATE ker_tcp_mss_port)
    add_test(NAME tcp-control COMMAND ker-tcp-control-test)
    set_tests_properties(tcp-control PROPERTIES TIMEOUT 30
        ENVIRONMENT "LD_LIBRARY_PATH=${ker_dpdk_library_path}:$ENV{LD_LIBRARY_PATH}")
    add_test(NAME tcp-mss-import COMMAND "${Python3_EXECUTABLE}"
        "${CMAKE_CURRENT_SOURCE_DIR}/tcp-mss-import.py" "${KER_LINUX_DIR}"
        "${KER_TCP_MSS_MANIFEST}" "${KER_TCP_MSS_IMPORT}"
        "${PROJECT_SOURCE_DIR}/tools/import-linux-tcp-mss.py")
endif()

# Inventory integrity is distinct from migrated networking behavior.
find_package(Python3 REQUIRED COMPONENTS Interpreter)
add_test(NAME fstack-migration-inventory
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/fstack_migration.py")
add_test(NAME fstack-migration-audit-guards
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/test_fstack_migration.py")
set_tests_properties(fstack-migration-inventory fstack-migration-audit-guards
    PROPERTIES TIMEOUT 30 LABELS "provenance")

# Fifty independently selectable F-Stack configuration regression scenarios.
# No native kernel, EAL, root privileges or PMD are required.
add_test(NAME fstack-config-ini-basic
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/posix/test_fstack_config_cases.py"
        SourceCases.test_ini_basic)
set_tests_properties(fstack-config-ini-basic PROPERTIES
    TIMEOUT 15 LABELS "fstack;fstack-config-cases" ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")
add_test(NAME fstack-config-ini-sections
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/posix/test_fstack_config_cases.py"
        SourceCases.test_ini_sections)
set_tests_properties(fstack-config-ini-sections PROPERTIES
    TIMEOUT 15 LABELS "fstack;fstack-config-cases" ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")
add_test(NAME fstack-config-ini-comments
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/posix/test_fstack_config_cases.py"
        SourceCases.test_ini_comments)
set_tests_properties(fstack-config-ini-comments PROPERTIES
    TIMEOUT 15 LABELS "fstack;fstack-config-cases" ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")
add_test(NAME fstack-config-ini-inline-comment
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/posix/test_fstack_config_cases.py"
        SourceCases.test_ini_inline_comment)
set_tests_properties(fstack-config-ini-inline-comment PROPERTIES
    TIMEOUT 15 LABELS "fstack;fstack-config-cases" ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")
add_test(NAME fstack-config-ini-whitespace
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/posix/test_fstack_config_cases.py"
        SourceCases.test_ini_whitespace)
set_tests_properties(fstack-config-ini-whitespace PROPERTIES
    TIMEOUT 15 LABELS "fstack;fstack-config-cases" ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")
add_test(NAME fstack-config-ini-empty-value
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/posix/test_fstack_config_cases.py"
        SourceCases.test_ini_empty_value)
set_tests_properties(fstack-config-ini-empty-value PROPERTIES
    TIMEOUT 15 LABELS "fstack;fstack-config-cases" ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")
add_test(NAME fstack-config-ini-invalid-syntax
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/posix/test_fstack_config_cases.py"
        SourceCases.test_ini_invalid_syntax)
set_tests_properties(fstack-config-ini-invalid-syntax PROPERTIES
    TIMEOUT 15 LABELS "fstack;fstack-config-cases" ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")
add_test(NAME fstack-config-ini-bom
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/posix/test_fstack_config_cases.py"
        SourceCases.test_ini_bom)
set_tests_properties(fstack-config-ini-bom PROPERTIES
    TIMEOUT 15 LABELS "fstack;fstack-config-cases" ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")
add_test(NAME fstack-config-ini-file
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/posix/test_fstack_config_cases.py"
        SourceCases.test_ini_file)
set_tests_properties(fstack-config-ini-file PROPERTIES
    TIMEOUT 15 LABELS "fstack;fstack-config-cases" ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")
add_test(NAME fstack-config-ini-missing-file
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/posix/test_fstack_config_cases.py"
        SourceCases.test_ini_missing_file)
set_tests_properties(fstack-config-ini-missing-file PROPERTIES
    TIMEOUT 15 LABELS "fstack;fstack-config-cases" ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")
add_test(NAME fstack-config-ini-filename
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/posix/test_fstack_config_cases.py"
        SourceCases.test_ini_filename)
set_tests_properties(fstack-config-ini-filename PROPERTIES
    TIMEOUT 15 LABELS "fstack;fstack-config-cases" ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")
add_test(NAME fstack-config-ini-long-key
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/posix/test_fstack_config_cases.py"
        SourceCases.test_ini_long_key)
set_tests_properties(fstack-config-ini-long-key PROPERTIES
    TIMEOUT 15 LABELS "fstack;fstack-config-cases" ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")
add_test(NAME fstack-config-ini-empty-stream
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/posix/test_fstack_config_cases.py"
        SourceCases.test_ini_empty_stream)
set_tests_properties(fstack-config-ini-empty-stream PROPERTIES
    TIMEOUT 15 LABELS "fstack;fstack-config-cases" ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")
add_test(NAME fstack-config-ini-unclosed-section
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/posix/test_fstack_config_cases.py"
        SourceCases.test_ini_unclosed_section)
set_tests_properties(fstack-config-ini-unclosed-section PROPERTIES
    TIMEOUT 15 LABELS "fstack;fstack-config-cases" ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")
add_test(NAME fstack-config-ini-no-final-newline
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/posix/test_fstack_config_cases.py"
        SourceCases.test_ini_no_final_newline)
set_tests_properties(fstack-config-ini-no-final-newline PROPERTIES
    TIMEOUT 15 LABELS "fstack;fstack-config-cases" ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")
add_test(NAME fstack-config-ini-colon
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/posix/test_fstack_config_cases.py"
        SourceCases.test_ini_colon)
set_tests_properties(fstack-config-ini-colon PROPERTIES
    TIMEOUT 15 LABELS "fstack;fstack-config-cases" ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")
add_test(NAME fstack-config-ini-bare-line
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/posix/test_fstack_config_cases.py"
        SourceCases.test_ini_bare_line)
set_tests_properties(fstack-config-ini-bare-line PROPERTIES
    TIMEOUT 15 LABELS "fstack;fstack-config-cases" ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")
add_test(NAME fstack-config-ini-partial-bom
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/posix/test_fstack_config_cases.py"
        SourceCases.test_ini_partial_bom)
set_tests_properties(fstack-config-ini-partial-bom PROPERTIES
    TIMEOUT 15 LABELS "fstack;fstack-config-cases" ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")
add_test(NAME fstack-config-ini-bom-mismatch
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/posix/test_fstack_config_cases.py"
        SourceCases.test_ini_bom_mismatch)
set_tests_properties(fstack-config-ini-bom-mismatch PROPERTIES
    TIMEOUT 15 LABELS "fstack;fstack-config-cases" ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")
add_test(NAME fstack-config-no-dpdk
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/posix/test_fstack_config_cases.py"
        SourceCases.test_config_no_dpdk)
set_tests_properties(fstack-config-no-dpdk PROPERTIES
    TIMEOUT 15 LABELS "fstack;fstack-config-cases" ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")
add_test(NAME fstack-config-bad-lcore
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/posix/test_fstack_config_cases.py"
        SourceCases.test_config_bad_lcore)
set_tests_properties(fstack-config-bad-lcore PROPERTIES
    TIMEOUT 15 LABELS "fstack;fstack-config-cases" ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")
add_test(NAME fstack-config-dual-vlan
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/posix/test_fstack_config_cases.py"
        SourceCases.test_config_dual_vlan)
set_tests_properties(fstack-config-dual-vlan PROPERTIES
    TIMEOUT 15 LABELS "fstack;fstack-config-cases" ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")
add_test(NAME fstack-config-vip
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/posix/test_fstack_config_cases.py"
        SourceCases.test_config_vip)
set_tests_properties(fstack-config-vip PROPERTIES
    TIMEOUT 15 LABELS "fstack;fstack-config-cases" ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")
add_test(NAME fstack-config-cli-override
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/posix/test_fstack_config_cases.py"
        SourceCases.test_config_cli_override)
set_tests_properties(fstack-config-cli-override PROPERTIES
    TIMEOUT 15 LABELS "fstack;fstack-config-cases" ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")
add_test(NAME fstack-config-empty
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/posix/test_fstack_config_cases.py"
        SourceCases.test_config_empty)
set_tests_properties(fstack-config-empty PROPERTIES
    TIMEOUT 15 LABELS "fstack;fstack-config-cases" ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")
add_test(NAME fstack-config-missing-path
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/posix/test_fstack_config_cases.py"
        SourceCases.test_config_missing_path)
set_tests_properties(fstack-config-missing-path PROPERTIES
    TIMEOUT 15 LABELS "fstack;fstack-config-cases" ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")
# Ker-only EAL forwarding coverage; intentionally not linked to an upstream case.
add_test(NAME fstack-config-eal-process-type-forwarding
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/posix/test_fstack_config_cases.py"
        SourceCases.test_eal_process_type_forwarding)
set_tests_properties(fstack-config-eal-process-type-forwarding PROPERTIES
    TIMEOUT 15 LABELS "fstack;fstack-config-cases" ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")
add_test(NAME fstack-config-address
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/posix/test_fstack_config_cases.py"
        SourceCases.test_config_address)
set_tests_properties(fstack-config-address PROPERTIES
    TIMEOUT 15 LABELS "fstack;fstack-config-cases" ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")
add_test(NAME fstack-config-zero-lcore
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/posix/test_fstack_config_cases.py"
        SourceCases.test_config_zero_lcore)
set_tests_properties(fstack-config-zero-lcore PROPERTIES
    TIMEOUT 15 LABELS "fstack;fstack-config-cases" ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")
add_test(NAME fstack-config-bond-without-count
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/posix/test_fstack_config_cases.py"
        SourceCases.test_config_bond_without_count)
set_tests_properties(fstack-config-bond-without-count PROPERTIES
    TIMEOUT 15 LABELS "fstack;fstack-config-cases" ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")
add_test(NAME fstack-config-bond-bad-index
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/posix/test_fstack_config_cases.py"
        SourceCases.test_config_bond_bad_index)
set_tests_properties(fstack-config-bond-bad-index PROPERTIES
    TIMEOUT 15 LABELS "fstack;fstack-config-cases" ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")
add_test(NAME fstack-config-uppercase-lcore
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/posix/test_fstack_config_cases.py"
        SourceCases.test_config_uppercase_lcore)
set_tests_properties(fstack-config-uppercase-lcore PROPERTIES
    TIMEOUT 15 LABELS "fstack;fstack-config-cases" ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")
add_test(NAME fstack-config-vlan-bad-index
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/posix/test_fstack_config_cases.py"
        SourceCases.test_config_vlan_bad_index)
set_tests_properties(fstack-config-vlan-bad-index PROPERTIES
    TIMEOUT 15 LABELS "fstack;fstack-config-cases" ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")
add_test(NAME fstack-config-vdev-without-count
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/posix/test_fstack_config_cases.py"
        SourceCases.test_config_vdev_without_count)
set_tests_properties(fstack-config-vdev-without-count PROPERTIES
    TIMEOUT 15 LABELS "fstack;fstack-config-cases" ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")
add_test(NAME fstack-config-interface-bad-name
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/posix/test_fstack_config_cases.py"
        SourceCases.test_config_interface_bad_name)
set_tests_properties(fstack-config-interface-bad-name PROPERTIES
    TIMEOUT 15 LABELS "fstack;fstack-config-cases" ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")
add_test(NAME fstack-config-repeat-keys
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/posix/test_fstack_config_cases.py"
        SourceCases.test_config_repeat_keys)
set_tests_properties(fstack-config-repeat-keys PROPERTIES
    TIMEOUT 15 LABELS "fstack;fstack-config-cases" ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")
add_test(NAME fstack-config-multibit-lcore
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/posix/test_fstack_config_cases.py"
        SourceCases.test_config_multibit_lcore)
set_tests_properties(fstack-config-multibit-lcore PROPERTIES
    TIMEOUT 15 LABELS "fstack;fstack-config-cases" ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")
add_test(NAME fstack-config-blank-lcore
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/posix/test_fstack_config_cases.py"
        SourceCases.test_config_blank_lcore)
set_tests_properties(fstack-config-blank-lcore PROPERTIES
    TIMEOUT 15 LABELS "fstack;fstack-config-cases" ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")
add_test(NAME fstack-config-mid-nonhex-lcore
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/posix/test_fstack_config_cases.py"
        SourceCases.test_config_mid_nonhex_lcore)
set_tests_properties(fstack-config-mid-nonhex-lcore PROPERTIES
    TIMEOUT 15 LABELS "fstack;fstack-config-cases" ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")
add_test(NAME fstack-config-vlan-vips
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/posix/test_fstack_config_cases.py"
        SourceCases.test_config_vlan_vips)
set_tests_properties(fstack-config-vlan-vips PROPERTIES
    TIMEOUT 15 LABELS "fstack;fstack-config-cases" ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")
add_test(NAME fstack-config-exception-reject
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/posix/test_fstack_config_cases.py"
        SourceCases.test_config_exception_reject)
set_tests_properties(fstack-config-exception-reject PROPERTIES
    TIMEOUT 15 LABELS "fstack;fstack-config-cases" ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")
add_test(NAME fstack-config-exception-invalid
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/posix/test_fstack_config_cases.py"
        SourceCases.test_config_exception_invalid)
set_tests_properties(fstack-config-exception-invalid PROPERTIES
    TIMEOUT 15 LABELS "fstack;fstack-config-cases" ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")
add_test(NAME fstack-config-mtu-defaults
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/posix/test_fstack_config_cases.py"
        SourceCases.test_config_mtu_defaults)
set_tests_properties(fstack-config-mtu-defaults PROPERTIES
    TIMEOUT 15 LABELS "fstack;fstack-config-cases" ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")
add_test(NAME fstack-config-jumbo
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/posix/test_fstack_config_cases.py"
        SourceCases.test_config_jumbo)
set_tests_properties(fstack-config-jumbo PROPERTIES
    TIMEOUT 15 LABELS "fstack;fstack-config-cases" ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")
add_test(NAME fstack-config-scatter
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/posix/test_fstack_config_cases.py"
        SourceCases.test_config_scatter)
set_tests_properties(fstack-config-scatter PROPERTIES
    TIMEOUT 15 LABELS "fstack;fstack-config-cases" ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")
add_test(NAME fstack-config-bad-storage-mode
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/posix/test_fstack_config_cases.py"
        SourceCases.test_config_bad_storage_mode)
set_tests_properties(fstack-config-bad-storage-mode PROPERTIES
    TIMEOUT 15 LABELS "fstack;fstack-config-cases" ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")
add_test(NAME fstack-config-nonnumeric-ceiling
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/posix/test_fstack_config_cases.py"
        SourceCases.test_config_nonnumeric_ceiling)
set_tests_properties(fstack-config-nonnumeric-ceiling PROPERTIES
    TIMEOUT 15 LABELS "fstack;fstack-config-cases" ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")
add_test(NAME fstack-config-over-ceiling
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/posix/test_fstack_config_cases.py"
        SourceCases.test_config_over_ceiling)
set_tests_properties(fstack-config-over-ceiling PROPERTIES
    TIMEOUT 15 LABELS "fstack;fstack-config-cases" ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")
add_test(NAME fstack-config-disabled-jumbo
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/posix/test_fstack_config_cases.py"
        SourceCases.test_config_disabled_jumbo)
set_tests_properties(fstack-config-disabled-jumbo PROPERTIES
    TIMEOUT 15 LABELS "fstack;fstack-config-cases" ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")
add_test(NAME fstack-config-oversized-jumbo
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/posix/test_fstack_config_cases.py"
        SourceCases.test_config_oversized_jumbo)
set_tests_properties(fstack-config-oversized-jumbo PROPERTIES
    TIMEOUT 15 LABELS "fstack;fstack-config-cases" ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")

# Exact callback behavior missing from the strict launcher INI schema.
add_executable(ker-fstack-ini-callback-test fstack-ini-callback.c)
target_link_libraries(ker-fstack-ini-callback-test PRIVATE ker::ini)
target_compile_options(ker-fstack-ini-callback-test PRIVATE -Wall -Wextra -Werror)
add_test(NAME fstack-ini-callback-no-section COMMAND ker-fstack-ini-callback-test no-section)
set_tests_properties(fstack-ini-callback-no-section PROPERTIES TIMEOUT 15 LABELS "fstack;fstack-newly-adapted")
add_test(NAME fstack-ini-callback-handler-rejection COMMAND ker-fstack-ini-callback-test handler-rejection)
set_tests_properties(fstack-ini-callback-handler-rejection PROPERTIES TIMEOUT 15 LABELS "fstack;fstack-newly-adapted")
add_test(NAME fstack-ini-callback-null-file COMMAND ker-fstack-ini-callback-test null-file)
set_tests_properties(fstack-ini-callback-null-file PROPERTIES TIMEOUT 15 LABELS "fstack;fstack-newly-adapted")
add_test(NAME fstack-ini-callback-long-section COMMAND ker-fstack-ini-callback-test long-section)
set_tests_properties(fstack-ini-callback-long-section PROPERTIES TIMEOUT 15 LABELS "fstack;fstack-newly-adapted")
add_test(NAME fstack-ini-callback-user-data COMMAND ker-fstack-ini-callback-test user-data)
set_tests_properties(fstack-ini-callback-user-data PROPERTIES TIMEOUT 15 LABELS "fstack;fstack-newly-adapted")
add_test(NAME fstack-ini-callback-multiline COMMAND ker-fstack-ini-callback-test multiline)
set_tests_properties(fstack-ini-callback-multiline PROPERTIES TIMEOUT 15 LABELS "fstack;fstack-newly-adapted")
add_test(NAME fstack-ini-import COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/ini-import.py")
set_tests_properties(fstack-ini-import PROPERTIES TIMEOUT 15 LABELS "provenance")
add_test(NAME fstack-ipc-import COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/ipc-import.py")
set_tests_properties(fstack-ipc-import PROPERTIES TIMEOUT 15 LABELS "provenance")
add_test(NAME fstack-reload-import COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/reload-import.py")
set_tests_properties(fstack-reload-import PROPERTIES TIMEOUT 15 LABELS "provenance")

if(KER_WITH_DPDK)
    add_executable(ker-fstack-ipc-test fstack-ipc.c)
    target_link_libraries(ker-fstack-ipc-test PRIVATE ker::ipc Threads::Threads)
    target_compile_options(ker-fstack-ipc-test PRIVATE -Wall -Wextra -Werror)
    add_executable(ker-fstack-ipc-stash-test fstack-ipc-stash-origin.c)
    target_link_libraries(ker-fstack-ipc-stash-test PRIVATE ker-ipc-test-adapter)
    target_compile_options(ker-fstack-ipc-stash-test PRIVATE -Wall -Wextra -Werror)
    string(JOIN ":" ker_ipc_test_libraries ${DPDK_LIBRARY_DIRS})
    add_test(NAME fstack-ipc-stash-origin COMMAND ker-fstack-ipc-stash-test)
    set_tests_properties(fstack-ipc-stash-origin PROPERTIES TIMEOUT 15 LABELS "fstack;fstack-ipc;fstack-newly-adapted"
        ENVIRONMENT "LD_LIBRARY_PATH=${ker_ipc_test_libraries}:$ENV{LD_LIBRARY_PATH}")
    add_test(NAME fstack-ipc-process COMMAND ker-fstack-ipc-test process)
    set_tests_properties(fstack-ipc-process PROPERTIES TIMEOUT 15 LABELS "fstack;fstack-ipc;fstack-newly-adapted"
        ENVIRONMENT "LD_LIBRARY_PATH=${ker_ipc_test_libraries}:$ENV{LD_LIBRARY_PATH}")
    add_test(NAME fstack-ipc-generation COMMAND ker-fstack-ipc-test generation)
    set_tests_properties(fstack-ipc-generation PROPERTIES TIMEOUT 15 LABELS "fstack;fstack-ipc;fstack-newly-adapted"
        ENVIRONMENT "LD_LIBRARY_PATH=${ker_ipc_test_libraries}:$ENV{LD_LIBRARY_PATH}")
    add_test(NAME fstack-ipc-generation-epoch COMMAND ker-fstack-ipc-test generation-epoch)
    set_tests_properties(fstack-ipc-generation-epoch PROPERTIES TIMEOUT 15 LABELS "fstack;fstack-ipc;fstack-newly-adapted"
        ENVIRONMENT "LD_LIBRARY_PATH=${ker_ipc_test_libraries}:$ENV{LD_LIBRARY_PATH}")
    add_test(NAME fstack-ipc-coordinate COMMAND ker-fstack-ipc-test coordinate)
    set_tests_properties(fstack-ipc-coordinate PROPERTIES TIMEOUT 15 LABELS "fstack;fstack-ipc;fstack-newly-adapted"
        ENVIRONMENT "LD_LIBRARY_PATH=${ker_ipc_test_libraries}:$ENV{LD_LIBRARY_PATH}")
    add_test(NAME fstack-ipc-generation-option-epoch COMMAND ker-fstack-ipc-test generation-option-epoch)
    set_tests_properties(fstack-ipc-generation-option-epoch PROPERTIES TIMEOUT 15 LABELS "fstack;fstack-ipc;fstack-newly-adapted"
        ENVIRONMENT "LD_LIBRARY_PATH=${ker_ipc_test_libraries}:$ENV{LD_LIBRARY_PATH}")
    add_test(NAME fstack-ipc-generation-option COMMAND ker-fstack-ipc-test generation-option)
    set_tests_properties(fstack-ipc-generation-option PROPERTIES TIMEOUT 15 LABELS "fstack;fstack-ipc;fstack-newly-adapted"
        ENVIRONMENT "LD_LIBRARY_PATH=${ker_ipc_test_libraries}:$ENV{LD_LIBRARY_PATH}")
    add_test(NAME fstack-ipc-malformed COMMAND ker-fstack-ipc-test malformed)
    set_tests_properties(fstack-ipc-malformed PROPERTIES TIMEOUT 15 LABELS "fstack;fstack-ipc;fstack-newly-adapted"
        ENVIRONMENT "LD_LIBRARY_PATH=${ker_ipc_test_libraries}:$ENV{LD_LIBRARY_PATH}")
    add_test(NAME fstack-ipc-own-reply COMMAND ker-fstack-ipc-test own-reply)
    set_tests_properties(fstack-ipc-own-reply PROPERTIES TIMEOUT 15 LABELS "fstack;fstack-ipc;fstack-newly-adapted"
        ENVIRONMENT "LD_LIBRARY_PATH=${ker_ipc_test_libraries}:$ENV{LD_LIBRARY_PATH}")
    add_test(NAME fstack-ipc-foreign-live COMMAND ker-fstack-ipc-test foreign-live)
    set_tests_properties(fstack-ipc-foreign-live PROPERTIES TIMEOUT 15 LABELS "fstack;fstack-ipc;fstack-newly-adapted"
        ENVIRONMENT "LD_LIBRARY_PATH=${ker_ipc_test_libraries}:$ENV{LD_LIBRARY_PATH}")
    add_test(NAME fstack-ipc-foreign-no-send COMMAND ker-fstack-ipc-test foreign-no-send)
    set_tests_properties(fstack-ipc-foreign-no-send PROPERTIES TIMEOUT 15 LABELS "fstack;fstack-ipc;fstack-newly-adapted"
        ENVIRONMENT "LD_LIBRARY_PATH=${ker_ipc_test_libraries}:$ENV{LD_LIBRARY_PATH}")
    add_test(NAME fstack-ipc-orphan COMMAND ker-fstack-ipc-test orphan)
    set_tests_properties(fstack-ipc-orphan PROPERTIES TIMEOUT 15 LABELS "fstack;fstack-ipc;fstack-newly-adapted"
        ENVIRONMENT "LD_LIBRARY_PATH=${ker_ipc_test_libraries}:$ENV{LD_LIBRARY_PATH}")
    add_test(NAME fstack-ipc-probe COMMAND ker-fstack-ipc-test probe)
    set_tests_properties(fstack-ipc-probe PROPERTIES TIMEOUT 15 LABELS "fstack;fstack-ipc;fstack-newly-adapted"
        ENVIRONMENT "LD_LIBRARY_PATH=${ker_ipc_test_libraries}:$ENV{LD_LIBRARY_PATH}")
endif()
if(KER_WITH_DPDK)
    add_test(NAME fstack-ipc-epoch-names COMMAND ker-fstack-ipc-test epoch-names)
    add_test(NAME fstack-ipc-legacy-names COMMAND ker-fstack-ipc-test legacy-names)
    set_tests_properties(fstack-ipc-epoch-names fstack-ipc-legacy-names PROPERTIES
        TIMEOUT 15 LABELS "fstack;fstack-ipc;fstack-newly-adapted"
        ENVIRONMENT "LD_LIBRARY_PATH=${ker_ipc_test_libraries}:$ENV{LD_LIBRARY_PATH}")
    add_executable(ker-fstack-ipc-multiprocess-test fstack-ipc-multiprocess.c)
    target_link_libraries(ker-fstack-ipc-multiprocess-test PRIVATE ker::reload)
    target_compile_options(ker-fstack-ipc-multiprocess-test PRIVATE -Wall -Wextra -Werror)
    list(GET DPDK_LIBRARY_DIRS 0 ker_ipc_pmd_root)
    add_test(NAME fstack-ipc-multiprocess
        COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/posix/fstack-ipc-multiprocess.py"
            --app "$<TARGET_FILE:ker-fstack-ipc-multiprocess-test>"
            --unit-app "$<TARGET_FILE:ker-fstack-ipc-test>" --reload-app "$<TARGET_FILE:ker-fstack-reload-test>" --pmd-root "${ker_ipc_pmd_root}")
    set_tests_properties(fstack-ipc-multiprocess PROPERTIES TIMEOUT 180 SKIP_RETURN_CODE 77
        LABELS "fstack;fstack-ipc;multiprocess")
endif()

if(KER_WITH_DPDK)
    add_executable(ker-fstack-reload-test fstack-reload.c)
    target_link_libraries(ker-fstack-reload-test PRIVATE ker::reload)
    target_compile_options(ker-fstack-reload-test PRIVATE -Wall -Wextra -Werror)
    add_test(NAME fstack-reload-message-serdes COMMAND ker-fstack-reload-test)
    set_tests_properties(fstack-reload-message-serdes PROPERTIES TIMEOUT 15
        LABELS "fstack;fstack-reload;fstack-newly-adapted"
        ENVIRONMENT "LD_LIBRARY_PATH=${ker_ipc_test_libraries}:$ENV{LD_LIBRARY_PATH}")
endif()

if(KER_WITH_DPDK)
    add_executable(ker-fstack-reload-poll-test fstack-reload-poll.c)
    target_link_libraries(ker-fstack-reload-poll-test PRIVATE ker::reload)
    target_compile_options(ker-fstack-reload-poll-test PRIVATE -Wall -Wextra -Werror)
    add_test(NAME fstack-reload-markers COMMAND ker-fstack-reload-poll-test markers)
    add_test(NAME fstack-reload-barrier COMMAND ker-fstack-reload-poll-test barrier)
    set_tests_properties(fstack-reload-markers fstack-reload-barrier PROPERTIES TIMEOUT 15
        LABELS "fstack;fstack-reload;fstack-newly-adapted"
        ENVIRONMENT "LD_LIBRARY_PATH=${ker_ipc_test_libraries}:$ENV{LD_LIBRARY_PATH}")
    find_library(ker_reload_ring_pmd NAMES rte_net_ring HINTS ${DPDK_LIBRARY_DIRS} NO_DEFAULT_PATH REQUIRED)
    add_executable(ker-fstack-reload-multiprocess-test fstack-reload-multiprocess.c)
    target_link_libraries(ker-fstack-reload-multiprocess-test PRIVATE ker::reload "${ker_reload_ring_pmd}")
    target_compile_options(ker-fstack-reload-multiprocess-test PRIVATE -Wall -Wextra -Werror)
    add_test(NAME fstack-reload-multiprocess
        COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/posix/fstack-reload-multiprocess.py"
            --app "$<TARGET_FILE:ker-fstack-reload-multiprocess-test>"
            --unit-app "$<TARGET_FILE:ker-fstack-reload-poll-test>" --heartbeat-app "$<TARGET_FILE:ker-fstack-reload-heartbeat-test>" --pmd-root "${ker_ipc_pmd_root}")
    set_tests_properties(fstack-reload-multiprocess PROPERTIES TIMEOUT 180 SKIP_RETURN_CODE 77
        LABELS "fstack;fstack-reload;multiprocess")
endif()

if(KER_WITH_DPDK)
    add_executable(ker-fstack-reload-heartbeat-test fstack-reload-heartbeat.c)
    target_include_directories(ker-fstack-reload-heartbeat-test PRIVATE "${PROJECT_SOURCE_DIR}/third_party/fstack-ipc")
    target_link_libraries(ker-fstack-reload-heartbeat-test PRIVATE ker::reload)
    target_compile_options(ker-fstack-reload-heartbeat-test PRIVATE -Wall -Wextra -Werror)
    add_test(NAME fstack-reload-heartbeat COMMAND ker-fstack-reload-heartbeat-test)
    set_tests_properties(fstack-reload-heartbeat PROPERTIES TIMEOUT 15 LABELS "fstack;fstack-reload;fstack-newly-adapted"
        ENVIRONMENT "LD_LIBRARY_PATH=${ker_ipc_test_libraries}:$ENV{LD_LIBRARY_PATH}")
endif()

if(KER_WITH_DPDK)
    add_executable(ker-fstack-reload-controller-test fstack-reload-controller.c)
    target_link_libraries(ker-fstack-reload-controller-test PRIVATE ker-example-reload-policy)
    target_compile_options(ker-fstack-reload-controller-test PRIVATE -Wall -Wextra -Werror)
    add_test(NAME fstack-reload-fsm-transitions COMMAND ker-fstack-reload-controller-test transitions)
    add_test(NAME fstack-reload-fsm-legal COMMAND ker-fstack-reload-controller-test legal)
    add_test(NAME fstack-reload-fsm-illegal COMMAND ker-fstack-reload-controller-test illegal)
    add_test(NAME fstack-reload-fsm-recovery COMMAND ker-fstack-reload-controller-test recovery)
    set_tests_properties(fstack-reload-fsm-transitions fstack-reload-fsm-legal
        fstack-reload-fsm-illegal fstack-reload-fsm-recovery PROPERTIES TIMEOUT 15
        LABELS "fstack;fstack-reload;fstack-newly-adapted"
        ENVIRONMENT "LD_LIBRARY_PATH=${ker_ipc_test_libraries}:$ENV{LD_LIBRARY_PATH}")
    add_test(NAME fstack-reload-controller
        COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/posix/fstack-reload-controller.py"
            --app "$<TARGET_FILE:ker-reload-controller>"
            --unit-app "$<TARGET_FILE:ker-fstack-reload-controller-test>" --pmd-root "${ker_ipc_pmd_root}")
    set_tests_properties(fstack-reload-controller PROPERTIES TIMEOUT 180 SKIP_RETURN_CODE 77
        LABELS "fstack;fstack-reload;multiprocess")
endif()
add_test(NAME fstack-reload-controller-import
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/reload-controller-import.py")
set_tests_properties(fstack-reload-controller-import PROPERTIES TIMEOUT 15 LABELS provenance)

add_test(NAME fstack-pool-import COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/pool-import.py")
set_tests_properties(fstack-pool-import PROPERTIES TIMEOUT 15 LABELS provenance)
add_executable(ker-fstack-address-policy-test fstack-address-policy.c)
add_test(NAME fstack-address-policy-import COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/address-policy-import.py")
set_tests_properties(fstack-address-policy-import PROPERTIES TIMEOUT 15 LABELS provenance)
add_test(NAME fstack-packet-dispatcher-import COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/packet-dispatcher-import.py")
set_tests_properties(fstack-packet-dispatcher-import PROPERTIES TIMEOUT 15 LABELS provenance)
add_test(NAME fstack-reload-live-slot-import COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/reload-live-slot-import.py")
set_tests_properties(fstack-reload-live-slot-import PROPERTIES TIMEOUT 15 LABELS provenance)
target_link_libraries(ker-fstack-address-policy-test PRIVATE ker::address_policy)
target_compile_options(ker-fstack-address-policy-test PRIVATE -Wall -Wextra -Werror)
add_executable(ker-address-policy-lifetime-test address-policy-lifetime.c)
target_link_libraries(ker-address-policy-lifetime-test PRIVATE ker::address_policy Threads::Threads)
target_compile_options(ker-address-policy-lifetime-test PRIVATE -Wall -Wextra -Werror)
add_test(NAME fstack-address-policy-lifetime COMMAND ker-address-policy-lifetime-test)
set_tests_properties(fstack-address-policy-lifetime PROPERTIES TIMEOUT 10 LABELS fstack)
add_test(NAME fstack-address-policy-register COMMAND ker-fstack-address-policy-test register)
add_test(NAME fstack-address-policy-default COMMAND ker-fstack-address-policy-test default)
add_test(NAME fstack-address-policy-ipv4 COMMAND ker-fstack-address-policy-test ipv4)
add_test(NAME fstack-address-policy-ipv6 COMMAND ker-fstack-address-policy-test ipv6)
set_tests_properties(fstack-address-policy-register fstack-address-policy-default
    fstack-address-policy-ipv4 fstack-address-policy-ipv6 PROPERTIES TIMEOUT 10 LABELS fstack)
if(KER_WITH_DPDK)
    add_executable(ker-fstack-pool-test fstack-pools.c)
    add_executable(ker-fstack-dispatcher-test fstack-packet-dispatcher.c)
    add_executable(ker-packet-dispatcher-pmd-test packet-dispatcher-pmd.c)
    target_link_libraries(ker-packet-dispatcher-pmd-test PRIVATE ker::packet_dispatcher "${ker_reload_ring_pmd}")
    target_compile_options(ker-packet-dispatcher-pmd-test PRIVATE -Wall -Wextra -Werror)
    add_executable(ker-packet-dispatcher-lifetime-test packet-dispatcher-lifetime.c)
    target_link_libraries(ker-packet-dispatcher-lifetime-test PRIVATE ker::packet_dispatcher Threads::Threads)
    target_compile_options(ker-packet-dispatcher-lifetime-test PRIVATE -Wall -Wextra -Werror)
    add_test(NAME fstack-packet-dispatcher-lifetime COMMAND ker-packet-dispatcher-lifetime-test)
    set_tests_properties(fstack-packet-dispatcher-lifetime PROPERTIES TIMEOUT 10 LABELS fstack)
    add_test(NAME fstack-packet-dispatcher-pmd COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/posix/packet-dispatcher-pmd.py"
        --app "$<TARGET_FILE:ker-packet-dispatcher-pmd-test>" --pmd-root "${ker_ipc_pmd_root}")
    set_tests_properties(fstack-packet-dispatcher-pmd PROPERTIES TIMEOUT 45 LABELS fstack)
    target_link_libraries(ker-fstack-dispatcher-test PRIVATE ker::packet_dispatcher)
    target_compile_options(ker-fstack-dispatcher-test PRIVATE -Wall -Wextra -Werror)
    add_test(NAME fstack-packet-dispatcher-plain COMMAND ker-fstack-dispatcher-test plain)
    add_test(NAME fstack-packet-dispatcher-context COMMAND ker-fstack-dispatcher-test context)
    add_test(NAME fstack-packet-dispatcher-unregister COMMAND ker-fstack-dispatcher-test unregister)
    set_tests_properties(fstack-packet-dispatcher-plain fstack-packet-dispatcher-context
        fstack-packet-dispatcher-unregister PROPERTIES TIMEOUT 10 LABELS fstack)
    get_target_property(ker_pool_private_definitions ker-pools COMPILE_DEFINITIONS)
    get_target_property(ker_pool_private_includes ker-pools INCLUDE_DIRECTORIES)
    target_compile_definitions(ker-fstack-pool-test PRIVATE ${ker_pool_private_definitions})
    target_include_directories(ker-fstack-pool-test PRIVATE ${ker_pool_private_includes})
    target_link_libraries(ker-fstack-pool-test PRIVATE PkgConfig::DPDK)
    add_executable(ker-fstack-pool-multiprocess-test fstack-pool-multiprocess.c)
    target_link_libraries(ker-fstack-pool-multiprocess-test PRIVATE ker::pools ker::ipc "${ker_reload_ring_pmd}")
    target_compile_options(ker-fstack-pool-multiprocess-test PRIVATE -Wall -Wextra -Werror)
    add_test(NAME fstack-pool-generation COMMAND ker-fstack-pool-test generation)
    add_test(NAME fstack-pool-cache COMMAND ker-fstack-pool-test cache)
    set_tests_properties(fstack-pool-generation fstack-pool-cache PROPERTIES TIMEOUT 30
        LABELS "fstack;fstack-newly-adapted"
        ENVIRONMENT "LD_LIBRARY_PATH=${ker_ipc_test_libraries}:$ENV{LD_LIBRARY_PATH}")
    add_test(NAME fstack-pool-legacy-consumer
        COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/posix/fstack-pools.py"
            --app "$<TARGET_FILE:ker-fstack-pool-multiprocess-test>"
            --unit-app "$<TARGET_FILE:ker-fstack-pool-test>" --pmd-root "${ker_ipc_pmd_root}" --legacy-only)
    set_tests_properties(fstack-pool-legacy-consumer PROPERTIES TIMEOUT 60 LABELS "fstack;pool-foundation")
    add_test(NAME fstack-pool-multiprocess
        COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/posix/fstack-pools.py"
            --app "$<TARGET_FILE:ker-fstack-pool-multiprocess-test>"
            --unit-app "$<TARGET_FILE:ker-fstack-pool-test>" --pmd-root "${ker_ipc_pmd_root}")
    set_tests_properties(fstack-pool-multiprocess PROPERTIES TIMEOUT 180 SKIP_RETURN_CODE 77
        LABELS "fstack;multiprocess")
endif()

if(KER_WITH_DPDK)
    # Compile the actual production TU with private fixture access. This target
    # deliberately does not link ker::reload or install fixture entry points.
    add_executable(ker-fstack-reload-directory-test fstack-reload-directory.c)
    get_target_property(ker_reload_private_definitions ker-reload COMPILE_DEFINITIONS)
    get_target_property(ker_reload_private_includes ker-reload INCLUDE_DIRECTORIES)
    target_compile_definitions(ker-fstack-reload-directory-test PRIVATE ${ker_reload_private_definitions})
    target_include_directories(ker-fstack-reload-directory-test PRIVATE ${ker_reload_private_includes})
    target_link_libraries(ker-fstack-reload-directory-test PRIVATE ker::ipc)
    add_executable(ker-fstack-reload-live-slot-test fstack-reload-live-slot.c)
    target_compile_definitions(ker-fstack-reload-live-slot-test PRIVATE ${ker_reload_private_definitions})
    target_include_directories(ker-fstack-reload-live-slot-test PRIVATE ${ker_reload_private_includes})
    target_link_libraries(ker-fstack-reload-live-slot-test PRIVATE ker::ipc)
    add_executable(ker-fstack-reload-slot-window-test fstack-reload-slot-window.c)
    target_compile_definitions(ker-fstack-reload-slot-window-test PRIVATE ${ker_reload_private_definitions})
    target_include_directories(ker-fstack-reload-slot-window-test PRIVATE ${ker_reload_private_includes})
    target_link_libraries(ker-fstack-reload-slot-window-test PRIVATE ker::ipc)
    target_compile_options(ker-fstack-reload-slot-window-test PRIVATE -Wall -Wextra -Werror)
    add_executable(ker-fstack-reload-slot-public-test fstack-reload-slot-public.c)
    target_include_directories(ker-fstack-reload-slot-public-test PRIVATE "${PROJECT_SOURCE_DIR}/third_party/fstack-ipc")
    target_link_libraries(ker-fstack-reload-slot-public-test PRIVATE ker::reload "${ker_reload_ring_pmd}")
    target_compile_options(ker-fstack-reload-slot-public-test PRIVATE -Wall -Wextra -Werror)
    add_test(NAME fstack-reload-slot-window COMMAND ker-fstack-reload-slot-window-test window)
    add_test(NAME fstack-reload-slot-exhausted COMMAND ker-fstack-reload-slot-window-test exhausted)
    set_tests_properties(fstack-reload-slot-window fstack-reload-slot-exhausted PROPERTIES TIMEOUT 15 LABELS fstack)
    add_executable(ker-fstack-reload-slot-runtime-test fstack-reload-slot-runtime.c)
    target_compile_definitions(ker-fstack-reload-slot-runtime-test PRIVATE ${ker_reload_private_definitions})
    target_include_directories(ker-fstack-reload-slot-runtime-test PRIVATE ${ker_reload_private_includes})
    target_link_libraries(ker-fstack-reload-slot-runtime-test PRIVATE ker::ipc "${ker_reload_ring_pmd}")
    target_compile_options(ker-fstack-reload-slot-runtime-test PRIVATE -Wall -Wextra -Werror)
    set_target_properties(ker-fstack-reload-slot-runtime-test PROPERTIES C_VISIBILITY_PRESET hidden POSITION_INDEPENDENT_CODE ON)
    add_test(NAME fstack-reload-slot-window-multiprocess
        COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/posix/fstack-reload-slot-window.py"
            --app "$<TARGET_FILE:ker-fstack-reload-slot-public-test>"
            --budget-app "$<TARGET_FILE:ker-fstack-reload-slot-runtime-test>"
            --unit-app "$<TARGET_FILE:ker-fstack-reload-slot-window-test>" --pmd-root "${ker_ipc_pmd_root}")
    set_tests_properties(fstack-reload-slot-window-multiprocess PROPERTIES TIMEOUT 120 SKIP_RETURN_CODE 77 LABELS "fstack;multiprocess")
    add_test(NAME fstack-reload-live-slot COMMAND ker-fstack-reload-live-slot-test)
    set_tests_properties(fstack-reload-live-slot PROPERTIES TIMEOUT 15 LABELS fstack
        ENVIRONMENT "LD_LIBRARY_PATH=${ker_ipc_test_libraries}:$ENV{LD_LIBRARY_PATH}")
    add_test(NAME fstack-reload-live-slot-multiprocess
        COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/posix/fstack-reload-live-slot.py"
            --app "$<TARGET_FILE:ker-fstack-reload-directory-multiprocess-test>"
            --unit-app "$<TARGET_FILE:ker-fstack-reload-live-slot-test>" --pmd-root "${ker_ipc_pmd_root}")
    set_tests_properties(fstack-reload-live-slot-multiprocess PROPERTIES TIMEOUT 120 SKIP_RETURN_CODE 77 LABELS "fstack;multiprocess")
    add_executable(ker-fstack-reload-directory-eal-test fstack-reload-directory-eal.c)
    target_include_directories(ker-fstack-reload-directory-eal-test PRIVATE "${PROJECT_SOURCE_DIR}/third_party/fstack-ipc")
    target_link_libraries(ker-fstack-reload-directory-eal-test PRIVATE ker::reload)
    target_compile_options(ker-fstack-reload-directory-eal-test PRIVATE -Wall -Wextra -Werror)
    add_executable(ker-fstack-reload-directory-multiprocess-test fstack-reload-directory-multiprocess.c)
    target_link_libraries(ker-fstack-reload-directory-multiprocess-test PRIVATE ker::reload "${ker_reload_ring_pmd}")
    target_compile_options(ker-fstack-reload-directory-multiprocess-test PRIVATE -Wall -Wextra -Werror)
    add_test(NAME fstack-reload-directory-multiprocess
        COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/posix/fstack-reload-directory.py"
            --app "$<TARGET_FILE:ker-fstack-reload-directory-multiprocess-test>"
            --unit-app "$<TARGET_FILE:ker-fstack-reload-directory-test>" --pmd-root "${ker_ipc_pmd_root}")
    set_tests_properties(fstack-reload-directory-multiprocess PROPERTIES TIMEOUT 240 SKIP_RETURN_CODE 77
        LABELS "fstack;fstack-reload;multiprocess")
    # Isolated production-TU copy with an address-specific CAS barrier for the
    # proof/CAS interleaving. The normal multiprocess/public-consumer targets
    # continue linking the installed production component.
    add_executable(ker-fstack-reload-directory-reclaim-race-test
        fstack-reload-directory-multiprocess.c "${PROJECT_SOURCE_DIR}/src/compat/reload.c")
    target_compile_definitions(ker-fstack-reload-directory-reclaim-race-test PRIVATE
        ${ker_reload_private_definitions} KER_RELOAD_TESTING)
    target_include_directories(ker-fstack-reload-directory-reclaim-race-test PRIVATE
        ${ker_reload_private_includes})
    target_link_libraries(ker-fstack-reload-directory-reclaim-race-test PRIVATE ker::ipc "${ker_reload_ring_pmd}")
    target_compile_options(ker-fstack-reload-directory-reclaim-race-test PRIVATE -Wall -Wextra -Werror)
    set_target_properties(ker-fstack-reload-directory-reclaim-race-test PROPERTIES
        C_VISIBILITY_PRESET hidden POSITION_INDEPENDENT_CODE ON)
    add_test(NAME fstack-reload-directory-reclaim-race
        COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/posix/fstack-reload-directory.py"
            --app "$<TARGET_FILE:ker-fstack-reload-directory-reclaim-race-test>"
            --unit-app "$<TARGET_FILE:ker-fstack-reload-directory-test>" --pmd-root "${ker_ipc_pmd_root}"
            --verify-reclaim-gate)
    set_tests_properties(fstack-reload-directory-reclaim-race PROPERTIES TIMEOUT 240 SKIP_RETURN_CODE 77
        LABELS "fstack;fstack-reload;multiprocess")
    # Negative control removes only the new poll/reclaim gate, retaining the
    # exact same production CAS interposition and fixture.
    add_executable(ker-fstack-reload-directory-reclaim-negative-test
        fstack-reload-directory-multiprocess.c "${PROJECT_SOURCE_DIR}/src/compat/reload.c")
    target_compile_definitions(ker-fstack-reload-directory-reclaim-negative-test PRIVATE
        ${ker_reload_private_definitions} KER_RELOAD_TESTING KER_RELOAD_TESTING_NO_RECLAIM_GATE)
    target_include_directories(ker-fstack-reload-directory-reclaim-negative-test PRIVATE
        ${ker_reload_private_includes})
    target_link_libraries(ker-fstack-reload-directory-reclaim-negative-test PRIVATE ker::ipc "${ker_reload_ring_pmd}")
    target_compile_options(ker-fstack-reload-directory-reclaim-negative-test PRIVATE -Wall -Wextra -Werror)
    set_target_properties(ker-fstack-reload-directory-reclaim-negative-test PROPERTIES
        C_VISIBILITY_PRESET hidden POSITION_INDEPENDENT_CODE ON)
    add_test(NAME fstack-reload-directory-reclaim-negative-control
        COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/posix/fstack-reload-directory.py"
            --app "$<TARGET_FILE:ker-fstack-reload-directory-reclaim-negative-test>"
            --unit-app "$<TARGET_FILE:ker-fstack-reload-directory-test>" --pmd-root "${ker_ipc_pmd_root}"
            --negative-control)
    set_tests_properties(fstack-reload-directory-reclaim-negative-control PROPERTIES TIMEOUT 240 SKIP_RETURN_CODE 77
        LABELS "fstack;fstack-reload;multiprocess")
    add_test(NAME fstack-reload-coordinate-multiprocess
        COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/posix/fstack-reload-coordinates.py"
            --app "$<TARGET_FILE:ker-fstack-reload-directory-multiprocess-test>"
            --unit-app "$<TARGET_FILE:ker-fstack-reload-directory-test>" --pmd-root "${ker_ipc_pmd_root}")
    set_tests_properties(fstack-reload-coordinate-multiprocess PROPERTIES TIMEOUT 240 SKIP_RETURN_CODE 77
        LABELS "fstack;fstack-reload;multiprocess")
    add_test(NAME fstack-reload-directory-foundation COMMAND ker-fstack-reload-directory-test)
    add_test(NAME fstack-reload-directory-primary-eal COMMAND ker-fstack-reload-directory-eal-test)
    set_tests_properties(fstack-reload-directory-foundation fstack-reload-directory-primary-eal PROPERTIES TIMEOUT 30
        LABELS "fstack;fstack-reload;directory-foundation"
        ENVIRONMENT "LD_LIBRARY_PATH=${ker_ipc_test_libraries}:$ENV{LD_LIBRARY_PATH}")
endif()

if(KER_WITH_DPDK)
    add_test(NAME fstack-reload-m5-arbitration COMMAND ker-fstack-reload-directory-test m5-arbitration)
    add_test(NAME fstack-reload-m5-probe COMMAND ker-fstack-reload-directory-test m5-probe)
    add_test(NAME fstack-reload-m5-names COMMAND ker-fstack-reload-directory-test m5-names)
    add_test(NAME fstack-reload-m5-handover COMMAND ker-fstack-reload-directory-test m5-handover)
    set_tests_properties(fstack-reload-m5-arbitration fstack-reload-m5-probe
        fstack-reload-m5-names fstack-reload-m5-handover PROPERTIES TIMEOUT 30
        LABELS "fstack;fstack-reload;fstack-newly-adapted"
        ENVIRONMENT "LD_LIBRARY_PATH=${ker_ipc_test_libraries}:$ENV{LD_LIBRARY_PATH}")
endif()

if(KER_WITH_DPDK)
    add_test(NAME fstack-reload-directory-hw-users COMMAND ker-fstack-reload-directory-test hw-users)
    add_test(NAME fstack-reload-directory-reclaim COMMAND ker-fstack-reload-directory-test reclaim)
    add_test(NAME fstack-reload-directory-release COMMAND ker-fstack-reload-directory-test release)
    add_test(NAME fstack-reload-directory-orphans COMMAND ker-fstack-reload-directory-test orphans)
    add_test(NAME fstack-reload-directory-ring-census COMMAND ker-fstack-reload-directory-test ring-census)
    set_tests_properties(fstack-reload-directory-hw-users fstack-reload-directory-reclaim
        fstack-reload-directory-release fstack-reload-directory-orphans fstack-reload-directory-ring-census
        PROPERTIES TIMEOUT 30 LABELS "fstack;fstack-reload;fstack-newly-adapted"
        ENVIRONMENT "LD_LIBRARY_PATH=${ker_ipc_test_libraries}:$ENV{LD_LIBRARY_PATH}")
endif()
