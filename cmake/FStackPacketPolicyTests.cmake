# These examples keep upstream caller-side policy out of the Ker libraries.
add_library(ker-example-rss-table STATIC "${PROJECT_SOURCE_DIR}/examples/rss-table-policy.c")
add_library(ker-example-rss-recheck STATIC "${PROJECT_SOURCE_DIR}/examples/rss-table-policy.c")
foreach(policy ker-example-rss-table ker-example-rss-recheck)
    target_include_directories(${policy} PUBLIC
        "${PROJECT_SOURCE_DIR}/examples"
        "${PROJECT_SOURCE_DIR}/third_party/fstack-reload"
        "${PROJECT_SOURCE_DIR}/third_party/fstack-rss-table")
    target_link_libraries(${policy} PUBLIC PkgConfig::DPDK)
    # Preserve the original Toeplitz implementation's signed shift behavior.
    target_compile_options(${policy} PRIVATE -Wall -Wextra -Werror -fwrapv)
    set_target_properties(${policy} PROPERTIES C_STANDARD 11 C_STANDARD_REQUIRED YES C_EXTENSIONS OFF)
endforeach()
target_compile_definitions(ker-example-rss-recheck PRIVATE EXAMPLE_RSS_TEST_RECHECK_WRAP)

add_library(ker-example-flow-map STATIC "${PROJECT_SOURCE_DIR}/examples/flow-map-policy.c")
target_include_directories(ker-example-flow-map PUBLIC
    "${PROJECT_SOURCE_DIR}/examples" "${PROJECT_SOURCE_DIR}/third_party/fstack-flow-map"
    PRIVATE "${PROJECT_SOURCE_DIR}/third_party/fstack-reload" "${PROJECT_SOURCE_DIR}/third_party/fstack-ipc")
get_target_property(reload_symbols ker_reload_objects COMPILE_DEFINITIONS)
target_compile_definitions(ker-example-flow-map PRIVATE ${reload_symbols})
target_link_libraries(ker-example-flow-map PUBLIC PkgConfig::DPDK)
target_compile_options(ker-example-flow-map PRIVATE -Wall -Wextra -Werror)

add_executable(ker-fstack-rss-table-test fstack-rss-source-case.c)
target_link_libraries(ker-fstack-rss-table-test PRIVATE ker-example-rss-table)
add_executable(ker-fstack-rss-adjust-test fstack-rss-adjust.c)
target_link_libraries(ker-fstack-rss-adjust-test PRIVATE ker-example-rss-recheck)
add_executable(ker-fstack-rss-microbench-test fstack-rss-adjust-microbench.c)
target_link_libraries(ker-fstack-rss-microbench-test PRIVATE ker-example-rss-table)
add_executable(ker-fstack-rss-thash-test fstack-rss-thash.c)
target_link_libraries(ker-fstack-rss-thash-test PRIVATE PkgConfig::DPDK)
add_executable(ker-rss-table-router "${PROJECT_SOURCE_DIR}/examples/rss-table-router.c")
target_link_libraries(ker-rss-table-router PRIVATE ker-example-rss-table "${KER_NET_RING_PMD}")

add_executable(ker-fstack-flow-map-test fstack-flow-map.c)
target_link_libraries(ker-fstack-flow-map-test PRIVATE ker-example-flow-map ker_reload_objects ker::ipc)
add_executable(ker-flow-map-router "${PROJECT_SOURCE_DIR}/examples/flow-map-router.c")
target_link_libraries(ker-flow-map-router PRIVATE ker-example-flow-map ker_reload_objects ker::ipc "${KER_NET_RING_PMD}")
foreach(target ker-fstack-flow-map-test ker-flow-map-router)
    target_include_directories(${target} PRIVATE
        "${PROJECT_SOURCE_DIR}/third_party/fstack-reload" "${PROJECT_SOURCE_DIR}/third_party/fstack-ipc")
    target_compile_definitions(${target} PRIVATE ${reload_symbols})
endforeach()

foreach(target ker-fstack-rss-table-test ker-fstack-rss-adjust-test ker-fstack-rss-microbench-test
               ker-fstack-rss-thash-test ker-rss-table-router ker-fstack-flow-map-test ker-flow-map-router)
    target_compile_options(${target} PRIVATE -Wall -Wextra -Werror)
    target_link_options(${target} PRIVATE -Wl,--disable-new-dtags)
    set_target_properties(${target} PROPERTIES BUILD_RPATH "${DPDK_LIBRARY_DIRS}")
endforeach()
target_compile_options(ker-fstack-rss-table-test PRIVATE -fwrapv)
target_compile_options(ker-fstack-rss-adjust-test PRIVATE -fwrapv)
target_compile_options(ker-fstack-rss-microbench-test PRIVATE -fwrapv)
target_compile_options(ker-fstack-rss-thash-test PRIVATE -fwrapv)

add_test(NAME fstack-rss-table-test_ff_rss_tbl_set_portrange_no_cfg
    COMMAND ker-fstack-rss-table-test test_ff_rss_tbl_set_portrange_no_cfg)

add_test(NAME fstack-rss-table-test_ff_rss_tbl_set_portrange_disabled
    COMMAND ker-fstack-rss-table-test test_ff_rss_tbl_set_portrange_disabled)

add_test(NAME fstack-rss-table-test_ff_rss_tbl_set_portrange_inverted_range
    COMMAND ker-fstack-rss-table-test test_ff_rss_tbl_set_portrange_inverted_range)

add_test(NAME fstack-rss-table-test_ff_rss_tbl_get_portrange_no_cfg
    COMMAND ker-fstack-rss-table-test test_ff_rss_tbl_get_portrange_no_cfg)

add_test(NAME fstack-rss-table-test_ff_rss_tbl_get_portrange_disabled
    COMMAND ker-fstack-rss-table-test test_ff_rss_tbl_get_portrange_disabled)

add_test(NAME fstack-rss-table-test_ff_rss_tbl_get_portrange_smoke
    COMMAND ker-fstack-rss-table-test test_ff_rss_tbl_get_portrange_smoke)

add_test(NAME fstack-rss-table-test_ff_rss_tbl_get_portrange_hit
    COMMAND ker-fstack-rss-table-test test_ff_rss_tbl_get_portrange_hit)

add_test(NAME fstack-rss-table-test_ff_rss_tbl_get_portrange_rotation
    COMMAND ker-fstack-rss-table-test test_ff_rss_tbl_get_portrange_rotation)

add_test(NAME fstack-rss-table-test_ff_rss_tbl_get_portrange_miss
    COMMAND ker-fstack-rss-table-test test_ff_rss_tbl_get_portrange_miss)

add_test(NAME fstack-rss-table-test_ff_rss_check6_landing
    COMMAND ker-fstack-rss-table-test test_ff_rss_check6_landing)

add_test(NAME fstack-rss-table-test_ff_rss_check6_single_queue
    COMMAND ker-fstack-rss-table-test test_ff_rss_check6_single_queue)

add_test(NAME fstack-rss-table-test_ff_rss_tbl6_set_get
    COMMAND ker-fstack-rss-table-test test_ff_rss_tbl6_set_get)

add_test(NAME fstack-rss-adjust-test_ff_rss_adjust_sport_thash_adjust_off
    COMMAND ker-fstack-rss-adjust-test test_ff_rss_adjust_sport_thash_adjust_off)

add_test(NAME fstack-rss-adjust-test_ff_rss_adjust_sport6_thash_adjust_off
    COMMAND ker-fstack-rss-adjust-test test_ff_rss_adjust_sport6_thash_adjust_off)

add_test(NAME fstack-rss-adjust-test_ff_rss_thash_ctx_init_thash_adjust_off
    COMMAND ker-fstack-rss-adjust-test test_ff_rss_thash_ctx_init_thash_adjust_off)

add_test(NAME fstack-rss-adjust-test_ff_rss_adjust_sport_null
    COMMAND ker-fstack-rss-adjust-test test_ff_rss_adjust_sport_null)

add_test(NAME fstack-rss-adjust-test_ff_rss_adjust_sport_degraded
    COMMAND ker-fstack-rss-adjust-test test_ff_rss_adjust_sport_degraded)

add_test(NAME fstack-rss-adjust-test_ff_rss_adjust_sport_single_queue
    COMMAND ker-fstack-rss-adjust-test test_ff_rss_adjust_sport_single_queue)

add_test(NAME fstack-rss-adjust-test_ff_rss_adjust_sport6_guard
    COMMAND ker-fstack-rss-adjust-test test_ff_rss_adjust_sport6_guard)

add_test(NAME fstack-rss-adjust-test_ff_rss_adjust_sport_range_params
    COMMAND ker-fstack-rss-adjust-test test_ff_rss_adjust_sport_range_params)

add_test(NAME fstack-rss-adjust-test_ff_rss_adjust_sport6_range_params
    COMMAND ker-fstack-rss-adjust-test test_ff_rss_adjust_sport6_range_params)

add_test(NAME fstack-rss-adjust-test_ff_rss_adjust_sport_recheck_off
    COMMAND ker-fstack-rss-adjust-test test_ff_rss_adjust_sport_recheck_off)

add_test(NAME fstack-rss-adjust-test_ff_rss_adjust_sport_recheck_on
    COMMAND ker-fstack-rss-adjust-test test_ff_rss_adjust_sport_recheck_on)

add_test(NAME fstack-rss-adjust-test_ff_rss_adjust_sport6_recheck_off
    COMMAND ker-fstack-rss-adjust-test test_ff_rss_adjust_sport6_recheck_off)

add_test(NAME fstack-rss-adjust-test_ff_rss_adjust_sport6_recheck_on
    COMMAND ker-fstack-rss-adjust-test test_ff_rss_adjust_sport6_recheck_on)

add_test(NAME fstack-flow-map-basic
    COMMAND ker-fstack-flow-map-test basic)

add_test(NAME fstack-flow-map-single-phase
    COMMAND ker-fstack-flow-map-test single-phase)

add_test(NAME fstack-flow-map-admission
    COMMAND ker-fstack-flow-map-test admission)

add_test(NAME fstack-flow-map-revoke
    COMMAND ker-fstack-flow-map-test revoke)

add_test(NAME fstack-flow-map-growth
    COMMAND ker-fstack-flow-map-test growth)

add_test(NAME fstack-rss-thash-ipv4 COMMAND ker-fstack-rss-thash-test ipv4)

add_test(NAME fstack-rss-thash-ipv6 COMMAND ker-fstack-rss-thash-test ipv6)

add_test(NAME fstack-rss-adjust-microbench COMMAND ker-fstack-rss-microbench-test)

add_test(NAME fstack-rss-adjust-ready COMMAND ker-fstack-rss-adjust-test)

add_test(NAME fstack-rss-caller-routing COMMAND ker-rss-table-router)

add_test(NAME fstack-flow-map-caller-routing COMMAND ker-flow-map-router)

set_tests_properties(
    fstack-rss-table-test_ff_rss_tbl_set_portrange_no_cfg
    fstack-rss-table-test_ff_rss_tbl_set_portrange_disabled
    fstack-rss-table-test_ff_rss_tbl_set_portrange_inverted_range
    fstack-rss-table-test_ff_rss_tbl_get_portrange_no_cfg
    fstack-rss-table-test_ff_rss_tbl_get_portrange_disabled
    fstack-rss-table-test_ff_rss_tbl_get_portrange_smoke
    fstack-rss-table-test_ff_rss_tbl_get_portrange_hit
    fstack-rss-table-test_ff_rss_tbl_get_portrange_rotation
    fstack-rss-table-test_ff_rss_tbl_get_portrange_miss
    fstack-rss-table-test_ff_rss_check6_landing
    fstack-rss-table-test_ff_rss_check6_single_queue
    fstack-rss-table-test_ff_rss_tbl6_set_get
    fstack-rss-adjust-test_ff_rss_adjust_sport_thash_adjust_off
    fstack-rss-adjust-test_ff_rss_adjust_sport6_thash_adjust_off
    fstack-rss-adjust-test_ff_rss_thash_ctx_init_thash_adjust_off
    fstack-rss-adjust-test_ff_rss_adjust_sport_null
    fstack-rss-adjust-test_ff_rss_adjust_sport_degraded
    fstack-rss-adjust-test_ff_rss_adjust_sport_single_queue
    fstack-rss-adjust-test_ff_rss_adjust_sport6_guard
    fstack-rss-adjust-test_ff_rss_adjust_sport_range_params
    fstack-rss-adjust-test_ff_rss_adjust_sport6_range_params
    fstack-rss-adjust-test_ff_rss_adjust_sport_recheck_off
    fstack-rss-adjust-test_ff_rss_adjust_sport_recheck_on
    fstack-rss-adjust-test_ff_rss_adjust_sport6_recheck_off
    fstack-rss-adjust-test_ff_rss_adjust_sport6_recheck_on
    fstack-flow-map-basic
    fstack-flow-map-single-phase
    fstack-flow-map-admission
    fstack-flow-map-revoke
    fstack-flow-map-growth
    fstack-rss-thash-ipv4
    fstack-rss-thash-ipv6
    fstack-rss-adjust-microbench
    fstack-rss-adjust-ready
    fstack-rss-caller-routing
    fstack-flow-map-caller-routing
    PROPERTIES TIMEOUT 30 LABELS fstack)
set_tests_properties(fstack-rss-adjust-microbench PROPERTIES RUN_SERIAL TRUE)

foreach(audit fstack-rss-table-import fstack-rss-adjust-import fstack-rss-microbench-import
              rss-thash-import flow-map-import)
    add_test(NAME ${audit}
        COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/${audit}.py")
    set_tests_properties(${audit} PROPERTIES TIMEOUT 30 LABELS "fstack;provenance")
endforeach()
