# The caller links the original allocation and packet-ring functions privately.
find_library(ker_kni_vdev_bus NAMES rte_bus_vdev HINTS ${DPDK_LIBRARY_DIRS} NO_DEFAULT_PATH REQUIRED)
get_target_property(kni_reload_symbols ker_reload_objects COMPILE_DEFINITIONS)
# The separate KNI caller owns the original config layout used by its excerpts.
list(FILTER kni_reload_symbols EXCLUDE REGEX "^ff_global_cfg=")

add_library(ker-example-kni-bridge STATIC "${PROJECT_SOURCE_DIR}/examples/kni-bridge-policy.c")
target_include_directories(ker-example-kni-bridge PUBLIC
    "${PROJECT_SOURCE_DIR}/examples"
    "${PROJECT_SOURCE_DIR}/third_party/fstack-kni-bridge"
    "${PROJECT_SOURCE_DIR}/third_party/fstack-reload"
    "${PROJECT_SOURCE_DIR}/third_party/fstack-ipc")
target_compile_definitions(ker-example-kni-bridge PRIVATE _DEFAULT_SOURCE=1 ${kni_reload_symbols})
target_compile_options(ker-example-kni-bridge PRIVATE -Wall -Wextra -Werror)
target_link_libraries(ker-example-kni-bridge PUBLIC PkgConfig::DPDK)
set_target_properties(ker-example-kni-bridge PROPERTIES C_STANDARD 11 C_STANDARD_REQUIRED YES C_EXTENSIONS OFF)

add_executable(ker-kni-owner-source-test fstack-kni-owner.c)
add_executable(ker-kni-allocation-test fstack-kni-allocation.c)
foreach(target ker-kni-owner-source-test ker-kni-allocation-test)
    target_compile_definitions(${target} PRIVATE ${kni_reload_symbols})
    target_compile_options(${target} PRIVATE -Wall -Wextra -Werror)
    target_link_options(${target} PRIVATE -Wl,--disable-new-dtags)
    target_link_libraries(${target} PRIVATE
        ker-example-kni-bridge ker_reload_objects ker::ipc "${KER_NET_RING_PMD}" "${ker_kni_vdev_bus}")
    set_target_properties(${target} PROPERTIES BUILD_RPATH "${DPDK_LIBRARY_DIRS}")
endforeach()
target_link_options(ker-kni-owner-source-test PRIVATE -Wl,--wrap=rte_zmalloc
    -Wl,--wrap=rte_eal_process_type -Wl,--wrap=rte_eal_hotplug_add
    -Wl,--wrap=rte_eth_macaddr_get -Wl,--wrap=__rte_panic)
target_link_options(ker-kni-allocation-test PRIVATE -Wl,--wrap=rte_zmalloc -Wl,--wrap=rte_exit
    -Wl,--wrap=__rte_panic -Wl,--wrap=rte_eal_hotplug_add)

add_test(NAME fstack-kni-owner-source COMMAND ker-kni-owner-source-test owner)
add_test(NAME fstack-kni-nonowner-source COMMAND ker-kni-owner-source-test nonowner)
add_test(NAME fstack-kni-short-tx-source COMMAND ker-kni-owner-source-test short-tx)
add_test(NAME fstack-kni-full-ring-source COMMAND ker-kni-owner-source-test full-ring)
add_test(NAME fstack-kni-stats-oom-source COMMAND ker-kni-allocation-test stats)
add_test(NAME fstack-kni-slot-oom-source COMMAND ker-kni-allocation-test slot)
add_test(NAME fstack-kni-stats-real-exit
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/kni-fatal.py"
        "$<TARGET_FILE:ker-kni-allocation-test>" stats)
add_test(NAME fstack-kni-slot-real-panic
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/kni-fatal.py"
        "$<TARGET_FILE:ker-kni-allocation-test>" slot)
set_tests_properties(fstack-kni-owner-source fstack-kni-nonowner-source fstack-kni-short-tx-source
    fstack-kni-full-ring-source fstack-kni-stats-oom-source fstack-kni-slot-oom-source
    fstack-kni-stats-real-exit fstack-kni-slot-real-panic PROPERTIES TIMEOUT 30 LABELS fstack)
add_test(NAME fstack-kni-original-import
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/fstack-kni-import.py")
set_tests_properties(fstack-kni-original-import PROPERTIES TIMEOUT 30 LABELS "fstack;provenance")
