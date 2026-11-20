find_library(ker_reload_data_vdev_bus NAMES rte_bus_vdev HINTS ${DPDK_LIBRARY_DIRS} NO_DEFAULT_PATH REQUIRED)
add_executable(ker-fstack-parked-tx-test fstack-parked-tx.c)
add_executable(ker-fstack-peer-dispatch-test fstack-peer-dispatch.c)
add_executable(ker-fstack-a10-dispatch-test fstack-a10-dispatch.c
    "${PROJECT_SOURCE_DIR}/examples/a10-dispatch-policy.c"
    "${PROJECT_SOURCE_DIR}/src/compat/peer-dispatcher.c")
target_link_libraries(ker-fstack-parked-tx-test PRIVATE ker::reload_tx ker::packet_dispatcher)
target_link_libraries(ker-fstack-peer-dispatch-test PRIVATE ker::peer_dispatcher)
# The sample's caller flow map uses the same original state as the test.
target_link_libraries(ker-fstack-a10-dispatch-test PRIVATE
    ker-example-flow-map ker_reload_objects ker::ipc ker::packet_dispatcher)
foreach(target ker-fstack-parked-tx-test ker-fstack-peer-dispatch-test ker-fstack-a10-dispatch-test)
    target_link_libraries(${target} PRIVATE "${KER_NET_RING_PMD}" "${ker_reload_data_vdev_bus}")
    target_compile_options(${target} PRIVATE -Wall -Wextra -Werror)
    target_link_options(${target} PRIVATE -Wl,--disable-new-dtags)
    set_target_properties(${target} PROPERTIES BUILD_RPATH "${DPDK_LIBRARY_DIRS}")
endforeach()
add_test(NAME fstack-parked-tx-divert COMMAND ker-fstack-parked-tx-test divert)
add_test(NAME fstack-parked-tx-watermark COMMAND ker-fstack-parked-tx-test watermark)
add_test(NAME fstack-parked-tx-guard COMMAND ker-fstack-parked-tx-test guard)
add_test(NAME fstack-parked-tx-pass COMMAND ker-fstack-parked-tx-test pass)
add_test(NAME fstack-parked-tx-ownership COMMAND ker-fstack-parked-tx-test ownership)
add_test(NAME fstack-peer-dispatch-ownership COMMAND ker-fstack-peer-dispatch-test)
add_test(NAME fstack-a10-halfopen-dispatch COMMAND ker-fstack-a10-dispatch-test dispatch)
add_test(NAME fstack-a10-window-mechanism COMMAND ker-fstack-a10-dispatch-test mechanism)
add_test(NAME fstack-a10-dispatch-import COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/a10-dispatch-import.py")
set_tests_properties(fstack-parked-tx-divert fstack-parked-tx-watermark fstack-parked-tx-guard fstack-parked-tx-pass
    fstack-parked-tx-ownership fstack-peer-dispatch-ownership fstack-a10-halfopen-dispatch fstack-a10-window-mechanism
    PROPERTIES TIMEOUT 30 LABELS fstack)
set_tests_properties(fstack-a10-dispatch-import PROPERTIES TIMEOUT 15 LABELS provenance)
