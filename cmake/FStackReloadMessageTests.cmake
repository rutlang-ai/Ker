add_executable(ker-reload-message-test reload-message.c)
target_compile_options(ker-reload-message-test PRIVATE -Wall -Wextra -Werror)
target_link_libraries(ker-reload-message-test PRIVATE ker::reload)
target_link_options(ker-reload-message-test PRIVATE -Wl,--disable-new-dtags)
set_target_properties(ker-reload-message-test PROPERTIES BUILD_RPATH "${DPDK_LIBRARY_DIRS}")
add_test(NAME fstack-reload-message-serdes COMMAND ker-reload-message-test)
set_tests_properties(fstack-reload-message-serdes PROPERTIES TIMEOUT 30 LABELS fstack)
add_test(NAME fstack-reload-message-original-import
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/reload-import.py")
set_tests_properties(fstack-reload-message-original-import PROPERTIES
    TIMEOUT 30 LABELS "fstack;provenance")

# The retained reload unit cases exercise the same private implementation
# linked into ker::reload, including in a shared-library build.
function(fstack_reload_source_case source)
    add_executable("ker-${source}" fstack-reload-case.c)
    get_target_property(reload_symbols ker_reload_objects COMPILE_DEFINITIONS)
    target_compile_definitions("ker-${source}" PRIVATE ${reload_symbols}
        "SOURCE_FUNCTION=${source}" "SOURCE_INCLUDE=\"fstack-reload-source/${source}.inc\"")
    target_include_directories("ker-${source}" PRIVATE
        "${PROJECT_SOURCE_DIR}/third_party/fstack-ipc"
        "${PROJECT_SOURCE_DIR}/third_party/fstack-reload")
    target_compile_options("ker-${source}" PRIVATE -Wall -Wextra -Werror)
    target_link_libraries("ker-${source}" PRIVATE ker_reload_objects ker::ipc)
    target_link_options("ker-${source}" PRIVATE -Wl,--disable-new-dtags)
    set_target_properties("ker-${source}" PROPERTIES BUILD_RPATH "${DPDK_LIBRARY_DIRS}")
endfunction()

fstack_reload_source_case(test_ut_nr_22_heartbeat_and_rx_return)
add_test(NAME fstack-reload-heartbeat COMMAND ker-test_ut_nr_22_heartbeat_and_rx_return)
set_tests_properties(fstack-reload-heartbeat PROPERTIES TIMEOUT 30 LABELS fstack)

fstack_reload_source_case(test_ut_nr_26_rx_handover_markers)
add_test(NAME fstack-reload-rx-handover COMMAND ker-test_ut_nr_26_rx_handover_markers)
set_tests_properties(fstack-reload-rx-handover PROPERTIES TIMEOUT 30 LABELS fstack)

fstack_reload_source_case(test_ut_nr_11_handover_barrier)
add_test(NAME fstack-reload-handover-barrier COMMAND ker-test_ut_nr_11_handover_barrier)
set_tests_properties(fstack-reload-handover-barrier PROPERTIES TIMEOUT 30 LABELS fstack)
