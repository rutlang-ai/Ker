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
