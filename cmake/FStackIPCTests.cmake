add_executable(ker-ipc-coordinate-test ipc-coordinate.c)
target_compile_options(ker-ipc-coordinate-test PRIVATE -Wall -Wextra -Werror)
target_link_libraries(ker-ipc-coordinate-test PRIVATE ker::ipc)
target_link_options(ker-ipc-coordinate-test PRIVATE -Wl,--disable-new-dtags)
set_target_properties(ker-ipc-coordinate-test PROPERTIES BUILD_RPATH "${DPDK_LIBRARY_DIRS}")

add_test(NAME fstack-ipc-process-coordinate
    COMMAND ker-ipc-coordinate-test 1 - 1 -1 4294967295 - 0)
set_tests_properties(fstack-ipc-process-coordinate PROPERTIES TIMEOUT 30 LABELS fstack)

add_test(NAME fstack-ipc-original-import
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/ipc-import.py")
set_tests_properties(fstack-ipc-original-import PROPERTIES TIMEOUT 30 LABELS "fstack;provenance")

add_test(NAME fstack-ipc-process-generation
    COMMAND ker-ipc-coordinate-test 1:0 - 1 0 4294967295 ff_msg_ring_in_1_g0 0)
set_tests_properties(fstack-ipc-process-generation PROPERTIES TIMEOUT 30 LABELS fstack)

add_test(NAME fstack-ipc-process-epoch
    COMMAND ker-ipc-coordinate-test 1:0:3 - 1 0 3 ff_msg_ring_in_1_e3_g0 3)
set_tests_properties(fstack-ipc-process-epoch PROPERTIES TIMEOUT 30 LABELS fstack)

add_test(NAME fstack-ipc-full-coordinate
    COMMAND ker-ipc-coordinate-test 2:1:1 - 2 1 1 ff_msg_ring_in_2_e1_g1 1)
set_tests_properties(fstack-ipc-full-coordinate PROPERTIES TIMEOUT 30 LABELS fstack)

add_test(NAME fstack-ipc-generation-epoch
    COMMAND ker-ipc-coordinate-test - 1:2 0 1 2 ff_msg_ring_in_0_e2_g1 2)
set_tests_properties(fstack-ipc-generation-epoch PROPERTIES TIMEOUT 30 LABELS fstack)

add_test(NAME fstack-ipc-generation-option
    COMMAND ker-ipc-coordinate-test - 0 0 0 4294967295 ff_msg_ring_in_0_g0 0)
set_tests_properties(fstack-ipc-generation-option PROPERTIES TIMEOUT 30 LABELS fstack)

add_test(NAME fstack-ipc-malformed-coordinate
    COMMAND ker-ipc-coordinate-test --malformed)
set_tests_properties(fstack-ipc-malformed-coordinate PROPERTIES TIMEOUT 30 LABELS fstack)


add_executable(ker-ipc-ownership-test ipc-ownership.c)
target_compile_options(ker-ipc-ownership-test PRIVATE -Wall -Wextra -Werror)
target_link_libraries(ker-ipc-ownership-test PRIVATE ker::ipc)
target_link_options(ker-ipc-ownership-test PRIVATE -Wl,--disable-new-dtags)
set_target_properties(ker-ipc-ownership-test PROPERTIES BUILD_RPATH "${DPDK_LIBRARY_DIRS}")

add_test(NAME fstack-ipc-own-reply
    COMMAND ker-ipc-ownership-test own-reply)
set_tests_properties(fstack-ipc-own-reply PROPERTIES TIMEOUT 30 LABELS fstack)

add_test(NAME fstack-ipc-foreign-live
    COMMAND ker-ipc-ownership-test foreign-live)
set_tests_properties(fstack-ipc-foreign-live PROPERTIES TIMEOUT 30 LABELS fstack)

add_test(NAME fstack-ipc-foreign-no-send
    COMMAND ker-ipc-ownership-test foreign-no-send)
set_tests_properties(fstack-ipc-foreign-no-send PROPERTIES TIMEOUT 30 LABELS fstack)
