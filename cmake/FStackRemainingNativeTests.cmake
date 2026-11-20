add_executable(ker-fstack-address-policy-sockets-test tests/posix/address-policy-sockets.c)
add_executable(ker-fstack-run-stop-test tests/posix/remaining-run-stop.c)
add_executable(ker-fstack-mmap-fatal-test tests/posix/remaining-mmap.c examples/host-mapping.c)
target_link_libraries(ker-fstack-address-policy-sockets-test PRIVATE ker::address_policy)
target_include_directories(ker-fstack-mmap-fatal-test PRIVATE
    examples third_party/fstack-reload third_party/fstack-host-readiness)
foreach(target ker-fstack-address-policy-sockets-test ker-fstack-run-stop-test ker-fstack-mmap-fatal-test)
    target_include_directories(${target} PRIVATE include tests)
    target_compile_options(${target} PRIVATE -Wall -Wextra -Werror)
    target_link_libraries(${target} PRIVATE Threads::Threads ${CMAKE_DL_LIBS})
endforeach()
set(ker_remaining_native "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/posix/remaining-native.py"
    --launcher "${PROJECT_SOURCE_DIR}/tools/ker-run.py" --library "$<TARGET_FILE:ker-posix>"
    --worker "$<TARGET_FILE:ker-io-worker>")
add_test(NAME native-fstack-address-policy-sockets COMMAND ${ker_remaining_native}
    --app "$<TARGET_FILE:ker-fstack-address-policy-sockets-test>" --profile address)
add_test(NAME native-fstack-host-mmap-fatal COMMAND ${ker_remaining_native}
    --app "$<TARGET_FILE:ker-fstack-mmap-fatal-test>" --profile mmap)
add_test(NAME native-fstack-run-stop-one COMMAND ${ker_remaining_native}
    --app "$<TARGET_FILE:ker-fstack-run-stop-test>" --profile one)
add_test(NAME native-fstack-run-stop-repeat COMMAND ${ker_remaining_native}
    --app "$<TARGET_FILE:ker-fstack-run-stop-test>" --profile repeat)
add_test(NAME native-fstack-run-stop-wait COMMAND ${ker_remaining_native}
    --app "$<TARGET_FILE:ker-fstack-run-stop-test>" --profile wait)
add_test(NAME fstack-host-mmap-import COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/fstack-host-mmap-import.py")
set_tests_properties(native-fstack-address-policy-sockets native-fstack-host-mmap-fatal
    native-fstack-run-stop-one native-fstack-run-stop-repeat native-fstack-run-stop-wait
    PROPERTIES TIMEOUT 35 LABELS "fstack;native-dpdk")
set_tests_properties(fstack-host-mmap-import PROPERTIES TIMEOUT 15 LABELS provenance)
