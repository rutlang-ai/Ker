add_executable(ker-native-offload-wire-test tests/posix/tx-offloads.c)
target_compile_options(ker-native-offload-wire-test PRIVATE -Wall -Wextra -Werror)
add_executable(ker-native-offload-metadata-test tests/posix/worker-offload.c src/posix/worker-offload.c)
target_include_directories(ker-native-offload-metadata-test PRIVATE src/posix tests)
target_link_libraries(ker-native-offload-metadata-test PRIVATE PkgConfig::DPDK)
target_link_options(ker-native-offload-metadata-test PRIVATE -Wl,--disable-new-dtags)
target_compile_options(ker-native-offload-metadata-test PRIVATE -Wall -Wextra -Werror)
set_target_properties(ker-native-offload-metadata-test PROPERTIES BUILD_RPATH "${DPDK_LIBRARY_DIRS}")
add_test(NAME native-fstack-tx-offload-metadata COMMAND ker-native-offload-metadata-test)
add_test(NAME native-fstack-tx-offloads COMMAND "${Python3_EXECUTABLE}"
    "${PROJECT_SOURCE_DIR}/tests/posix/tx-offloads.py"
    --launcher "${PROJECT_SOURCE_DIR}/tools/ker-run.py" --library "$<TARGET_FILE:ker-posix>"
    --worker "$<TARGET_FILE:ker-io-worker>" --app "$<TARGET_FILE:ker-native-offload-wire-test>")
set_tests_properties(native-fstack-tx-offload-metadata native-fstack-tx-offloads
    PROPERTIES TIMEOUT 105 LABELS "fstack;native-dpdk")
