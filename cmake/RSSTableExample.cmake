add_library(ker-example-rss-table STATIC "${PROJECT_SOURCE_DIR}/examples/rss-table-policy.c")
target_include_directories(ker-example-rss-table PUBLIC
    "${PROJECT_SOURCE_DIR}/examples" "${PROJECT_SOURCE_DIR}/third_party/fstack-reload"
    "${PROJECT_SOURCE_DIR}/third_party/fstack-pools"
    PRIVATE "${PROJECT_SOURCE_DIR}/third_party/fstack-rss-table")
target_link_libraries(ker-example-rss-table PUBLIC ker::packet_dispatcher)
# The unchanged source's Toeplitz initialization relies on two's-complement
# signed left-shift behavior. Scope that arithmetic contract to this object.
target_compile_options(ker-example-rss-table PRIVATE -fwrapv)
set_target_properties(ker-example-rss-table PROPERTIES
    C_STANDARD 11 C_STANDARD_REQUIRED YES C_EXTENSIONS OFF)
add_executable(ker-rss-table-router "${PROJECT_SOURCE_DIR}/examples/rss-table-router.c")
target_link_libraries(ker-rss-table-router PRIVATE ker-example-rss-table "${ker_controller_ring_pmd}")
target_compile_options(ker-rss-table-router PRIVATE -Wall -Wextra -Werror)
set_target_properties(ker-rss-table-router PROPERTIES C_STANDARD 11 C_STANDARD_REQUIRED YES C_EXTENSIONS OFF)
if(BUILD_TESTING)
    # Private copy with the original adjustment helper's predicate call site
    # redirected to the unchanged upstream counting wrappers. Production stays
    # linked to ker-example-rss-table without test instrumentation.
    add_library(ker-example-rss-table-test STATIC
        "${PROJECT_SOURCE_DIR}/examples/rss-table-policy.c")
    target_include_directories(ker-example-rss-table-test PUBLIC
        "${PROJECT_SOURCE_DIR}/examples" "${PROJECT_SOURCE_DIR}/third_party/fstack-reload"
        "${PROJECT_SOURCE_DIR}/third_party/fstack-pools"
        PRIVATE "${PROJECT_SOURCE_DIR}/third_party/fstack-rss-table")
    target_link_libraries(ker-example-rss-table-test PUBLIC ker::packet_dispatcher)
    target_compile_definitions(ker-example-rss-table-test PRIVATE EXAMPLE_RSS_TEST_RECHECK_WRAP)
    target_compile_options(ker-example-rss-table-test PRIVATE -fwrapv)
    set_target_properties(ker-example-rss-table-test PROPERTIES
        C_STANDARD 11 C_STANDARD_REQUIRED YES C_EXTENSIONS OFF)
    add_executable(ker-fstack-rss-adjust-source-test
        "${PROJECT_SOURCE_DIR}/tests/fstack-rss-adjust.c")
    target_include_directories(ker-fstack-rss-adjust-source-test PRIVATE
        "${PROJECT_SOURCE_DIR}/tests" "${PROJECT_SOURCE_DIR}/examples"
        "${PROJECT_SOURCE_DIR}/third_party/fstack-pools")
    target_link_libraries(ker-fstack-rss-adjust-source-test PRIVATE ker-example-rss-table-test)
    target_compile_options(ker-fstack-rss-adjust-source-test PRIVATE -Wall -Wextra -Werror -fwrapv)
    set_target_properties(ker-fstack-rss-adjust-source-test PROPERTIES
        C_STANDARD 11 C_STANDARD_REQUIRED YES C_EXTENSIONS OFF)
    add_test(NAME fstack-rss-adjust-original-import
        COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/fstack-rss-adjust-import.py")
    add_test(NAME fstack-rss-adjust-source
        COMMAND ker-fstack-rss-adjust-source-test)
    add_test(NAME fstack-rss-adjust-caller
        COMMAND ker-rss-table-router)
    set_tests_properties(fstack-rss-adjust-original-import PROPERTIES LABELS "fstack;provenance")
    string(REPLACE ";" ":" ker_rss_runtime_library_path "${DPDK_LIBRARY_DIRS}")
    set_tests_properties(fstack-rss-adjust-source fstack-rss-adjust-caller
        PROPERTIES LABELS "fstack;fstack-newly-adapted" TIMEOUT 30
        ENVIRONMENT "LD_LIBRARY_PATH=${ker_rss_runtime_library_path}:$ENV{LD_LIBRARY_PATH}")
endif()
