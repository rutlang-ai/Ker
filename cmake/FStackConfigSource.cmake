# Exercise legacy configuration documents independently of the Ker launcher.
add_library(ker-test-fstack-config STATIC
    "${PROJECT_SOURCE_DIR}/third_party/fstack-config/ff_config.c"
    "${PROJECT_SOURCE_DIR}/examples/fstack-config-ini.c"
    "${PROJECT_SOURCE_DIR}/examples/fstack-config-policy.c")
target_include_directories(ker-test-fstack-config PUBLIC
    "${PROJECT_SOURCE_DIR}/examples" "${PROJECT_SOURCE_DIR}/third_party/fstack-reload"
    PRIVATE "${PROJECT_SOURCE_DIR}/third_party/inih" "${PROJECT_SOURCE_DIR}/third_party/fstack-ipc")
target_link_libraries(ker-test-fstack-config PRIVATE PkgConfig::DPDK)
target_compile_definitions(ker-test-fstack-config PUBLIC FF_KERNEL_COEXIST)
set_target_properties(ker-test-fstack-config PROPERTIES C_STANDARD 11
    C_STANDARD_REQUIRED YES C_EXTENSIONS OFF)
set_source_files_properties("${PROJECT_SOURCE_DIR}/third_party/fstack-config/ff_config.c"
    PROPERTIES COMPILE_DEFINITIONS
    "_GNU_SOURCE;ff_global_cfg=example_upstream_global_cfg;ff_load_config=example_upstream_load_config;ff_unload_config=example_upstream_unload_config;dpdk_argc=example_upstream_dpdk_argc;dpdk_argv=example_upstream_dpdk_argv;short_options=example_upstream_short_options;long_options=example_upstream_long_options;FF_LOG_FILENAME_PREFIX=example_upstream_log_filename_prefix;ini_parse=example_upstream_ini_parse")

function(fstack_config_case case)
    add_executable("ker-${case}" fstack-config-case.c)
    target_compile_definitions("ker-${case}" PRIVATE
        "SOURCE_FUNCTION=${case}" "SOURCE_INCLUDE=fstack-config-source/${case}.inc")
    target_compile_options("ker-${case}" PRIVATE -Wall -Wextra -Werror)
    target_link_libraries("ker-${case}" PRIVATE ker-test-fstack-config)
    # Resolve transitive shared libraries from the selected DPDK build.
    target_link_options("ker-${case}" PRIVATE -Wl,--disable-new-dtags)
    set_target_properties("ker-${case}" PROPERTIES BUILD_RPATH "${DPDK_LIBRARY_DIRS}")
endfunction()

fstack_config_case(test_ff_load_config_valid_minimal_ini)
add_test(NAME fstack-config-source-test_ff_load_config_valid_minimal_ini
    COMMAND ker-test_ff_load_config_valid_minimal_ini)
set_tests_properties(fstack-config-source-test_ff_load_config_valid_minimal_ini PROPERTIES
    WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}/tests/upstream/fstack/tests/unit"
    TIMEOUT 30 LABELS fstack)

add_test(NAME fstack-config-source-import
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/fstack-config-import.py")
set_tests_properties(fstack-config-source-import PROPERTIES TIMEOUT 30 LABELS "fstack;provenance")
