# Caller-side legacy document inspection; never linked into Ker or exported.
add_library(ker-example-fstack-config STATIC
    "${PROJECT_SOURCE_DIR}/third_party/fstack-config/ff_config.c"
    "${PROJECT_SOURCE_DIR}/examples/fstack-config-ini.c"
    "${PROJECT_SOURCE_DIR}/examples/fstack-config-policy.c")
target_include_directories(ker-example-fstack-config PUBLIC
    "${PROJECT_SOURCE_DIR}/examples" "${PROJECT_SOURCE_DIR}/third_party/fstack-reload"
    PRIVATE "${PROJECT_SOURCE_DIR}/third_party/inih" "${PROJECT_SOURCE_DIR}/third_party/fstack-ipc")
target_link_libraries(ker-example-fstack-config PUBLIC PkgConfig::DPDK)
set_source_files_properties("${PROJECT_SOURCE_DIR}/third_party/fstack-config/ff_config.c"
    PROPERTIES COMPILE_DEFINITIONS
    "_GNU_SOURCE;ff_global_cfg=example_upstream_global_cfg;ff_load_config=example_upstream_load_config;ff_unload_config=example_upstream_unload_config;dpdk_argc=example_upstream_dpdk_argc;dpdk_argv=example_upstream_dpdk_argv;short_options=example_upstream_short_options;long_options=example_upstream_long_options;FF_LOG_FILENAME_PREFIX=example_upstream_log_filename_prefix;ini_parse=example_upstream_ini_parse")
add_executable(ker-fstack-config-inspect "${PROJECT_SOURCE_DIR}/examples/fstack-config-inspect.c")
target_link_libraries(ker-fstack-config-inspect PRIVATE ker-example-fstack-config)
set_target_properties(ker-example-fstack-config ker-fstack-config-inspect PROPERTIES
    C_STANDARD 11 C_STANDARD_REQUIRED YES C_EXTENSIONS OFF)
