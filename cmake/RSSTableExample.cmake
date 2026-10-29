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
