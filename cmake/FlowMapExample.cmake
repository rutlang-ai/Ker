# Caller-owned metadata policy, excluded from Ker libraries and exports.
add_library(ker-example-flow-map STATIC "${PROJECT_SOURCE_DIR}/examples/flow-map-policy.c")
target_include_directories(ker-example-flow-map PUBLIC
    "${PROJECT_SOURCE_DIR}/examples" "${PROJECT_SOURCE_DIR}/third_party/fstack-flow-map"
    PRIVATE "${PROJECT_SOURCE_DIR}/third_party/fstack-reload" "${PROJECT_SOURCE_DIR}/third_party/fstack-ipc")
target_link_libraries(ker-example-flow-map PUBLIC ker::reload)
target_compile_options(ker-example-flow-map PRIVATE -Wall -Wextra -Werror)
add_executable(ker-flow-map-router "${PROJECT_SOURCE_DIR}/examples/flow-map-router.c")
target_link_libraries(ker-flow-map-router PRIVATE ker-example-flow-map "${ker_controller_ring_pmd}")
target_compile_options(ker-flow-map-router PRIVATE -Wall -Wextra -Werror)
set_target_properties(ker-example-flow-map ker-flow-map-router PROPERTIES
    C_STANDARD 11 C_STANDARD_REQUIRED YES C_EXTENSIONS OFF)
