# Caller application policy, never linked into or exported by a Ker library.
find_library(ker_controller_ring_pmd NAMES rte_net_ring HINTS ${DPDK_LIBRARY_DIRS} NO_DEFAULT_PATH REQUIRED)
add_library(ker-example-reload-policy STATIC "${PROJECT_SOURCE_DIR}/examples/reload-controller-policy.c")
target_include_directories(ker-example-reload-policy PUBLIC
    "${PROJECT_SOURCE_DIR}/examples" "${PROJECT_SOURCE_DIR}/third_party/fstack-nginx")
target_link_libraries(ker-example-reload-policy PUBLIC ker::reload)
target_compile_options(ker-example-reload-policy PRIVATE -Wall -Wextra -Werror)
add_executable(ker-reload-controller "${PROJECT_SOURCE_DIR}/examples/reload-controller.c")
target_link_libraries(ker-reload-controller PRIVATE ker-example-reload-policy "${ker_controller_ring_pmd}")
target_compile_options(ker-reload-controller PRIVATE -Wall -Wextra -Werror)
