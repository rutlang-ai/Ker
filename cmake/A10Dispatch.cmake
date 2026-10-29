# Application metadata policy, never linked into or exported by Ker libraries.
add_library(ker-example-a10-dispatch STATIC "${PROJECT_SOURCE_DIR}/examples/a10-dispatch-policy.c")
target_link_libraries(ker-example-a10-dispatch PUBLIC ker-example-flow-map ker::peer_dispatcher)
target_compile_options(ker-example-a10-dispatch PRIVATE -Wall -Wextra -Werror)
set_target_properties(ker-example-a10-dispatch PROPERTIES C_STANDARD 11 C_STANDARD_REQUIRED YES C_EXTENSIONS OFF)
