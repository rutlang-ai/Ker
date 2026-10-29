# Optional byte/mbuf TX ownership adapter; protocol and peer policy stay with callers.
add_library(ker-reload-tx src/compat/reload-tx.c)
add_library(ker::reload_tx ALIAS ker-reload-tx)
target_link_libraries(ker-reload-tx PUBLIC ker::reload)
target_compile_options(ker-reload-tx PRIVATE -Wall -Wextra -Werror)
set_target_properties(ker-reload-tx PROPERTIES VERSION ${PROJECT_VERSION} SOVERSION 0
    EXPORT_NAME reload_tx C_VISIBILITY_PRESET hidden C_STANDARD 11 C_STANDARD_REQUIRED YES C_EXTENSIONS OFF)
install(TARGETS ker-reload-tx EXPORT kerTargets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
