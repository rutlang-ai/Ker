# Optional ownership bridge; ordinary borrowed callback dispatch stays independent.
add_library(ker-peer-dispatcher src/compat/peer-dispatcher.c)
add_library(ker::peer_dispatcher ALIAS ker-peer-dispatcher)
target_link_libraries(ker-peer-dispatcher PUBLIC ker::packet_dispatcher ker::reload)
target_compile_features(ker-peer-dispatcher PUBLIC c_std_11)
target_compile_options(ker-peer-dispatcher PRIVATE -Wall -Wextra -Werror)
set_target_properties(ker-peer-dispatcher PROPERTIES VERSION ${PROJECT_VERSION} SOVERSION 0
    EXPORT_NAME peer_dispatcher C_VISIBILITY_PRESET hidden C_STANDARD 11 C_STANDARD_REQUIRED YES C_EXTENSIONS OFF)
install(TARGETS ker-peer-dispatcher EXPORT kerTargets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
install(FILES include/ker/peer-dispatcher.h DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/ker)
