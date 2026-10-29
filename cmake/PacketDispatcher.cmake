add_library(ker-packet-dispatcher src/compat/packet-dispatcher.c)
add_library(ker::packet_dispatcher ALIAS ker-packet-dispatcher)
target_compile_features(ker-packet-dispatcher PUBLIC c_std_11)
target_include_directories(ker-packet-dispatcher PUBLIC
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)
target_link_libraries(ker-packet-dispatcher PUBLIC PkgConfig::DPDK PRIVATE Threads::Threads)
target_compile_options(ker-packet-dispatcher PRIVATE -Wall -Wextra -Werror)
set_target_properties(ker-packet-dispatcher PROPERTIES VERSION ${PROJECT_VERSION} SOVERSION 0
    EXPORT_NAME packet_dispatcher C_VISIBILITY_PRESET hidden)
install(TARGETS ker-packet-dispatcher EXPORT kerTargets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
install(FILES third_party/fstack-dispatcher/LICENSE third_party/fstack-dispatcher/UPSTREAM.json
    DESTINATION ${CMAKE_INSTALL_DATADIR}/ker/fstack-dispatcher)
