# Standalone generic configuration adapter. Preserve the original parser and
# isolate its symbols so applications can also link their own inih version.
add_library(ker-ini third_party/inih/ff_ini_parser.c src/compat/ini.c)
add_library(ker::ini ALIAS ker-ini)
target_compile_features(ker-ini PUBLIC c_std_11)
target_include_directories(ker-ini PUBLIC
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)
target_include_directories(ker-ini PRIVATE "${PROJECT_SOURCE_DIR}/third_party/inih")
target_compile_definitions(ker-ini PRIVATE
    ini_parse=ker_ini_upstream_parse
    ini_parse_file=ker_ini_upstream_parse_file
    ini_parse_stream=ker_ini_upstream_parse_stream)
set_target_properties(ker-ini PROPERTIES VERSION ${PROJECT_VERSION} SOVERSION 0
    EXPORT_NAME ini C_VISIBILITY_PRESET hidden)
install(TARGETS ker-ini EXPORT kerTargets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
install(FILES third_party/inih/LICENSE third_party/inih/UPSTREAM.json
    DESTINATION ${CMAKE_INSTALL_DATADIR}/ker/inih)
