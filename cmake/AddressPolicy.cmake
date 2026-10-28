# Callback dispatch is independent of EAL and the kernel runtime.
find_package(Threads REQUIRED)
add_library(ker-address-policy src/compat/address-policy.c)
add_library(ker::address_policy ALIAS ker-address-policy)
target_compile_features(ker-address-policy PUBLIC c_std_11)
target_include_directories(ker-address-policy PUBLIC
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)
target_link_libraries(ker-address-policy PRIVATE Threads::Threads)
target_compile_options(ker-address-policy PRIVATE -Wall -Wextra -Werror)
set_target_properties(ker-address-policy PROPERTIES VERSION ${PROJECT_VERSION} SOVERSION 0
    EXPORT_NAME address_policy C_VISIBILITY_PRESET hidden)
install(TARGETS ker-address-policy EXPORT kerTargets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
install(FILES include/ker/address-policy.h DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/ker)
install(FILES third_party/fstack-address-policy/LICENSE third_party/fstack-address-policy/UPSTREAM.json
    DESTINATION ${CMAKE_INSTALL_DATADIR}/ker/fstack-address-policy)
