# Original memory policy/selection only; EAL and packet work stay caller-owned.
add_library(ker-pools src/compat/pools.c)
add_library(ker::pools ALIAS ker-pools)
target_compile_features(ker-pools PUBLIC c_std_11)
target_include_directories(ker-pools PUBLIC
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)
target_include_directories(ker-pools PRIVATE
    "${PROJECT_SOURCE_DIR}/third_party/fstack-pools"
    "${PROJECT_SOURCE_DIR}/third_party/fstack-reload"
    "${PROJECT_SOURCE_DIR}/third_party/fstack-ipc")
target_link_libraries(ker-pools PUBLIC PkgConfig::DPDK)
target_compile_definitions(ker-pools PRIVATE
    ff_global_cfg=ker_pool_upstream_configuration
    pktmbuf_pool=ker_pool_upstream_rx_pools
    ff_mbuf_gen_pool_name=ker_pool_upstream_generation_name
    ff_shared_pool_cache_size=ker_pool_upstream_cache_size
    ff_app_mbuf_pool=ker_pool_upstream_application_pool
    ff_app_mbuf_set_gen=ker_pool_upstream_set_generation)
set_target_properties(ker-pools PROPERTIES VERSION ${PROJECT_VERSION} SOVERSION 0
    EXPORT_NAME pools C_VISIBILITY_PRESET hidden)
install(TARGETS ker-pools EXPORT kerTargets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
install(FILES include/ker/pools.h DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/ker)
install(FILES third_party/fstack-pools/LICENSE third_party/fstack-pools/UPSTREAM.json
    DESTINATION ${CMAKE_INSTALL_DATADIR}/ker/fstack-pools)
