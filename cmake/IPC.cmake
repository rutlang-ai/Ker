# Generic F-Stack shared-message compatibility; requires caller-owned EAL.
file(MAKE_DIRECTORY "${PROJECT_BINARY_DIR}/ipc-include/ker/fstack")
configure_file("${PROJECT_SOURCE_DIR}/third_party/fstack-ipc/ff_msg.h"
    "${PROJECT_BINARY_DIR}/ipc-include/ker/fstack/ff_msg.h" COPYONLY)
function(ker_add_ipc_library target)
    if(ARGC GREATER 1)
        add_library(${target} ${ARGV1} "${PROJECT_SOURCE_DIR}/src/compat/ipc.c")
    else()
        add_library(${target} "${PROJECT_SOURCE_DIR}/src/compat/ipc.c")
    endif()
    target_compile_features(${target} PUBLIC c_std_11)
    target_include_directories(${target} PUBLIC
        $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
        $<BUILD_INTERFACE:${PROJECT_BINARY_DIR}/ipc-include>
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)
    target_include_directories(${target} PRIVATE "${PROJECT_SOURCE_DIR}/third_party/fstack-ipc")
    target_link_libraries(${target} PUBLIC PkgConfig::DPDK)
    target_compile_definitions(${target} PRIVATE
        ff_proc_id=ker_ipc_upstream_proc_id
        ff_set_proc_id=ker_ipc_upstream_set_proc_id
        ff_set_proc_id_str=ker_ipc_upstream_set_proc_id_str
        ff_set_gen=ker_ipc_upstream_set_gen
        ff_set_gen_str=ker_ipc_upstream_set_gen_str
        ff_set_epoch=ker_ipc_upstream_set_epoch
        ff_ipc_init=ker_ipc_upstream_init
        ff_ipc_exit=ker_ipc_upstream_exit
        ff_ipc_msg_alloc=ker_ipc_upstream_msg_alloc
        ff_ipc_msg_free=ker_ipc_upstream_msg_free
        ff_ipc_send=ker_ipc_upstream_send
        ff_ipc_recv=ker_ipc_upstream_recv
        ff_ipc_reply_stats=ker_ipc_upstream_reply_stats)
    set_target_properties(${target} PROPERTIES VERSION ${PROJECT_VERSION} SOVERSION 0
        C_VISIBILITY_PRESET hidden)
endfunction()

ker_add_ipc_library(ker-ipc)
set_target_properties(ker-ipc PROPERTIES EXPORT_NAME ipc)
add_library(ker::ipc ALIAS ker-ipc)
if(BUILD_TESTING)
    # Isolated, non-installed copy for deterministic enqueue interleaving tests.
    ker_add_ipc_library(ker-ipc-test-adapter STATIC)
    target_compile_definitions(ker-ipc-test-adapter PRIVATE KER_IPC_TESTING)
endif()
install(TARGETS ker-ipc EXPORT kerTargets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
install(FILES include/ker/ipc.h DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/ker)
install(FILES third_party/fstack-ipc/ff_msg.h DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/ker/fstack)
install(FILES third_party/fstack-ipc/LICENSE third_party/fstack-ipc/UPSTREAM.json
    DESTINATION ${CMAKE_INSTALL_DATADIR}/ker/fstack-ipc)
