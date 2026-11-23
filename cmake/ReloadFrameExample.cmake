# Caller composes the existing reload gate/TX API; no new Ker exports.
find_library(ker_reload_frame_vdev_bus NAMES rte_bus_vdev HINTS ${DPDK_LIBRARY_DIRS} NO_DEFAULT_PATH REQUIRED)
add_library(ker-example-reload-frame STATIC examples/reload-frame-cycle.c src/posix/worker-mbuf.c)
target_include_directories(ker-example-reload-frame PUBLIC "${PROJECT_SOURCE_DIR}/examples"
    PRIVATE "${PROJECT_SOURCE_DIR}/src/posix")
target_compile_definitions(ker-example-reload-frame PRIVATE _DEFAULT_SOURCE=1)
target_compile_options(ker-example-reload-frame PRIVATE -Wall -Wextra -Werror)
target_link_libraries(ker-example-reload-frame PUBLIC ker::reload_tx "${ker_controller_ring_pmd}" "${ker_reload_frame_vdev_bus}")
set_target_properties(ker-example-reload-frame PROPERTIES C_STANDARD 11 C_STANDARD_REQUIRED YES C_EXTENSIONS OFF)
add_executable(ker-reload-frame-forwarder examples/reload-frame-forwarder.c)
target_include_directories(ker-reload-frame-forwarder PRIVATE src/posix)
target_link_libraries(ker-reload-frame-forwarder PRIVATE ker-example-reload-frame)
target_compile_options(ker-reload-frame-forwarder PRIVATE -Wall -Wextra -Werror)
if(KER_BUILD_EXAMPLES)
    install(TARGETS ker-reload-frame-forwarder RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR} COMPONENT reload-frame-example)
    # The standalone component must also carry its Ker runtime DSOs.
    foreach(dependency ker-reload-tx ker-reload ker-ipc)
        get_target_property(dependency_type ${dependency} TYPE)
        if(dependency_type STREQUAL "SHARED_LIBRARY")
            install(TARGETS ${dependency} LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
                COMPONENT reload-frame-example RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
                COMPONENT reload-frame-example)
        endif()
    endforeach()
    install(FILES "${PROJECT_SOURCE_DIR}/third_party/fstack-reload/LICENSE"
        DESTINATION ${CMAKE_INSTALL_DATADIR}/ker/examples/reload-frame COMPONENT reload-frame-example)
endif()
if(BUILD_TESTING)
    foreach(variant source no-hook dirty-start)
        add_executable(ker-reload-boot-${variant}-test tests/fstack-reload-boot.c)
        target_include_directories(ker-reload-boot-${variant}-test PRIVATE tests src/posix third_party/fstack-reload)
        target_link_libraries(ker-reload-boot-${variant}-test PRIVATE ker-example-reload-frame)
        target_compile_options(ker-reload-boot-${variant}-test PRIVATE -Wall -Wextra -Werror)
    endforeach()
    target_sources(ker-reload-boot-no-hook-test PRIVATE tests/reload-boot-no-hook.c)
    target_link_options(ker-reload-boot-no-hook-test PRIVATE -Wl,--wrap=rte_eth_add_tx_callback)
    target_sources(ker-reload-boot-dirty-start-test PRIVATE tests/reload-boot-dirty-start.c)
    target_link_options(ker-reload-boot-dirty-start-test PRIVATE -Wl,--wrap=example_reload_cycle_start)
endif()
if(BUILD_TESTING)
    find_package(Python3 REQUIRED COMPONENTS Interpreter)
    list(GET DPDK_LIBRARY_DIRS 0 ker_reload_frame_pmd_root)
    add_test(NAME fstack-reload-boot-source
        COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/posix/fstack-reload-boot.py"
            --app "$<TARGET_FILE:ker-reload-boot-source-test>" --pmd-root "${ker_reload_frame_pmd_root}" --profile source)
    add_test(NAME fstack-reload-boot-no-hook-control
        COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/posix/fstack-reload-boot.py"
            --app "$<TARGET_FILE:ker-reload-boot-no-hook-test>" --pmd-root "${ker_reload_frame_pmd_root}" --profile no-hook)
    add_test(NAME fstack-reload-boot-premature-tx-control
        COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/posix/fstack-reload-boot.py"
            --app "$<TARGET_FILE:ker-reload-boot-dirty-start-test>" --pmd-root "${ker_reload_frame_pmd_root}" --profile dirty-start)
    add_test(NAME fstack-reload-boot-consumer
        COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/posix/fstack-reload-boot.py"
            --app "$<TARGET_FILE:ker-reload-frame-forwarder>" --pmd-root "${ker_reload_frame_pmd_root}" --profile consumer)
    if(KER_BUILD_EXAMPLES)
        add_test(NAME fstack-reload-boot-installed-consumer
            COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/posix/fstack-reload-boot.py"
                --app "$<TARGET_FILE:ker-reload-frame-forwarder>" --pmd-root "${ker_reload_frame_pmd_root}" --profile consumer
                --install-example-from "${PROJECT_BINARY_DIR}" --install-bindir "${CMAKE_INSTALL_BINDIR}"
                --install-libdir "${CMAKE_INSTALL_LIBDIR}")
        set_tests_properties(fstack-reload-boot-installed-consumer PROPERTIES TIMEOUT 120 LABELS "fstack;fstack-newly-adapted;installed")
    endif()
    set_tests_properties(fstack-reload-boot-source fstack-reload-boot-no-hook-control
        fstack-reload-boot-premature-tx-control fstack-reload-boot-consumer PROPERTIES
        TIMEOUT 120 LABELS "fstack;fstack-newly-adapted")
    add_test(NAME fstack-reload-boot-original-import
        COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/fstack-reload-boot-import.py")
    set_tests_properties(fstack-reload-boot-original-import PROPERTIES LABELS "provenance;fstack")
endif()
