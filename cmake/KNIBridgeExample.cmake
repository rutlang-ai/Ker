# Original allocation/copy/PMD helpers in a primary caller, outside Ker exports.
find_library(ker_kni_vdev_bus NAMES rte_bus_vdev HINTS ${DPDK_LIBRARY_DIRS} NO_DEFAULT_PATH REQUIRED)
add_library(ker-example-kni-bridge STATIC examples/kni-bridge-policy.c)
target_include_directories(ker-example-kni-bridge PUBLIC examples third_party/fstack-kni-bridge third_party/fstack-reload)
target_compile_definitions(ker-example-kni-bridge PRIVATE _DEFAULT_SOURCE=1)
target_compile_options(ker-example-kni-bridge PRIVATE -Wall -Wextra -Werror)
target_link_libraries(ker-example-kni-bridge PUBLIC ker::reload PkgConfig::DPDK "${ker_kni_vdev_bus}")
set_target_properties(ker-example-kni-bridge PROPERTIES C_STANDARD 11 C_STANDARD_REQUIRED YES C_EXTENSIONS OFF)
add_executable(ker-kni-host-bridge examples/kni-host-bridge.c)
target_link_libraries(ker-kni-host-bridge PRIVATE ker-example-kni-bridge)
target_compile_options(ker-kni-host-bridge PRIVATE -Wall -Wextra -Werror)
if(BUILD_TESTING)
    find_library(ker_kni_ring_pmd NAMES rte_net_ring HINTS ${DPDK_LIBRARY_DIRS} NO_DEFAULT_PATH REQUIRED)
    add_executable(ker-kni-owner-bypass-test examples/kni-host-bridge.c)
    target_compile_definitions(ker-kni-owner-bypass-test PRIVATE KER_KNI_TEST_BYPASS_OWNER=1)
    target_link_libraries(ker-kni-owner-bypass-test PRIVATE ker-example-kni-bridge)
    target_compile_options(ker-kni-owner-bypass-test PRIVATE -Wall -Wextra -Werror)
endif()
if(KER_BUILD_EXAMPLES)
    install(TARGETS ker-kni-host-bridge RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR} COMPONENT kni-host-example)
    foreach(dependency ker-reload ker-ipc)
        get_target_property(dependency_type ${dependency} TYPE)
        if(dependency_type STREQUAL "SHARED_LIBRARY")
            install(TARGETS ${dependency} LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
                COMPONENT kni-host-example RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
                COMPONENT kni-host-example)
        endif()
    endforeach()
    install(FILES "${PROJECT_SOURCE_DIR}/third_party/fstack-kni-bridge/LICENSE"
        DESTINATION ${CMAKE_INSTALL_DATADIR}/ker/examples/kni-host COMPONENT kni-host-example)
endif()
if(BUILD_TESTING)
    add_executable(ker-kni-allocation-test tests/fstack-kni-allocation.c)
    target_include_directories(ker-kni-allocation-test PRIVATE tests)
    target_link_libraries(ker-kni-allocation-test PRIVATE ker-example-kni-bridge)
    target_compile_options(ker-kni-allocation-test PRIVATE -Wall -Wextra -Werror)
    target_link_options(ker-kni-allocation-test PRIVATE -Wl,--wrap=rte_zmalloc -Wl,--wrap=rte_exit
        -Wl,--wrap=__rte_panic -Wl,--wrap=rte_eal_hotplug_add)
    add_executable(ker-kni-owner-source-test tests/fstack-kni-owner.c)
    target_include_directories(ker-kni-owner-source-test PRIVATE tests third_party/fstack-ipc)
    target_link_libraries(ker-kni-owner-source-test PRIVATE ker-example-kni-bridge "${ker_kni_ring_pmd}")
    target_compile_options(ker-kni-owner-source-test PRIVATE -Wall -Wextra -Werror)
    target_link_options(ker-kni-owner-source-test PRIVATE -Wl,--wrap=rte_zmalloc
        -Wl,--wrap=rte_eal_process_type -Wl,--wrap=rte_eal_hotplug_add
        -Wl,--wrap=rte_eth_macaddr_get -Wl,--wrap=__rte_panic)
endif()
if(BUILD_TESTING)
    find_package(Python3 REQUIRED COMPONENTS Interpreter)
    list(GET DPDK_LIBRARY_DIRS 0 ker_kni_source_pmd_root)
    add_test(NAME fstack-kni-allocation-original-import
        COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/fstack-kni-allocation-import.py")
    set_tests_properties(fstack-kni-allocation-original-import PROPERTIES LABELS "fstack;provenance")
    add_test(NAME fstack-kni-owner-original-import
        COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/fstack-kni-owner-import.py")
    add_test(NAME fstack-kni-owner-source
        COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/posix/fstack-kni-owner-source.py"
            --app "$<TARGET_FILE:ker-kni-owner-source-test>" --pmd-root "${ker_kni_source_pmd_root}")
    add_test(NAME fstack-kni-short-tx-source
        COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/posix/fstack-kni-owner-source.py"
            --app "$<TARGET_FILE:ker-kni-owner-source-test>" --pmd-root "${ker_kni_source_pmd_root}"
            --profile short-tx)
    set_tests_properties(fstack-kni-owner-original-import PROPERTIES LABELS "fstack;provenance")
    set_tests_properties(fstack-kni-owner-source PROPERTIES LABELS "fstack;fstack-newly-adapted" TIMEOUT 30)
    set_tests_properties(fstack-kni-short-tx-source PROPERTIES LABELS "fstack;fstack-newly-adapted" TIMEOUT 30)
endif()
# The native CI profile provisions namespaces, tun and /dev/vhost-net before
# its full CTest graph. Other DPDK builds still compile the caller and harness.
if(BUILD_TESTING AND KER_WITH_NATIVE_TCP)
    list(GET DPDK_LIBRARY_DIRS 0 ker_kni_pmd_root)
    add_test(NAME native-fstack-kni-stats-oom-source
        COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/posix/fstack-kni-allocation.py"
            --app "$<TARGET_FILE:ker-kni-allocation-test>" --pmd-root "${ker_kni_pmd_root}" --profile stats)
    add_test(NAME native-fstack-kni-slot-oom-source
        COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/posix/fstack-kni-allocation.py"
            --app "$<TARGET_FILE:ker-kni-allocation-test>" --pmd-root "${ker_kni_pmd_root}" --profile slot)
    add_test(NAME native-fstack-kni-stats-real-exit
        COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/posix/fstack-kni-allocation.py"
            --app "$<TARGET_FILE:ker-kni-allocation-test>" --pmd-root "${ker_kni_pmd_root}" --profile fatal-stats)
    add_test(NAME native-fstack-kni-slot-real-panic
        COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/posix/fstack-kni-allocation.py"
            --app "$<TARGET_FILE:ker-kni-allocation-test>" --pmd-root "${ker_kni_pmd_root}" --profile fatal-slot)
    add_test(NAME native-fstack-kni-allocation-bypass-control
        COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/posix/fstack-kni-allocation.py"
            --app "$<TARGET_FILE:ker-kni-allocation-test>" --pmd-root "${ker_kni_pmd_root}" --profile bypass)
    add_test(NAME native-fstack-kni-host-consumer
        COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/posix/fstack-kni-allocation.py"
            --app "$<TARGET_FILE:ker-kni-host-bridge>" --pmd-root "${ker_kni_pmd_root}" --profile consumer)
    add_test(NAME native-fstack-kni-owner-bypass-control
        COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/posix/fstack-kni-allocation.py"
            --app "$<TARGET_FILE:ker-kni-owner-bypass-test>" --pmd-root "${ker_kni_pmd_root}" --profile owner-bypass)
    if(KER_BUILD_EXAMPLES)
        add_test(NAME native-fstack-kni-host-installed-consumer
            COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/posix/fstack-kni-allocation.py"
                --app "$<TARGET_FILE:ker-kni-host-bridge>" --pmd-root "${ker_kni_pmd_root}" --profile consumer
                --install-example-from "${PROJECT_BINARY_DIR}" --install-bindir "${CMAKE_INSTALL_BINDIR}"
                --install-libdir "${CMAKE_INSTALL_LIBDIR}")
        set_tests_properties(native-fstack-kni-host-installed-consumer PROPERTIES TIMEOUT 60 LABELS "fstack;fstack-newly-adapted;installed")
    endif()
    set_tests_properties(native-fstack-kni-stats-oom-source native-fstack-kni-slot-oom-source
        native-fstack-kni-stats-real-exit native-fstack-kni-slot-real-panic native-fstack-kni-allocation-bypass-control
        native-fstack-kni-host-consumer native-fstack-kni-owner-bypass-control
        PROPERTIES TIMEOUT 60 LABELS "fstack;fstack-newly-adapted")
endif()
