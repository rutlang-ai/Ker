# Caller-owned DPDK frame conversion, outside Ker's borrowed Linux callbacks.
file(GLOB ker_owned_ring_pmds "${KER_DPDK_PKGCONFIG_DIR}/../dpdk/pmds-*/librte_net_ring.so")
list(GET ker_owned_ring_pmds 0 ker_owned_ring_pmd)
find_library(ker_owned_vdev_bus NAMES rte_bus_vdev HINTS ${DPDK_LIBRARY_DIRS} NO_DEFAULT_PATH REQUIRED)
add_library(ker-example-owned-frame STATIC examples/owned-frame-send.c examples/owned-frame-upstream.c
    examples/owned-frame-port.c src/posix/worker-mbuf.c)
target_include_directories(ker-example-owned-frame PUBLIC "${PROJECT_SOURCE_DIR}/examples"
    PRIVATE "${PROJECT_SOURCE_DIR}/src/posix" "${PROJECT_SOURCE_DIR}/third_party/fstack-owned-send" "${PROJECT_SOURCE_DIR}/third_party/fstack-rss-table"
    "${PROJECT_SOURCE_DIR}/third_party/fstack-reload")
target_link_libraries(ker-example-owned-frame PUBLIC PkgConfig::DPDK "${ker_owned_ring_pmd}" "${ker_owned_vdev_bus}")
target_compile_definitions(ker-example-owned-frame PRIVATE _DEFAULT_SOURCE=1)
target_compile_options(ker-example-owned-frame PRIVATE -Wall -Wextra -Werror)
set_target_properties(ker-example-owned-frame PROPERTIES C_STANDARD 11 C_STANDARD_REQUIRED YES C_EXTENSIONS OFF)
add_executable(ker-owned-frame-forwarder examples/owned-frame-forwarder.c)
target_link_libraries(ker-owned-frame-forwarder PRIVATE ker-example-owned-frame)
target_compile_options(ker-owned-frame-forwarder PRIVATE -Wall -Wextra -Werror)
if(KER_BUILD_EXAMPLES)
    install(TARGETS ker-owned-frame-forwarder RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR} COMPONENT owned-frame-example)
    install(FILES "${PROJECT_SOURCE_DIR}/third_party/fstack-owned-send/LICENSE"
        DESTINATION ${CMAKE_INSTALL_DATADIR}/ker/examples/owned-frame COMPONENT owned-frame-example)
endif()
if(BUILD_TESTING)
    foreach(variant source no-free copy-success)
        add_executable(ker-owned-send-${variant}-test tests/fstack-owned-send.c)
        target_include_directories(ker-owned-send-${variant}-test PRIVATE tests)
        target_link_libraries(ker-owned-send-${variant}-test PRIVATE ker-example-owned-frame)
        target_compile_options(ker-owned-send-${variant}-test PRIVATE -Wall -Wextra -Werror)
    endforeach()
    target_sources(ker-owned-send-no-free-test PRIVATE tests/owned-send-no-input-free.c)
    target_link_options(ker-owned-send-no-free-test PRIVATE -Wl,--wrap=example_owned_input_free)
    target_sources(ker-owned-send-copy-success-test PRIVATE tests/owned-send-copy-success.c)
    target_link_options(ker-owned-send-copy-success-test PRIVATE -Wl,--wrap=example_owned_copydata)
endif()
if(BUILD_TESTING)
    find_package(Python3 REQUIRED COMPONENTS Interpreter)
    list(GET DPDK_LIBRARY_DIRS 0 ker_owned_send_pmd_root)
    add_test(NAME fstack-owned-send-null
        COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/posix/fstack-owned-send.py"
            --app "$<TARGET_FILE:ker-owned-send-source-test>" --pmd-root "${ker_owned_send_pmd_root}" --profile null)
    add_test(NAME fstack-owned-send-copy-failure
        COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/posix/fstack-owned-send.py"
            --app "$<TARGET_FILE:ker-owned-send-source-test>" --pmd-root "${ker_owned_send_pmd_root}" --profile copy)
    add_test(NAME fstack-owned-send-no-free-control
        COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/posix/fstack-owned-send.py"
            --app "$<TARGET_FILE:ker-owned-send-no-free-test>" --pmd-root "${ker_owned_send_pmd_root}" --profile no-free)
    add_test(NAME fstack-owned-send-false-copy-control
        COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/posix/fstack-owned-send.py"
            --app "$<TARGET_FILE:ker-owned-send-copy-success-test>" --pmd-root "${ker_owned_send_pmd_root}" --profile copy-success)
    add_test(NAME fstack-owned-send-consumer
        COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/posix/fstack-owned-send.py"
            --app "$<TARGET_FILE:ker-owned-frame-forwarder>" --pmd-root "${ker_owned_send_pmd_root}" --profile consumer)
    if(KER_BUILD_EXAMPLES)
        add_test(NAME fstack-owned-send-installed-consumer
            COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/posix/fstack-owned-send.py"
                --app "$<TARGET_FILE:ker-owned-frame-forwarder>" --pmd-root "${ker_owned_send_pmd_root}" --profile consumer
                --install-example-from "${PROJECT_BINARY_DIR}" --install-bindir "${CMAKE_INSTALL_BINDIR}")
        set_tests_properties(fstack-owned-send-installed-consumer PROPERTIES TIMEOUT 120 LABELS "fstack;fstack-newly-adapted;installed")
    endif()
    set_tests_properties(fstack-owned-send-null fstack-owned-send-copy-failure fstack-owned-send-no-free-control
        fstack-owned-send-false-copy-control fstack-owned-send-consumer PROPERTIES TIMEOUT 120 LABELS "fstack;fstack-newly-adapted")
    add_test(NAME fstack-owned-send-original-import
        COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/fstack-owned-send-import.py")
    set_tests_properties(fstack-owned-send-original-import PROPERTIES LABELS "provenance;fstack")
endif()
