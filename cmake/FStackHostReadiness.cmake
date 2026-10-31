# Caller-owned compatibility helpers; no addition to Ker's exported ABI.
if(KER_BUILD_EXAMPLES OR BUILD_TESTING)
    add_library(ker-example-host-readiness STATIC examples/host-readiness.c)
    target_include_directories(ker-example-host-readiness PUBLIC "${PROJECT_SOURCE_DIR}/examples"
        PRIVATE "${PROJECT_SOURCE_DIR}/third_party/fstack-host-readiness")
    target_compile_options(ker-example-host-readiness PRIVATE -Wall -Wextra -Werror)
    set_target_properties(ker-example-host-readiness PROPERTIES C_STANDARD 11 C_STANDARD_REQUIRED YES C_EXTENSIONS OFF)
    add_executable(ker-host-readiness-echo examples/host-readiness-echo.c)
    target_include_directories(ker-host-readiness-echo PRIVATE "${PROJECT_SOURCE_DIR}/include")
    target_link_libraries(ker-host-readiness-echo PRIVATE ker-example-host-readiness ker-example-host-mapping ${CMAKE_DL_LIBS})
    target_compile_options(ker-host-readiness-echo PRIVATE -Wall -Wextra -Werror)
    if(KER_BUILD_EXAMPLES)
        install(TARGETS ker-host-readiness-echo RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
            COMPONENT host-readiness-example)
        install(FILES "${PROJECT_SOURCE_DIR}/third_party/fstack-host-readiness/LICENSE"
            DESTINATION ${CMAKE_INSTALL_DATADIR}/ker/examples/host-readiness
            COMPONENT host-readiness-example)
    endif()
endif()
if(BUILD_TESTING)
    list(GET DPDK_LIBRARY_DIRS 0 ker_host_readiness_pmd_root)
    add_executable(ker-host-readiness-source-test tests/posix/fstack-host-readiness.c)
    target_include_directories(ker-host-readiness-source-test PRIVATE
        "${PROJECT_SOURCE_DIR}/include" "${PROJECT_SOURCE_DIR}/tests")
    target_link_libraries(ker-host-readiness-source-test PRIVATE ker-example-host-readiness ${CMAKE_DL_LIBS})
    target_compile_options(ker-host-readiness-source-test PRIVATE -Wall -Wextra -Werror)
    add_executable(ker-host-readiness-mod-failure-test tests/posix/fstack-host-readiness.c
        tests/posix/host-readiness-mod-failure.c)
    target_include_directories(ker-host-readiness-mod-failure-test PRIVATE
        "${PROJECT_SOURCE_DIR}/include" "${PROJECT_SOURCE_DIR}/tests")
    target_link_libraries(ker-host-readiness-mod-failure-test PRIVATE ker-example-host-readiness ${CMAKE_DL_LIBS})
    target_compile_options(ker-host-readiness-mod-failure-test PRIVATE -Wall -Wextra -Werror)
    target_link_options(ker-host-readiness-mod-failure-test PRIVATE -Wl,--wrap=epoll_ctl)
    add_test(NAME native-fstack-host-readiness-idempotent
        COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/posix/fstack-host-readiness.py"
            --launcher "${PROJECT_SOURCE_DIR}/tools/ker-run.py" --library "$<TARGET_FILE:ker-posix>"
            --worker "$<TARGET_FILE:ker-io-worker>" --app "$<TARGET_FILE:ker-host-readiness-source-test>"
            --pmd-root "${ker_host_readiness_pmd_root}" --profile source)
    add_test(NAME native-fstack-host-readiness-consumer
        COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/posix/fstack-host-readiness.py"
            --launcher "${PROJECT_SOURCE_DIR}/tools/ker-run.py" --library "$<TARGET_FILE:ker-posix>"
            --worker "$<TARGET_FILE:ker-io-worker>" --app "$<TARGET_FILE:ker-host-readiness-echo>"
            --pmd-root "${ker_host_readiness_pmd_root}" --profile consumer)
    add_test(NAME native-fstack-host-readiness-mod-failure
        COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/posix/fstack-host-readiness.py"
            --launcher "${PROJECT_SOURCE_DIR}/tools/ker-run.py" --library "$<TARGET_FILE:ker-posix>"
            --worker "$<TARGET_FILE:ker-io-worker>" --app "$<TARGET_FILE:ker-host-readiness-mod-failure-test>"
            --pmd-root "${ker_host_readiness_pmd_root}" --profile fault)
    if(KER_BUILD_EXAMPLES)
        add_test(NAME native-fstack-host-readiness-installed-consumer
            COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/posix/fstack-host-readiness.py"
                --launcher "${PROJECT_SOURCE_DIR}/tools/ker-run.py" --library "$<TARGET_FILE:ker-posix>"
                --worker "$<TARGET_FILE:ker-io-worker>" --app "$<TARGET_FILE:ker-host-readiness-echo>"
                --pmd-root "${ker_host_readiness_pmd_root}" --profile consumer
                --install-example-from "${PROJECT_BINARY_DIR}" --install-bindir "${CMAKE_INSTALL_BINDIR}")
        set_tests_properties(native-fstack-host-readiness-installed-consumer
            PROPERTIES TIMEOUT 60 LABELS "native-tcp;native-udp;fstack;fstack-newly-adapted;installed")
    endif()
    set_tests_properties(native-fstack-host-readiness-idempotent native-fstack-host-readiness-consumer
        native-fstack-host-readiness-mod-failure PROPERTIES TIMEOUT 60 LABELS "native-tcp;native-udp;fstack;fstack-newly-adapted")
    add_test(NAME fstack-host-readiness-original-import
        COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/fstack-host-readiness-import.py")
    set_tests_properties(fstack-host-readiness-original-import PROPERTIES LABELS "provenance;fstack")
endif()
