if(KER_BUILD_EXAMPLES OR BUILD_TESTING)
    add_library(ker-example-host-mapping STATIC examples/host-mapping.c)
    target_include_directories(ker-example-host-mapping PUBLIC "${PROJECT_SOURCE_DIR}/examples"
        "${PROJECT_SOURCE_DIR}/third_party/fstack-host-readiness"
        PRIVATE "${PROJECT_SOURCE_DIR}/third_party/fstack-reload")
    target_compile_options(ker-example-host-mapping PRIVATE -Wall -Wextra -Werror)
    set_target_properties(ker-example-host-mapping PROPERTIES C_STANDARD 11 C_STANDARD_REQUIRED YES C_EXTENSIONS OFF)
endif()
if(BUILD_TESTING)
    list(GET DPDK_LIBRARY_DIRS 0 ker_host_mapping_pmd_root)
    add_library(ker-example-host-mapping-release STATIC examples/host-mapping.c)
    target_include_directories(ker-example-host-mapping-release PUBLIC "${PROJECT_SOURCE_DIR}/examples"
        "${PROJECT_SOURCE_DIR}/third_party/fstack-host-readiness"
        PRIVATE "${PROJECT_SOURCE_DIR}/third_party/fstack-reload")
    target_compile_definitions(ker-example-host-mapping-release PRIVATE NDEBUG=1)
    target_compile_options(ker-example-host-mapping-release PRIVATE -Wall -Wextra -Werror)
    foreach(mode debug release)
        add_executable(ker-host-mmap-fatal-${mode}-test tests/posix/fstack-host-mmap-fatal.c)
        target_include_directories(ker-host-mmap-fatal-${mode}-test PRIVATE
            "${PROJECT_SOURCE_DIR}/include" "${PROJECT_SOURCE_DIR}/tests")
        if(mode STREQUAL release)
            target_link_libraries(ker-host-mmap-fatal-${mode}-test PRIVATE ker-example-host-mapping-release ${CMAKE_DL_LIBS})
            target_compile_definitions(ker-host-mmap-fatal-${mode}-test PRIVATE NDEBUG=1)
        else()
            target_link_libraries(ker-host-mmap-fatal-${mode}-test PRIVATE ker-example-host-mapping ${CMAKE_DL_LIBS})
        endif()
        target_compile_options(ker-host-mmap-fatal-${mode}-test PRIVATE -Wall -Wextra -Werror)
    endforeach()
    add_executable(ker-host-mmap-return-control-test tests/posix/fstack-host-mmap-fatal.c
        tests/posix/host-mmap-return-control.c)
    target_include_directories(ker-host-mmap-return-control-test PRIVATE
        "${PROJECT_SOURCE_DIR}/include" "${PROJECT_SOURCE_DIR}/tests")
    target_link_libraries(ker-host-mmap-return-control-test PRIVATE ker-example-host-mapping ${CMAKE_DL_LIBS})
    target_link_options(ker-host-mmap-return-control-test PRIVATE -Wl,--wrap=example_host_mmap)
    target_compile_options(ker-host-mmap-return-control-test PRIVATE -Wall -Wextra -Werror)
    add_test(NAME native-fstack-host-mmap-fatal-debug
        COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/posix/fstack-host-readiness.py"
            --launcher "${PROJECT_SOURCE_DIR}/tools/ker-run.py" --library "$<TARGET_FILE:ker-posix>"
            --worker "$<TARGET_FILE:ker-io-worker>" --app "$<TARGET_FILE:ker-host-mmap-fatal-debug-test>"
            --pmd-root "${ker_host_mapping_pmd_root}" --profile mmap-fatal)
    add_test(NAME native-fstack-host-mmap-fatal-release
        COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/posix/fstack-host-readiness.py"
            --launcher "${PROJECT_SOURCE_DIR}/tools/ker-run.py" --library "$<TARGET_FILE:ker-posix>"
            --worker "$<TARGET_FILE:ker-io-worker>" --app "$<TARGET_FILE:ker-host-mmap-fatal-release-test>"
            --pmd-root "${ker_host_mapping_pmd_root}" --profile mmap-fatal)
    add_test(NAME native-fstack-host-mmap-fatal-return-control
        COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/posix/fstack-host-readiness.py"
            --launcher "${PROJECT_SOURCE_DIR}/tools/ker-run.py" --library "$<TARGET_FILE:ker-posix>"
            --worker "$<TARGET_FILE:ker-io-worker>" --app "$<TARGET_FILE:ker-host-mmap-return-control-test>"
            --pmd-root "${ker_host_mapping_pmd_root}" --profile mmap-return)
    set_tests_properties(native-fstack-host-mmap-fatal-debug native-fstack-host-mmap-fatal-release
        native-fstack-host-mmap-fatal-return-control PROPERTIES TIMEOUT 60 LABELS "native-tcp;fstack;fstack-newly-adapted")
    add_test(NAME fstack-host-mmap-original-import
        COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/fstack-host-mmap-import.py")
    set_tests_properties(fstack-host-mmap-original-import PROPERTIES LABELS "provenance;fstack")
endif()
