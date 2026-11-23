function(ker_add_ff_owner_requests_tests)

    add_executable(ker-ff-owner-requests-parser-test
        "${PROJECT_SOURCE_DIR}/tests/posix/ff-owner-requests-parser.c"
        "${PROJECT_SOURCE_DIR}/src/posix/ff-owner-requests-parse.c")
    target_include_directories(ker-ff-owner-requests-parser-test PRIVATE
        "${PROJECT_SOURCE_DIR}/src/posix")
    target_compile_features(ker-ff-owner-requests-parser-test PRIVATE c_std_11)
    target_compile_options(ker-ff-owner-requests-parser-test PRIVATE -Wall -Wextra -Werror)
    add_test(NAME ff-owner-requests-diag-parser
        COMMAND "$<TARGET_FILE:ker-ff-owner-requests-parser-test>")
    set_tests_properties(ff-owner-requests-diag-parser PROPERTIES
        LABELS "native-tcp;reqsk;diag-parser")

    add_executable(ker-ff-owner-requests-layout-test
        "${PROJECT_SOURCE_DIR}/tests/posix/ff-owner-requests-layout.c")
    target_include_directories(ker-ff-owner-requests-layout-test SYSTEM PRIVATE
        "${ker_native_source}/include/uapi" "${ker_native_source}/include"
        "${ker_native_kernel}/arch/lkl/include/generated/uapi"
        "${ker_native_kernel}/arch/lkl/include/generated"
        "${ker_native_source}/arch/lkl/include/uapi"
        "${ker_native_source}/arch/lkl/include")
    target_compile_definitions(ker-ff-owner-requests-layout-test PRIVATE __KERNEL__)
    target_include_directories(ker-ff-owner-requests-layout-test PRIVATE
        "${PROJECT_SOURCE_DIR}/src/posix")
    target_compile_options(ker-ff-owner-requests-layout-test PRIVATE -Wall -Wextra -Werror)
    add_test(NAME ff-owner-requests-pinned-uapi-layout
        COMMAND "$<TARGET_FILE:ker-ff-owner-requests-layout-test>")
    set_tests_properties(ff-owner-requests-pinned-uapi-layout PROPERTIES
        LABELS "native-tcp;reqsk;diag-layout")

    add_executable(ker-ff-owner-requests-runtime-test
        "${PROJECT_SOURCE_DIR}/tests/posix/ff-owner-requests-runtime.c")
    target_include_directories(ker-ff-owner-requests-runtime-test PRIVATE
        "${PROJECT_SOURCE_DIR}/src/posix" "${PROJECT_SOURCE_DIR}/include")
    target_compile_features(ker-ff-owner-requests-runtime-test PRIVATE c_std_11)
    target_compile_options(ker-ff-owner-requests-runtime-test PRIVATE -Wall -Wextra -Werror)

    get_target_property(ker_posix_sources ker-posix SOURCES)
    foreach(source ff-owner-requests-diag.c ff-owner-requests-parse.c)
        set(path "${PROJECT_SOURCE_DIR}/src/posix/${source}")
        list(FIND ker_posix_sources "${path}" index)
        if(index EQUAL -1)
            list(APPEND ker_posix_sources "${path}")
        endif()
    endforeach()
    get_target_property(ker_posix_definitions ker-posix COMPILE_DEFINITIONS)
    get_target_property(ker_posix_options ker-posix COMPILE_OPTIONS)
    get_target_property(ker_posix_includes ker-posix INCLUDE_DIRECTORIES)
    foreach(property ker_posix_definitions ker_posix_options ker_posix_includes)
        if(NOT "${${property}}" OR "${${property}}" MATCHES "-NOTFOUND$")
            set(${property})
        endif()
    endforeach()
    add_library(ker-posix-ff-owner-requests-test-runtime SHARED
        ${ker_posix_sources}
        "${PROJECT_SOURCE_DIR}/tests/posix/ff-owner-requests-test-hooks.c")
    target_include_directories(ker-posix-ff-owner-requests-test-runtime PRIVATE
        "${PROJECT_SOURCE_DIR}/src/posix" "${PROJECT_SOURCE_DIR}/include"
        ${ker_posix_includes})
    target_include_directories(ker-posix-ff-owner-requests-test-runtime SYSTEM PRIVATE
        "${ker_native_source}/tools/lkl/include" "${ker_native_tools}/include")
    target_compile_definitions(ker-posix-ff-owner-requests-test-runtime PRIVATE
        ${ker_posix_definitions} KER_NATIVE_KERNEL_RELEASE="${ker_native_release}")
    target_compile_features(ker-posix-ff-owner-requests-test-runtime PRIVATE c_std_11)
    target_compile_options(ker-posix-ff-owner-requests-test-runtime PRIVATE
        ${ker_posix_options} -Wall -Wextra -Werror)
    file(READ "${PROJECT_SOURCE_DIR}/src/posix/exports.map" owner_exports)
    string(REPLACE "local: *;"
        "ker_ff_owner_requests_test_snapshot; ker_ff_owner_requests_test_syncookies; ker_ff_owner_requests_test_fastopen; local: *;"
        owner_test_exports "${owner_exports}")
    file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/ff-owner-requests-test-exports.map"
        "${owner_test_exports}")
    target_link_options(ker-posix-ff-owner-requests-test-runtime PRIVATE
        -Wl,--no-undefined
        "-Wl,--version-script=${CMAKE_CURRENT_BINARY_DIR}/ff-owner-requests-test-exports.map")
    target_link_libraries(ker-posix-ff-owner-requests-test-runtime PRIVATE
        "${ker_native_tools}/liblkl.a" Threads::Threads ${CMAKE_DL_LIBS} rt)
    target_link_libraries(ker-ff-owner-requests-runtime-test PRIVATE
        ker-posix-ff-owner-requests-test-runtime)

    add_test(NAME native-ff-owner-requests
        COMMAND "${Python3_EXECUTABLE}"
            "${PROJECT_SOURCE_DIR}/tests/posix/native-ff-owner-requests.py"
            --launcher "${PROJECT_SOURCE_DIR}/tools/ker-run.py"
            --library "$<TARGET_FILE:ker-posix-ff-owner-requests-test-runtime>"
            --worker "$<TARGET_FILE:ker-io-worker>"
            --dpdk-plugin-dir "${ker_session_pmd_dir}"
            --runtime-test "$<TARGET_FILE:ker-ff-owner-requests-runtime-test>")
    set_tests_properties(native-ff-owner-requests PROPERTIES TIMEOUT 90
        LABELS "native-tcp;reqsk;owner-mark;ack-loss")
endfunction()
