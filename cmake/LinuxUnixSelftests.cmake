if(BUILD_TESTING AND KER_BUILD_LINUX_PROTOCOL_SELFTESTS)
    add_library(ker-linux-unix-reference SHARED tests/posix/linux-unix-reference.c)
    target_link_libraries(ker-linux-unix-reference PRIVATE ${CMAKE_DL_LIBS})
    target_compile_options(ker-linux-unix-reference PRIVATE -Wall -Wextra -Werror)
    foreach(case diag_uid msg_oob scm_pidfd scm_rights unix_connect)
        set(source "${ker_native_source}/tools/testing/selftests/net/af_unix/${case}.c")
        add_executable(ker-linux-unix-${case} "${source}")
        target_compile_definitions(ker-linux-unix-${case} PRIVATE _GNU_SOURCE)
        target_compile_options(ker-linux-unix-${case} PRIVATE -Wno-error)
        target_link_libraries(ker-linux-unix-${case} PRIVATE Threads::Threads)
        add_test(NAME linux-original-af-unix-${case}
            COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/posix/linux-unix-selftest.py"
                --binary "$<TARGET_FILE:ker-linux-unix-${case}>" --source "${source}"
                --library "$<TARGET_FILE:ker-socket-preload>"
                --observer "$<TARGET_FILE:ker-linux-unix-reference>"
                --manifest "${ker_native_manifest}"
                --evidence "${PROJECT_BINARY_DIR}/linux-original-af-unix-${case}.json")
        set_tests_properties(linux-original-af-unix-${case} PROPERTIES TIMEOUT 180
            LABELS "linux-upstream;af-unix;host-compatibility"
            ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")
    endforeach()
endif()
