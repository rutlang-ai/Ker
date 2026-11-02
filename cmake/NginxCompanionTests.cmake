add_test(NAME native-nginx-companion-wire
    COMMAND "${CMAKE_COMMAND}" -E env
        "PYTHONPATH=${PROJECT_SOURCE_DIR}/tools"
        "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/posix/test_nginx_companion_wire.py")
set_tests_properties(native-nginx-companion-wire PROPERTIES
    LABELS "native;socket-broker;nginx-companion")
add_test(NAME native-nginx-companion-installed-bundle
    COMMAND "${Python3_EXECUTABLE}"
        "${PROJECT_SOURCE_DIR}/tests/posix/test_nginx_companion_bundle.py"
        --launcher "${PROJECT_BINARY_DIR}/ker-run"
        --companion "${PROJECT_BINARY_DIR}/ker-nginx-companion"
        --tools "${PROJECT_BINARY_DIR}")
set_tests_properties(native-nginx-companion-installed-bundle PROPERTIES
    LABELS "native;socket-broker;nginx-companion;bundle")

add_executable(ker-nginx-companion-test-server
    "${PROJECT_SOURCE_DIR}/tests/posix/nginx-companion-test-server.c")
target_compile_options(ker-nginx-companion-test-server PRIVATE -Wall -Wextra -Werror)
add_test(NAME native-nginx-companion-process-ownership
    COMMAND "${Python3_EXECUTABLE}"
        "${PROJECT_SOURCE_DIR}/tests/posix/test_nginx_companion_process.py"
        --server "$<TARGET_FILE:ker-nginx-companion-test-server>"
        --tools "${PROJECT_BINARY_DIR}/"
        --helper "${PROJECT_BINARY_DIR}/ker-nginx-companion")
set_tests_properties(native-nginx-companion-process-ownership PROPERTIES
    TIMEOUT 30 LABELS "native;socket-broker;nginx-companion;process-ownership")
