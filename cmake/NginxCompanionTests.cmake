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
        --tools "${PROJECT_BINARY_DIR}")
set_tests_properties(native-nginx-companion-installed-bundle PROPERTIES
    LABELS "native;socket-broker;nginx-companion;bundle")
