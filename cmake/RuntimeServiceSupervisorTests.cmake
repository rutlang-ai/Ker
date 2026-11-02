if(BUILD_TESTING)
    add_test(NAME native-runtime-service-actor-grant
        COMMAND "${Python3_EXECUTABLE}"
            "${PROJECT_SOURCE_DIR}/tests/posix/test_runtime_service.py")
    set_tests_properties(native-runtime-service-actor-grant
        PROPERTIES TIMEOUT 30 LABELS "fstack;runtime-service")
endif()
