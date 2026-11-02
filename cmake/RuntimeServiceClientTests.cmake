if(BUILD_TESTING)
    add_executable(ker-runtime-service-client-test
        tests/posix/runtime-service-client.c
        src/posix/runtime-service-client.c)
    target_include_directories(ker-runtime-service-client-test PRIVATE
        "${PROJECT_SOURCE_DIR}/src/posix")
    target_compile_features(ker-runtime-service-client-test PRIVATE c_std_11)
    target_compile_options(ker-runtime-service-client-test PRIVATE -Wall -Wextra -Werror)
    target_compile_definitions(ker-runtime-service-client-test PRIVATE
        KER_RUNTIME_SERVICE_CLIENT_TESTING=1)
    target_link_libraries(ker-runtime-service-client-test PRIVATE Threads::Threads OpenSSL::Crypto)
    add_test(NAME native-runtime-service-client-lease-reconnect
        COMMAND "$<TARGET_FILE:ker-runtime-service-client-test>")
    add_test(NAME native-runtime-service-client-wrong-profile-cleanup
        COMMAND "$<TARGET_FILE:ker-runtime-service-client-test>" --late-profile-mismatch)
    set_tests_properties(native-runtime-service-client-lease-reconnect
        PROPERTIES TIMEOUT 15 LABELS "runtime-service;fork;fd-lifetime")
    set_tests_properties(native-runtime-service-client-wrong-profile-cleanup
        PROPERTIES TIMEOUT 15 LABELS "runtime-service;fork;cleanup-only")
endif()
