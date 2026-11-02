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
    add_executable(ker-runtime-service-delegation-actor
        tests/posix/runtime-service-delegation-actor.c
        src/posix/runtime-service-client.c)
    target_include_directories(ker-runtime-service-delegation-actor PRIVATE
        "${PROJECT_SOURCE_DIR}/src/posix")
    target_compile_features(ker-runtime-service-delegation-actor PRIVATE c_std_11)
    target_compile_options(ker-runtime-service-delegation-actor PRIVATE -Wall -Wextra -Werror)
    target_link_libraries(ker-runtime-service-delegation-actor PRIVATE OpenSSL::Crypto)
    add_test(NAME native-runtime-service-client-lease-reconnect
        COMMAND "$<TARGET_FILE:ker-runtime-service-client-test>")
    add_test(NAME native-runtime-service-client-wrong-profile-cleanup
        COMMAND "$<TARGET_FILE:ker-runtime-service-client-test>" --late-profile-mismatch)
    add_test(NAME native-runtime-service-client-late-delegation-intent
        COMMAND "$<TARGET_FILE:ker-runtime-service-client-test>" --late-delegation-intent)
    add_test(NAME native-runtime-service-client-late-delegation-bind
        COMMAND "$<TARGET_FILE:ker-runtime-service-client-test>" --late-delegation-bind)
    set_tests_properties(native-runtime-service-client-lease-reconnect
        PROPERTIES TIMEOUT 15 LABELS "runtime-service;fork;fd-lifetime")
    set_tests_properties(native-runtime-service-client-wrong-profile-cleanup
        PROPERTIES TIMEOUT 15 LABELS "runtime-service;fork;cleanup-only")
    set_tests_properties(native-runtime-service-client-late-delegation-intent
        native-runtime-service-client-late-delegation-bind
        PROPERTIES TIMEOUT 15 LABELS "runtime-service;delegation;deadline;fail-closed")
    add_test(NAME native-runtime-service-delegation-worker-lifetime
        COMMAND "${Python3_EXECUTABLE}"
            "${PROJECT_SOURCE_DIR}/tests/posix/runtime-service-delegation-worker-lifetime.py"
            --worker "$<TARGET_FILE:ker-io-worker>"
            --actor "$<TARGET_FILE:ker-runtime-service-delegation-actor>"
            --dpdk-plugin-dir "${ker_rx_decision_dpdk_plugin_dir}")
    set_tests_properties(native-runtime-service-delegation-worker-lifetime
        PROPERTIES TIMEOUT 90 LABELS "runtime-service;delegation;dpdk;worker-lifetime")
    add_test(NAME native-runtime-service-delegation-lost-release-reply
        COMMAND "${Python3_EXECUTABLE}"
            "${PROJECT_SOURCE_DIR}/tests/posix/test_runtime_service.py"
            RuntimeServiceLostReleaseReplyTest.test_real_c_actor_retries_lost_final_release_reply_idempotently)
    set_tests_properties(native-runtime-service-delegation-lost-release-reply
        PROPERTIES TIMEOUT 30
            ENVIRONMENT "KER_TEST_C33_ACTOR=$<TARGET_FILE:ker-runtime-service-delegation-actor>"
            LABELS "runtime-service;delegation;release;response-loss")
endif()
