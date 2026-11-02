if(BUILD_TESTING)
    add_executable(ker-runtime-service-worker-actor
        tests/posix/runtime-service-worker-actor.c
        src/posix/runtime-service-client.c)
    target_include_directories(ker-runtime-service-worker-actor PRIVATE
        "${PROJECT_SOURCE_DIR}/src/posix")
    target_compile_features(ker-runtime-service-worker-actor PRIVATE c_std_11)
    target_compile_options(ker-runtime-service-worker-actor PRIVATE -Wall -Wextra -Werror)
    target_link_libraries(ker-runtime-service-worker-actor PRIVATE Threads::Threads OpenSSL::Crypto)

    add_test(NAME native-runtime-service-actor-grant
        COMMAND "${Python3_EXECUTABLE}"
            "${PROJECT_SOURCE_DIR}/tests/posix/test_runtime_service.py")
    set_tests_properties(native-runtime-service-actor-grant
        PROPERTIES TIMEOUT 30 LABELS "fstack;runtime-service")

    add_test(NAME native-runtime-service-worker-lifetime
        COMMAND "${Python3_EXECUTABLE}"
            "${PROJECT_SOURCE_DIR}/tests/posix/runtime-service-worker-lifetime.py"
            --worker "$<TARGET_FILE:ker-io-worker>"
            --actor "$<TARGET_FILE:ker-runtime-service-worker-actor>"
            --dpdk-plugin-dir "${ker_rx_decision_dpdk_plugin_dir}")
    set_tests_properties(native-runtime-service-worker-lifetime
        PROPERTIES TIMEOUT 90 LABELS "runtime-service;dpdk;worker-lifetime")
endif()
