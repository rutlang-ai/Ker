if(BUILD_TESTING AND KER_BUILD_LINUX_PROTOCOL_SELFTESTS AND ker_native_forwarding_profile)
    add_library(ker-linux-forwarding-preload SHARED tests/posix/linux-mptcp-socket-proxy.c)
    target_include_directories(ker-linux-forwarding-preload PRIVATE "${ao_headers}")
    target_compile_options(ker-linux-forwarding-preload PRIVATE -Wall -Wextra -Werror)
    target_compile_definitions(ker-linux-forwarding-preload PRIVATE KER_MPTCP_DIAG_PRELOAD=1 KER_FORWARDING_SELFTEST=1)
    target_link_libraries(ker-linux-forwarding-preload PRIVATE ${CMAKE_DL_LIBS})
    foreach(wrap IN LISTS diag_wraps)
        target_compile_definitions(ker-linux-forwarding-preload PRIVATE "__wrap_${wrap}=${wrap}")
    endforeach()
    add_test(NAME linux-original-forwarding-router-vid1
        COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/posix/linux-forwarding-selftest.py"
            --server "$<TARGET_FILE:ker-linux-network-server>"
            --preload "$<TARGET_FILE:ker-linux-forwarding-preload>" --tools "${KER_MPTCP_DIAG_TOOLS_DIR}"
            --launcher "${PROJECT_SOURCE_DIR}/tools/ker-run.py" --library "$<TARGET_FILE:ker-posix>"
            --worker "$<TARGET_FILE:ker-io-worker>" --pmd-dir "${ker_session_pmd_dir}"
            --manifest "${ker_native_manifest}"
            --evidence "${PROJECT_BINARY_DIR}/linux-original-forwarding-router-vid1.json")
    set_tests_properties(linux-original-forwarding-router-vid1 PROPERTIES TIMEOUT 240 RUN_SERIAL TRUE
        LABELS "linux-upstream;original-linux;protocol-selftest;dpdk;forwarding"
        ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")
endif()
