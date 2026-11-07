if(BUILD_TESTING AND KER_BUILD_LINUX_PROTOCOL_SELFTESTS AND ker_native_xt_string_selftests_profile)
    add_library(ker-linux-xt-string-preload SHARED tests/posix/linux-mptcp-socket-proxy.c)
    target_include_directories(ker-linux-xt-string-preload PRIVATE "${ao_headers}")
    target_compile_options(ker-linux-xt-string-preload PRIVATE -Wall -Wextra -Werror)
    target_compile_definitions(ker-linux-xt-string-preload PRIVATE
        KER_MPTCP_DIAG_PRELOAD=1 KER_NETWORK_SELFTEST=1 KER_MIXED_POLL_SELFTEST=1)
    target_link_libraries(ker-linux-xt-string-preload PRIVATE ${CMAKE_DL_LIBS})
    foreach(wrap IN LISTS diag_wraps ITEMS select)
        target_compile_definitions(ker-linux-xt-string-preload PRIVATE "__wrap_${wrap}=${wrap}")
    endforeach()
    add_executable(ker-linux-xt-string-server tests/posix/linux-mptcp-socket-server.c)
    target_compile_definitions(ker-linux-xt-string-server PRIVATE KER_NETWORK_SELFTEST=1)
    target_include_directories(ker-linux-xt-string-server PRIVATE "${ao_headers}")
    target_compile_options(ker-linux-xt-string-server PRIVATE -Wall -Wextra -Werror)
    target_link_libraries(ker-linux-xt-string-server PRIVATE Threads::Threads ${CMAKE_DL_LIBS})
    add_dependencies(ker-linux-xt-string-server ker-posix ker-io-worker ker-app
        ker-linux-xt-string-preload)
    add_test(NAME linux-original-netfilter-xt-string
        COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/posix/linux-xt-string-selftest.py"
            --server "$<TARGET_FILE:ker-linux-xt-string-server>"
            --preload "$<TARGET_FILE:ker-linux-xt-string-preload>" --tools "${KER_MPTCP_DIAG_TOOLS_DIR}"
            --launcher "${PROJECT_SOURCE_DIR}/tools/ker-run.py" --library "$<TARGET_FILE:ker-posix>"
            --worker "$<TARGET_FILE:ker-io-worker>" --pmd-dir "${ker_session_pmd_dir}"
            --manifest "${ker_native_manifest}"
            --evidence "${PROJECT_BINARY_DIR}/linux-original-netfilter-xt-string.json")
    set_tests_properties(linux-original-netfilter-xt-string PROPERTIES TIMEOUT 240 RUN_SERIAL TRUE
        LABELS "linux-upstream;original-linux;protocol-selftest;dpdk;xt-string-profile"
        ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")
endif()
