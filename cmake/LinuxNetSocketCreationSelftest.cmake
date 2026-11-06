if(BUILD_TESTING AND KER_BUILD_LINUX_PROTOCOL_SELFTESTS)
    add_library(ker-linux-socket-creation-proxy OBJECT tests/posix/linux-mptcp-socket-proxy.c)
    target_compile_definitions(ker-linux-socket-creation-proxy PRIVATE
        KER_NETWORK_SELFTEST=1 KER_SOCKET_CREATION_SELFTEST=1)
    target_include_directories(ker-linux-socket-creation-proxy PRIVATE "${ao_headers}")
    target_compile_options(ker-linux-socket-creation-proxy PRIVATE -Wall -Wextra -Werror)
    add_executable(ker-linux-socket-creation-server tests/posix/linux-mptcp-socket-server.c)
    target_compile_definitions(ker-linux-socket-creation-server PRIVATE
        KER_NETWORK_SELFTEST=1 KER_SOCKET_CREATION_SELFTEST=1)
    target_include_directories(ker-linux-socket-creation-server PRIVATE "${ao_headers}")
    target_compile_options(ker-linux-socket-creation-server PRIVATE -Wall -Wextra -Werror)
    target_link_libraries(ker-linux-socket-creation-server PRIVATE Threads::Threads ${CMAKE_DL_LIBS})
    add_dependencies(ker-linux-socket-creation-server ker-posix ker-io-worker ker-app)
    add_executable(ker-linux-network-socket
        "${ker_native_source}/tools/testing/selftests/net/socket.c"
        $<TARGET_OBJECTS:ker-linux-socket-creation-proxy>)
    target_include_directories(ker-linux-network-socket PRIVATE "${ao_headers}")
    target_compile_options(ker-linux-network-socket PRIVATE -Wno-error -UNDEBUG)
    target_link_libraries(ker-linux-network-socket PRIVATE Threads::Threads ${CMAKE_DL_LIBS})
    target_link_options(ker-linux-network-socket PRIVATE -Wl,--wrap=socket -Wl,--wrap=close)
    add_dependencies(ker-linux-network-socket ker-linux-socket-creation-server ker-linux-mptcp-socket-control)
    add_test(NAME linux-original-net-run_netsocktests
        COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/posix/linux-network-selftest.py"
            --program run_netsocktests --binary "$<TARGET_FILE:ker-linux-network-socket>"
            --server "$<TARGET_FILE:ker-linux-socket-creation-server>"
            --control "$<TARGET_FILE:ker-linux-mptcp-socket-control>"
            --launcher "${PROJECT_SOURCE_DIR}/tools/ker-run.py" --library "$<TARGET_FILE:ker-posix>"
            --worker "$<TARGET_FILE:ker-io-worker>" --pmd-dir "${ker_session_pmd_dir}"
            --manifest "${ker_native_manifest}"
            --evidence "${PROJECT_BINARY_DIR}/linux-original-net-run_netsocktests.json")
    set_tests_properties(linux-original-net-run_netsocktests PROPERTIES TIMEOUT 360 RUN_SERIAL TRUE
        LABELS "linux-upstream;original-linux;protocol-selftest;dpdk"
        ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")
endif()
