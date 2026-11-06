if(BUILD_TESTING AND KER_BUILD_LINUX_PROTOCOL_SELFTESTS AND ker_native_macvtap_profile)
    add_library(ker-linux-macvtap-proxy OBJECT tests/posix/linux-mptcp-socket-proxy.c)
    target_compile_definitions(ker-linux-macvtap-proxy PRIVATE
        KER_NETWORK_SELFTEST=1 KER_NET_DEVICE_SELFTEST=1 KER_MACVTAP_SELFTEST=1)
    target_include_directories(ker-linux-macvtap-proxy PRIVATE "${ao_headers}")
    target_compile_options(ker-linux-macvtap-proxy PRIVATE -Wall -Wextra -Werror)
    add_executable(ker-linux-macvtap-server tests/posix/linux-mptcp-socket-server.c)
    target_compile_definitions(ker-linux-macvtap-server PRIVATE
        KER_NETWORK_SELFTEST=1 KER_NET_DEVICE_SELFTEST=1 KER_MACVTAP_SELFTEST=1)
    target_include_directories(ker-linux-macvtap-server PRIVATE "${ao_headers}")
    target_compile_options(ker-linux-macvtap-server PRIVATE -Wall -Wextra -Werror)
    target_link_libraries(ker-linux-macvtap-server PRIVATE Threads::Threads ${CMAKE_DL_LIBS})
    add_dependencies(ker-linux-macvtap-server ker-posix ker-io-worker ker-app)
    add_executable(ker-linux-network-tap
        "${ker_native_source}/tools/testing/selftests/net/tap.c"
        $<TARGET_OBJECTS:ker-linux-macvtap-proxy>)
    target_include_directories(ker-linux-network-tap PRIVATE "${ao_headers}")
    target_compile_options(ker-linux-network-tap PRIVATE -Wno-error -UNDEBUG)
    target_link_libraries(ker-linux-network-tap PRIVATE Threads::Threads ${CMAKE_DL_LIBS})
    foreach(wrap socket bind connect listen accept getsockname getpeername setsockopt getsockopt
            read write ioctl recvmsg sendmsg recvfrom sendto recv send fcntl shutdown poll close open if_nametoindex)
        target_link_options(ker-linux-network-tap PRIVATE "-Wl,--wrap=${wrap}")
    endforeach()
    add_dependencies(ker-linux-network-tap ker-linux-macvtap-server ker-linux-mptcp-socket-control)
    add_test(NAME linux-original-net-tap
        COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/posix/linux-network-selftest.py"
            --program tap --binary "$<TARGET_FILE:ker-linux-network-tap>"
            --server "$<TARGET_FILE:ker-linux-macvtap-server>"
            --control "$<TARGET_FILE:ker-linux-mptcp-socket-control>"
            --launcher "${PROJECT_SOURCE_DIR}/tools/ker-run.py" --library "$<TARGET_FILE:ker-posix>"
            --worker "$<TARGET_FILE:ker-io-worker>" --pmd-dir "${ker_session_pmd_dir}"
            --manifest "${ker_native_manifest}"
            --evidence "${PROJECT_BINARY_DIR}/linux-original-net-tap.json")
    set_tests_properties(linux-original-net-tap PROPERTIES TIMEOUT 360 RUN_SERIAL TRUE
        LABELS "linux-upstream;original-linux;protocol-selftest;dpdk;macvtap-profile"
        ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")
endif()
