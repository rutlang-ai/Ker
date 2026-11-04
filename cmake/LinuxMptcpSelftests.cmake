if(BUILD_TESTING AND KER_BUILD_LINUX_PROTOCOL_SELFTESTS)
    set(mptcp_source "${ker_native_source}/tools/testing/selftests/net/mptcp/mptcp_connect.c")
    add_library(ker-linux-mptcp-ready OBJECT tests/posix/linux-mptcp-ready.c)
    target_compile_options(ker-linux-mptcp-ready PRIVATE -Wall -Wextra -Werror)
    add_executable(ker-linux-mptcp-connect "${mptcp_source}" $<TARGET_OBJECTS:ker-linux-mptcp-ready>)
    add_dependencies(ker-linux-mptcp-connect ker-app ker-posix ker-io-worker)
    target_compile_options(ker-linux-mptcp-connect PRIVATE -Wno-error -UNDEBUG)
    target_link_options(ker-linux-mptcp-connect PRIVATE -Wl,--wrap=listen -Wl,--wrap=open)
    target_link_libraries(ker-linux-mptcp-connect PRIVATE ${CMAKE_DL_LIBS})
    foreach(family 4 6)
        foreach(role client server)
            add_test(NAME linux-original-mptcp-ipv${family}-${role}
                COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/posix/linux-mptcp-selftest.py"
                    --binary "$<TARGET_FILE:ker-linux-mptcp-connect>" --source "${mptcp_source}"
                    --launcher "${PROJECT_SOURCE_DIR}/tools/ker-run.py"
                    --library "$<TARGET_FILE:ker-posix>" --worker "$<TARGET_FILE:ker-io-worker>"
                    --pmd-dir "${ker_session_pmd_dir}" --manifest "${ker_native_manifest}"
                    --family ${family} --role ${role}
                    --evidence "${PROJECT_BINARY_DIR}/linux-original-mptcp-ipv${family}-${role}.json")
            set_tests_properties(linux-original-mptcp-ipv${family}-${role} PROPERTIES TIMEOUT 180
                LABELS "linux-upstream;original-linux;mptcp;protocol-selftest;dpdk"
                ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")
        endforeach()
    endforeach()
endif()
