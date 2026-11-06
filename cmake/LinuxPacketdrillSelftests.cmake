if(BUILD_TESTING AND KER_BUILD_LINUX_PROTOCOL_SELFTESTS AND ker_native_packetdrill_profile)
    set(KER_PACKETDRILL_TOOLS_DIR "" CACHE PATH "Pinned packetdrill build with provenance.json")
    if(NOT EXISTS "${KER_PACKETDRILL_TOOLS_DIR}/packetdrill" OR
       NOT EXISTS "${KER_PACKETDRILL_TOOLS_DIR}/provenance.json")
        message(FATAL_ERROR "Build the pinned tool with tools/ci/build_packetdrill.sh and set KER_PACKETDRILL_TOOLS_DIR")
    endif()
    foreach(tool ip tc)
        if(NOT EXISTS "${KER_MPTCP_DIAG_TOOLS_DIR}/${tool}")
            message(FATAL_ERROR "Packetdrill requires pinned iproute2 ${tool} in KER_MPTCP_DIAG_TOOLS_DIR")
        endif()
    endforeach()
    add_executable(ker-linux-packetdrill-server tests/posix/linux-mptcp-socket-server.c)
    target_compile_definitions(ker-linux-packetdrill-server PRIVATE KER_PACKETDRILL_SELFTEST=1)
    target_include_directories(ker-linux-packetdrill-server PRIVATE "${ao_headers}")
    target_compile_options(ker-linux-packetdrill-server PRIVATE -Wall -Wextra -Werror)
    target_link_libraries(ker-linux-packetdrill-server PRIVATE Threads::Threads ${CMAKE_DL_LIBS})
    add_library(ker-linux-packetdrill-preload SHARED tests/posix/linux-mptcp-socket-proxy.c)
    target_compile_definitions(ker-linux-packetdrill-preload PRIVATE KER_PACKETDRILL_SELFTEST=1 KER_MPTCP_DIAG_PRELOAD=1)
    target_include_directories(ker-linux-packetdrill-preload PRIVATE "${ao_headers}")
    target_compile_options(ker-linux-packetdrill-preload PRIVATE -Wall -Wextra -Werror)
    target_link_libraries(ker-linux-packetdrill-preload PRIVATE ${CMAKE_DL_LIBS})
    foreach(wrap IN LISTS diag_wraps)
        target_compile_definitions(ker-linux-packetdrill-preload PRIVATE "__wrap_${wrap}=${wrap}")
    endforeach()
    add_test(NAME linux-original-packetdrill
        COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/posix/linux-packetdrill-selftest.py"
            --server "$<TARGET_FILE:ker-linux-packetdrill-server>"
            --preload "$<TARGET_FILE:ker-linux-packetdrill-preload>"
            --diag-preload "$<TARGET_FILE:ker-linux-mptcp-diag-preload>"
            --tool "${KER_PACKETDRILL_TOOLS_DIR}/packetdrill" --iproute "${KER_MPTCP_DIAG_TOOLS_DIR}"
            --launcher "${PROJECT_SOURCE_DIR}/tools/ker-run.py" --library "$<TARGET_FILE:ker-posix>"
            --worker "$<TARGET_FILE:ker-io-worker>" --pmd-dir "${ker_session_pmd_dir}"
            --manifest "${ker_native_manifest}" --evidence "${PROJECT_BINARY_DIR}/linux-original-packetdrill.json")
    set_tests_properties(linux-original-packetdrill PROPERTIES TIMEOUT 600 RUN_SERIAL TRUE
        LABELS "linux-upstream;original-linux;protocol-selftest;dpdk;packetdrill"
        ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")
endif()
