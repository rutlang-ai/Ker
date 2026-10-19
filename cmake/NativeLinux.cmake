# The full native kernel is isolated from the lightweight imported-header port.
# Protocol objects come from a pinned Linux stable tree, using the LKL arch port.
set(KER_NATIVE_LINUX_BUILD "${PROJECT_SOURCE_DIR}/build-native-linux" CACHE PATH
    "Output directory from tools/build-native-linux.py")
set(ker_native_manifest "${KER_NATIVE_LINUX_BUILD}/native-linux.json")
if(NOT EXISTS "${ker_native_manifest}")
    message(FATAL_ERROR "Run python3 tools/build-native-linux.py --build ${KER_NATIVE_LINUX_BUILD} first")
endif()
include("${PROJECT_SOURCE_DIR}/cmake/VerifyNativeLinuxFingerprint.cmake")
ker_verify_native_linux_fingerprint("${PROJECT_SOURCE_DIR}" "${ker_native_manifest}"
    "${PROJECT_SOURCE_DIR}/tools/build-native-linux.py")
file(READ "${ker_native_manifest}" ker_native_json)
string(JSON ker_native_source GET "${ker_native_json}" source)
string(JSON ker_native_kernel GET "${ker_native_json}" kernel)
string(JSON ker_native_release GET "${ker_native_json}" release)
file(READ "${PROJECT_SOURCE_DIR}/config/native-linux.json" ker_native_pins)
foreach(dependency linux lkl)
    string(JSON selected GET "${ker_native_json}" ${dependency} revision)
    string(JSON required GET "${ker_native_pins}" ${dependency} revision)
    if(NOT selected STREQUAL required)
        message(FATAL_ERROR "Native Linux ${dependency} revision differs from the pinned build manifest")
    endif()
endforeach()
set(ker_native_tools "${ker_native_kernel}/tools/lkl")
if(NOT EXISTS "${ker_native_tools}/liblkl.a")
    message(FATAL_ERROR "Missing native Linux library; rerun tools/build-native-linux.py")
endif()
foreach(artifact config library)
    if(artifact STREQUAL config)
        set(artifact_path "${ker_native_kernel}/.config")
    else()
        set(artifact_path "${ker_native_tools}/liblkl.a")
    endif()
    string(JSON expected_hash GET "${ker_native_json}" ${artifact}_sha256)
    file(SHA256 "${artifact_path}" actual_hash)
    if(NOT actual_hash STREQUAL expected_hash)
        message(FATAL_ERROR "Native Linux ${artifact} differs from the build proof; rerun tools/build-native-linux.py")
    endif()
endforeach()
add_library(ker-posix SHARED src/posix/lkl-channel.c src/posix/packet-device.c
    src/posix/fd-table.c src/posix/posix-socket.c src/posix/posix-poll.c src/posix/posix-stat.c
    src/posix/lifecycle.c src/posix/diagnostics.c)
target_include_directories(ker-posix SYSTEM PRIVATE
    "${ker_native_source}/tools/lkl/include" "${ker_native_tools}/include")
add_library(ker::posix ALIAS ker-posix)
target_include_directories(ker-posix PUBLIC
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)
target_compile_definitions(ker-posix PRIVATE KER_NATIVE_KERNEL_RELEASE="${ker_native_release}")
target_link_options(ker-posix PRIVATE -Wl,--no-undefined
    "-Wl,--version-script=${PROJECT_SOURCE_DIR}/src/posix/exports.map")
set_property(TARGET ker-posix APPEND PROPERTY LINK_DEPENDS "${PROJECT_SOURCE_DIR}/src/posix/exports.map")
target_link_libraries(ker-posix PRIVATE "${ker_native_tools}/liblkl.a" Threads::Threads ${CMAKE_DL_LIBS} rt)
set_target_properties(ker-posix PROPERTIES VERSION ${PROJECT_VERSION} SOVERSION 0 EXPORT_NAME posix)
add_executable(ker-app src/posix/app-guard.c)
add_executable(ker-io-worker src/posix/io-worker.c)
foreach(native_target ker-posix ker-app ker-io-worker)
    target_compile_features(${native_target} PRIVATE c_std_11)
    target_compile_options(${native_target} PRIVATE -Wall -Wextra -Werror)
endforeach()
target_link_libraries(ker-io-worker PRIVATE PkgConfig::DPDK)
# DPDK's libraries have transitive dependencies in this selected installation.
# Use a transitive RPATH rather than relying on the developer's shell setup.
target_link_options(ker-io-worker PRIVATE -Wl,--disable-new-dtags)
set_target_properties(ker-io-worker PROPERTIES
    BUILD_RPATH "${DPDK_LIBRARY_DIRS}" INSTALL_RPATH "${DPDK_LIBRARY_DIRS}")
install(TARGETS ker-posix EXPORT kerTargets
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR})
install(TARGETS ker-io-worker ker-app
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
file(RELATIVE_PATH KER_POSIX_LIB_FROM_BIN
    "${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_BINDIR}" "${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR}")
configure_file(tools/ker-run.py "${PROJECT_BINARY_DIR}/ker-run" @ONLY)
install(PROGRAMS "${PROJECT_BINARY_DIR}/ker-run" DESTINATION ${CMAKE_INSTALL_BINDIR})
install(FILES "${ker_native_manifest}"
    DESTINATION ${CMAKE_INSTALL_DATADIR}/ker/native-linux RENAME build.json)
install(FILES config/native-linux.json
    DESTINATION ${CMAKE_INSTALL_DATADIR}/ker/native-linux RENAME sources.json)
if(KER_BUILD_EXAMPLES)
    add_executable(ker-socket-echo examples/posix-echo.c)
    install(TARGETS ker-socket-echo RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
endif()
install(FILES "${ker_native_source}/COPYING" "${ker_native_source}/LICENSES/preferred/GPL-2.0"
    DESTINATION ${CMAKE_INSTALL_DATADIR}/ker/native-linux)
if(BUILD_TESTING)
    add_executable(ker-posix-tcp-echo-test tests/posix/tcp-echo.c)
    target_link_libraries(ker-posix-tcp-echo-test PRIVATE Threads::Threads)
    add_executable(ker-posix-tcp-errors-test tests/posix/tcp-errors.c)
    add_executable(ker-posix-fd-compat-test tests/posix/fd-compat.c)
    target_link_libraries(ker-posix-fd-compat-test PRIVATE Threads::Threads)
    add_executable(ker-posix-fstack-epoll-test tests/posix/fstack-epoll.c)
    target_compile_options(ker-posix-fstack-epoll-test PRIVATE -Wall -Wextra -Werror)
    add_executable(ker-posix-fstack-message-io-test tests/posix/fstack-message-io.c)
    target_compile_options(ker-posix-fstack-message-io-test PRIVATE -Wall -Wextra -Werror)
    find_package(Python3 REQUIRED COMPONENTS Interpreter)
    add_test(NAME native-ker-run-exit-status
        COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/posix/test_ker_run.py")
    add_test(NAME native-linux-fingerprint-stale-inputs
        COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/posix/test_native_linux_fingerprint.py"
            --builder "${PROJECT_SOURCE_DIR}/tools/build-native-linux.py"
            --verifier "${PROJECT_SOURCE_DIR}/cmake/VerifyNativeLinuxFingerprint.cmake"
            --cmake "${CMAKE_COMMAND}")
    set_tests_properties(native-linux-fingerprint-stale-inputs PROPERTIES TIMEOUT 30)
    set(ker_native_test_command "${Python3_EXECUTABLE}"
        "${PROJECT_SOURCE_DIR}/tests/posix/tcp-interop.py"
        --launcher "${PROJECT_SOURCE_DIR}/tools/ker-run.py"
        --library "$<TARGET_FILE:ker-posix>" --io-worker "$<TARGET_FILE:ker-io-worker>"
        --app "$<TARGET_FILE:ker-posix-tcp-echo-test>")
    add_test(NAME native-posix-tcp-interop COMMAND ${ker_native_test_command}
        --fd-app "$<TARGET_FILE:ker-posix-fd-compat-test>")
    add_test(NAME native-fstack-epoll COMMAND ${ker_native_test_command}
        --epoll-app "$<TARGET_FILE:ker-posix-fstack-epoll-test>")
    set_tests_properties(native-fstack-epoll PROPERTIES TIMEOUT 90 LABELS "native-tcp;fstack")
    add_test(NAME native-fstack-message-io COMMAND ${ker_native_test_command}
        --message-app "$<TARGET_FILE:ker-posix-fstack-message-io-test>")
    set_tests_properties(native-fstack-message-io PROPERTIES TIMEOUT 90 LABELS "native-tcp;fstack")
    add_test(NAME native-posix-tcp-loss-reorder COMMAND ${ker_native_test_command} --faults)
    add_test(NAME native-posix-tcp-zero-window COMMAND ${ker_native_test_command} --zero-window)
    add_test(NAME native-posix-tcp-errors COMMAND ${ker_native_test_command}
        --errors-app "$<TARGET_FILE:ker-posix-tcp-errors-test>")
    find_program(KER_TEST_CURL curl)
    find_program(KER_TEST_REDIS_SERVER NAMES valkey-server redis-server)
    if(KER_TEST_CURL OR KER_TEST_REDIS_SERVER)
        set(ker_application_test_args)
        if(KER_TEST_CURL)
            list(APPEND ker_application_test_args --curl "${KER_TEST_CURL}")
        endif()
        if(KER_TEST_REDIS_SERVER)
            list(APPEND ker_application_test_args --redis-server "${KER_TEST_REDIS_SERVER}")
        endif()
        add_test(NAME native-posix-existing-applications
            COMMAND ${ker_native_test_command} ${ker_application_test_args})
        set_tests_properties(native-posix-existing-applications PROPERTIES TIMEOUT 90 LABELS native-tcp)
    endif()
    set_tests_properties(native-posix-tcp-interop native-posix-tcp-loss-reorder native-posix-tcp-zero-window native-posix-tcp-errors
        PROPERTIES TIMEOUT 90 LABELS native-tcp)
    add_executable(ker-posix-fstack-socket-contracts-test tests/posix/fstack-socket-contracts.c)
    target_compile_options(ker-posix-fstack-socket-contracts-test PRIVATE -Wall -Wextra -Werror)
    add_test(NAME host-fstack-socket-contracts-reference COMMAND ker-posix-fstack-socket-contracts-test)
    set_tests_properties(host-fstack-socket-contracts-reference PROPERTIES TIMEOUT 30 LABELS fstack)
    add_test(NAME native-fstack-socket-contracts COMMAND ${ker_native_test_command}
        --fd-app "$<TARGET_FILE:ker-posix-fstack-socket-contracts-test>")
    set_tests_properties(native-fstack-socket-contracts PROPERTIES TIMEOUT 90 LABELS "native-tcp;fstack")
    add_executable(ker-posix-fstack-readiness-test tests/posix/fstack-readiness.c)
    target_compile_options(ker-posix-fstack-readiness-test PRIVATE -Wall -Wextra -Werror)
    add_test(NAME host-fstack-readiness-reference COMMAND ker-posix-fstack-readiness-test)
    set_tests_properties(host-fstack-readiness-reference PROPERTIES TIMEOUT 30 LABELS fstack)
    add_test(NAME native-fstack-readiness COMMAND ${ker_native_test_command}
        --fd-app "$<TARGET_FILE:ker-posix-fstack-readiness-test>")
    set_tests_properties(native-fstack-readiness PROPERTIES TIMEOUT 90 LABELS "native-tcp;fstack")
    add_executable(ker-posix-fstack-stream-io-test tests/posix/fstack-stream-io.c)
    target_compile_options(ker-posix-fstack-stream-io-test PRIVATE -Wall -Wextra -Werror)
    add_test(NAME native-fstack-stream-io COMMAND ${ker_native_test_command}
        --stream-app "$<TARGET_FILE:ker-posix-fstack-stream-io-test>")
    set_tests_properties(native-fstack-stream-io PROPERTIES TIMEOUT 90 LABELS "native-tcp;fstack")
    add_executable(ker-posix-fstack-udp-test tests/posix/fstack-udp.c)
    target_compile_options(ker-posix-fstack-udp-test PRIVATE -Wall -Wextra -Werror)
    add_test(NAME native-fstack-udp-interop COMMAND ${ker_native_test_command}
        --udp-app "$<TARGET_FILE:ker-posix-fstack-udp-test>")
    set_tests_properties(native-fstack-udp-interop PROPERTIES TIMEOUT 90 LABELS "native-udp;fstack")
    add_executable(ker-posix-fstack-udp-errors-test tests/posix/fstack-udp-errors.c)
    target_compile_options(ker-posix-fstack-udp-errors-test PRIVATE -Wall -Wextra -Werror)
    add_test(NAME native-fstack-udp-errors COMMAND ${ker_native_test_command}
        --udp-errors-app "$<TARGET_FILE:ker-posix-fstack-udp-errors-test>")
    set_tests_properties(native-fstack-udp-errors PROPERTIES TIMEOUT 90 LABELS "native-udp;fstack")
    add_executable(ker-posix-fstack-udp-ancillary-test tests/posix/fstack-udp-ancillary.c)
    target_compile_options(ker-posix-fstack-udp-ancillary-test PRIVATE -Wall -Wextra -Werror)
    add_test(NAME native-fstack-udp-ancillary COMMAND ${ker_native_test_command}
        --udp-ancillary-app "$<TARGET_FILE:ker-posix-fstack-udp-ancillary-test>")
    set_tests_properties(native-fstack-udp-ancillary PROPERTIES TIMEOUT 90 LABELS "native-udp;fstack")
    add_executable(ker-posix-fstack-udp-mtu-test tests/posix/fstack-udp-mtu.c)
    target_compile_options(ker-posix-fstack-udp-mtu-test PRIVATE -Wall -Wextra -Werror)
    add_test(NAME native-fstack-udp-mtu COMMAND ${ker_native_test_command}
        --udp-mtu-app "$<TARGET_FILE:ker-posix-fstack-udp-mtu-test>")
    set_tests_properties(native-fstack-udp-mtu PROPERTIES TIMEOUT 90 LABELS "native-udp;fstack")
    add_executable(ker-posix-fstack-udp-multicast-test tests/posix/fstack-udp-multicast.c)
    target_compile_options(ker-posix-fstack-udp-multicast-test PRIVATE -Wall -Wextra -Werror)
    add_test(NAME native-fstack-udp-multicast COMMAND ${ker_native_test_command}
        --udp-multicast-app "$<TARGET_FILE:ker-posix-fstack-udp-multicast-test>")
    set_tests_properties(native-fstack-udp-multicast PROPERTIES TIMEOUT 90 LABELS "native-udp;fstack")
    add_executable(ker-posix-fstack-tcp-timeouts-test tests/posix/fstack-tcp-timeouts.c)
    target_compile_options(ker-posix-fstack-tcp-timeouts-test PRIVATE -Wall -Wextra -Werror)
    add_test(NAME native-fstack-tcp-receive-timeouts COMMAND ${ker_native_test_command}
        --receive-timeouts-app "$<TARGET_FILE:ker-posix-fstack-tcp-timeouts-test>")
    set_tests_properties(native-fstack-tcp-receive-timeouts PROPERTIES TIMEOUT 90 LABELS "native-tcp;fstack")
    add_executable(ker-posix-fstack-tcp-send-timeouts-test tests/posix/fstack-tcp-send-timeouts.c)
    target_compile_options(ker-posix-fstack-tcp-send-timeouts-test PRIVATE -Wall -Wextra -Werror)
    add_test(NAME native-fstack-tcp-send-timeouts COMMAND ${ker_native_test_command}
        --send-timeouts-app "$<TARGET_FILE:ker-posix-fstack-tcp-send-timeouts-test>")
    set_tests_properties(native-fstack-tcp-send-timeouts PROPERTIES TIMEOUT 90 LABELS "native-tcp;fstack")
    add_executable(ker-posix-fstack-tcp-connect-test tests/posix/fstack-tcp-connect.c)
    target_compile_options(ker-posix-fstack-tcp-connect-test PRIVATE -Wall -Wextra -Werror)
    add_test(NAME native-fstack-tcp-connect-lifecycle COMMAND ${ker_native_test_command}
        --connect-lifecycle-app "$<TARGET_FILE:ker-posix-fstack-tcp-connect-test>")
    set_tests_properties(native-fstack-tcp-connect-lifecycle PROPERTIES TIMEOUT 90 LABELS "native-tcp;fstack")
    add_executable(ker-posix-fstack-tcp-defer-accept-test tests/posix/fstack-tcp-defer-accept.c)
    target_compile_options(ker-posix-fstack-tcp-defer-accept-test PRIVATE -Wall -Wextra -Werror)
    add_test(NAME native-fstack-tcp-defer-accept COMMAND ${ker_native_test_command}
        --defer-accept-app "$<TARGET_FILE:ker-posix-fstack-tcp-defer-accept-test>")
    set_tests_properties(native-fstack-tcp-defer-accept PROPERTIES TIMEOUT 90 LABELS "native-tcp;fstack")
    add_executable(ker-posix-fstack-tcp-reuseport-test tests/posix/fstack-tcp-reuseport.c)
    target_compile_options(ker-posix-fstack-tcp-reuseport-test PRIVATE -Wall -Wextra -Werror)
    add_test(NAME native-fstack-tcp-reuseport COMMAND ${ker_native_test_command}
        --reuseport-app "$<TARGET_FILE:ker-posix-fstack-tcp-reuseport-test>")
    set_tests_properties(native-fstack-tcp-reuseport PROPERTIES TIMEOUT 90 LABELS "native-tcp;fstack")
    add_executable(ker-posix-fstack-tcp-urgent-test tests/posix/fstack-tcp-urgent.c)
    target_compile_options(ker-posix-fstack-tcp-urgent-test PRIVATE -Wall -Wextra -Werror)
    add_test(NAME native-fstack-tcp-urgent COMMAND ${ker_native_test_command}
        --urgent-app "$<TARGET_FILE:ker-posix-fstack-tcp-urgent-test>")
    set_tests_properties(native-fstack-tcp-urgent PROPERTIES TIMEOUT 90 LABELS "native-tcp;fstack")
    add_executable(ker-posix-fstack-tcp-receive-queue-test tests/posix/fstack-tcp-receive-queue.c)
    target_compile_options(ker-posix-fstack-tcp-receive-queue-test PRIVATE -Wall -Wextra -Werror)
    add_test(NAME native-fstack-tcp-receive-queue COMMAND ${ker_native_test_command}
        --receive-queue-app "$<TARGET_FILE:ker-posix-fstack-tcp-receive-queue-test>")
    set_tests_properties(native-fstack-tcp-receive-queue PROPERTIES TIMEOUT 90 LABELS "native-tcp;fstack")
    add_executable(ker-posix-fstack-tcp-shutdown-write-test tests/posix/fstack-tcp-shutdown-write.c)
    target_compile_options(ker-posix-fstack-tcp-shutdown-write-test PRIVATE -Wall -Wextra -Werror)
    add_test(NAME native-fstack-tcp-shutdown-write COMMAND ${ker_native_test_command}
        --shutdown-write-app "$<TARGET_FILE:ker-posix-fstack-tcp-shutdown-write-test>")
    set_tests_properties(native-fstack-tcp-shutdown-write PROPERTIES TIMEOUT 90 LABELS "native-tcp;fstack")
    add_executable(ker-posix-fstack-udp-broadcast-test tests/posix/fstack-udp-broadcast.c)
    target_compile_options(ker-posix-fstack-udp-broadcast-test PRIVATE -Wall -Wextra -Werror)
    add_test(NAME native-fstack-udp-broadcast COMMAND ${ker_native_test_command}
        --udp-broadcast-app "$<TARGET_FILE:ker-posix-fstack-udp-broadcast-test>")
    set_tests_properties(native-fstack-udp-broadcast PROPERTIES TIMEOUT 90 LABELS "native-udp;fstack")
endif()
