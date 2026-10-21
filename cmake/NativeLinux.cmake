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
add_library(ker-posix SHARED src/posix/lkl-channel.c src/posix/ipv6-route.c src/posix/vlan.c src/posix/packet-device.c
    src/posix/fd-table.c src/posix/posix-socket.c src/posix/posix-poll.c src/posix/posix-stat.c
    src/posix/lifecycle.c src/posix/diagnostics.c src/posix/host-memory.c src/posix/host-thread.c src/posix/host-clock.c src/posix/host-entropy.c src/posix/realtime-clock.c)
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
add_executable(ker-io-worker src/posix/io-worker.c src/posix/worker-mbuf.c src/posix/worker-rx-drain.c src/posix/pcap.c src/posix/worker-log.c src/posix/worker-clock.c)
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
install(FILES config/native-launcher.example.ini DESTINATION ${CMAKE_INSTALL_DATADIR}/ker)
install(FILES config/native-linux.json
    DESTINATION ${CMAKE_INSTALL_DATADIR}/ker/native-linux RENAME sources.json)
if(KER_BUILD_EXAMPLES)
    add_executable(ker-socket-echo examples/posix-echo.c)
    install(TARGETS ker-socket-echo RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
endif()
install(FILES "${ker_native_source}/COPYING" "${ker_native_source}/LICENSES/preferred/GPL-2.0"
    DESTINATION ${CMAKE_INSTALL_DATADIR}/ker/native-linux)
if(BUILD_TESTING)
    add_executable(ker-packet-device-test tests/posix/fstack-packet-device.c src/posix/packet-device.c)
    target_include_directories(ker-packet-device-test PRIVATE "${PROJECT_SOURCE_DIR}/src/posix")
    target_include_directories(ker-packet-device-test SYSTEM PRIVATE
        "${ker_native_source}/tools/lkl/include" "${ker_native_tools}/include")
    target_compile_options(ker-packet-device-test PRIVATE -Wall -Wextra -Werror)
    target_link_libraries(ker-packet-device-test PRIVATE Threads::Threads)
    target_link_options(ker-packet-device-test PRIVATE -Wl,--wrap=calloc -Wl,--wrap=free)
    add_test(NAME native-fstack-packet-device COMMAND ker-packet-device-test)
    set_tests_properties(native-fstack-packet-device PROPERTIES TIMEOUT 30 LABELS fstack)
    add_executable(ker-worker-clock-test tests/posix/worker-clock.c src/posix/worker-clock.c)
    target_include_directories(ker-worker-clock-test PRIVATE "${PROJECT_SOURCE_DIR}/src/posix")
    target_compile_options(ker-worker-clock-test PRIVATE -Wall -Wextra -Werror)
    target_link_options(ker-worker-clock-test PRIVATE -Wl,--wrap=clock_gettime)
    add_test(NAME native-fstack-worker-clock COMMAND ker-worker-clock-test)
    set_tests_properties(native-fstack-worker-clock PROPERTIES TIMEOUT 30 LABELS fstack)
    add_library(ker-worker-clock-probe SHARED tests/posix/worker-clock-probe.c)
    target_compile_options(ker-worker-clock-probe PRIVATE -Wall -Wextra -Werror)
    target_link_libraries(ker-worker-clock-probe PRIVATE ${CMAKE_DL_LIBS})
    add_executable(ker-worker-log-test tests/posix/worker-log.c src/posix/worker-log.c)
    target_include_directories(ker-worker-log-test PRIVATE "${PROJECT_SOURCE_DIR}/src/posix")
    target_compile_options(ker-worker-log-test PRIVATE -Wall -Wextra -Werror)
    target_link_libraries(ker-worker-log-test PRIVATE PkgConfig::DPDK)
    add_test(NAME native-fstack-worker-log COMMAND ker-worker-log-test)
    set_tests_properties(native-fstack-worker-log PROPERTIES LABELS fstack TIMEOUT 30
        ENVIRONMENT "LD_LIBRARY_PATH=${DPDK_LIBRARY_DIRS}:$ENV{LD_LIBRARY_PATH}")
    add_library(ker-dpdk-log-lifetime-probe SHARED tests/posix/dpdk-log-lifetime-probe.c)
    target_compile_options(ker-dpdk-log-lifetime-probe PRIVATE -Wall -Wextra -Werror)
    target_link_libraries(ker-dpdk-log-lifetime-probe PRIVATE ${CMAKE_DL_LIBS})
    add_executable(ker-pcap-test tests/posix/pcap.c src/posix/pcap.c)
    target_include_directories(ker-pcap-test PRIVATE "${PROJECT_SOURCE_DIR}/src/posix" "${PROJECT_SOURCE_DIR}/tests")
    target_compile_options(ker-pcap-test PRIVATE -Wall -Wextra -Werror)
    target_link_libraries(ker-pcap-test PRIVATE PkgConfig::DPDK)
    add_test(NAME native-fstack-pcap COMMAND ker-pcap-test)
    set_tests_properties(native-fstack-pcap PROPERTIES LABELS "fstack" TIMEOUT 30
        ENVIRONMENT "LD_LIBRARY_PATH=${DPDK_LIBRARY_DIRS}:$ENV{LD_LIBRARY_PATH}")
    add_executable(ker-thread-runtime-test tests/posix/fstack-thread-runtime.c src/posix/host-thread.c)
    target_include_directories(ker-thread-runtime-test PRIVATE "${PROJECT_SOURCE_DIR}/src/posix")
    target_include_directories(ker-thread-runtime-test SYSTEM PRIVATE
        "${ker_native_source}/tools/lkl/include" "${ker_native_tools}/include")
    target_link_libraries(ker-thread-runtime-test PRIVATE "${ker_native_tools}/liblkl.a" Threads::Threads ${CMAKE_DL_LIBS} rt)
    target_link_options(ker-thread-runtime-test PRIVATE -Wl,--wrap=malloc -Wl,--wrap=free)
    target_compile_options(ker-thread-runtime-test PRIVATE -Wall -Wextra -Werror)
    add_test(NAME native-fstack-thread-runtime COMMAND ker-thread-runtime-test)
    set_tests_properties(native-fstack-thread-runtime PROPERTIES TIMEOUT 30 LABELS "native-tcp;fstack")
    foreach(mode debug release)
        add_executable(ker-host-failure-${mode}-test tests/posix/fstack-host-failure.c src/posix/host-clock.c)
        target_include_directories(ker-host-failure-${mode}-test PRIVATE "${PROJECT_SOURCE_DIR}/src/posix")
        target_include_directories(ker-host-failure-${mode}-test SYSTEM PRIVATE
            "${ker_native_source}/tools/lkl/include" "${ker_native_tools}/include")
        target_compile_options(ker-host-failure-${mode}-test PRIVATE -Wall -Wextra -Werror)
        target_link_options(ker-host-failure-${mode}-test PRIVATE -Wl,--wrap=clock_gettime)
    endforeach()
    target_compile_options(ker-host-failure-debug-test PRIVATE -UNDEBUG)
    target_compile_definitions(ker-host-failure-release-test PRIVATE NDEBUG)
    add_test(NAME native-fstack-host-failure-debug COMMAND ker-host-failure-debug-test)
    add_test(NAME native-fstack-host-failure-release COMMAND ker-host-failure-release-test)
    set_tests_properties(native-fstack-host-failure-debug native-fstack-host-failure-release
        PROPERTIES TIMEOUT 30 LABELS fstack)
    add_executable(ker-fd-map-test tests/posix/fstack-fd-map.c src/posix/fd-table.c src/posix/host-memory.c src/posix/host-clock.c)
    target_include_directories(ker-fd-map-test PRIVATE "${PROJECT_SOURCE_DIR}/src/posix")
    target_include_directories(ker-fd-map-test SYSTEM PRIVATE
        "${ker_native_source}/tools/lkl/include" "${ker_native_tools}/include")
    target_link_libraries(ker-fd-map-test PRIVATE "${ker_native_tools}/liblkl.a" Threads::Threads ${CMAKE_DL_LIBS} rt)
    target_compile_options(ker-fd-map-test PRIVATE -Wall -Wextra -Werror)
    add_test(NAME native-fstack-fd-map COMMAND ker-fd-map-test)
    set_tests_properties(native-fstack-fd-map PROPERTIES TIMEOUT 30 LABELS "native-tcp;fstack")
    add_executable(ker-errno-test tests/posix/fstack-errno.c src/posix/host-memory.c src/posix/host-clock.c)
    target_include_directories(ker-errno-test PRIVATE "${PROJECT_SOURCE_DIR}/src/posix")
    target_include_directories(ker-errno-test SYSTEM PRIVATE
        "${ker_native_source}/tools/lkl/include" "${ker_native_tools}/include")
    target_link_libraries(ker-errno-test PRIVATE "${ker_native_tools}/liblkl.a" Threads::Threads ${CMAKE_DL_LIBS} rt)
    target_compile_options(ker-errno-test PRIVATE -Wall -Wextra -Werror)
    add_test(NAME native-fstack-errno COMMAND ker-errno-test)
    set_tests_properties(native-fstack-errno PROPERTIES TIMEOUT 30 LABELS "native-tcp;fstack")
    add_executable(ker-entropy-test tests/posix/fstack-entropy.c src/posix/host-entropy.c src/posix/host-memory.c src/posix/host-clock.c)
    target_include_directories(ker-entropy-test PRIVATE "${PROJECT_SOURCE_DIR}/src/posix")
    target_include_directories(ker-entropy-test SYSTEM PRIVATE
        "${ker_native_source}/tools/lkl/include" "${ker_native_tools}/include")
    target_link_libraries(ker-entropy-test PRIVATE "${ker_native_tools}/liblkl.a" Threads::Threads ${CMAKE_DL_LIBS} rt)
    target_link_options(ker-entropy-test PRIVATE -Wl,--wrap=syscall -Wl,--wrap=getrandom)
    target_compile_options(ker-entropy-test PRIVATE -Wall -Wextra -Werror)
    add_test(NAME native-fstack-entropy COMMAND ker-entropy-test)
    set_tests_properties(native-fstack-entropy PROPERTIES TIMEOUT 30 LABELS "native-tcp;fstack")
    add_executable(ker-realtime-test tests/posix/fstack-realtime.c src/posix/realtime-clock.c src/posix/host-memory.c src/posix/host-clock.c)
    target_include_directories(ker-realtime-test PRIVATE "${PROJECT_SOURCE_DIR}/src/posix")
    target_include_directories(ker-realtime-test SYSTEM PRIVATE
        "${ker_native_source}/tools/lkl/include" "${ker_native_tools}/include")
    target_link_libraries(ker-realtime-test PRIVATE "${ker_native_tools}/liblkl.a" Threads::Threads ${CMAKE_DL_LIBS} rt)
    target_link_options(ker-realtime-test PRIVATE -Wl,--wrap=clock_gettime)
    target_compile_options(ker-realtime-test PRIVATE -Wall -Wextra -Werror)
    add_test(NAME native-fstack-realtime COMMAND ker-realtime-test)
    set_tests_properties(native-fstack-realtime PROPERTIES TIMEOUT 30 LABELS "native-tcp;fstack")
    add_executable(ker-host-runtime-test tests/posix/fstack-host-runtime.c src/posix/host-memory.c src/posix/host-clock.c)
    target_include_directories(ker-host-runtime-test PRIVATE "${PROJECT_SOURCE_DIR}/src/posix")
    target_include_directories(ker-host-runtime-test SYSTEM PRIVATE
        "${ker_native_source}/tools/lkl/include" "${ker_native_tools}/include")
    target_link_libraries(ker-host-runtime-test PRIVATE "${ker_native_tools}/liblkl.a" Threads::Threads ${CMAKE_DL_LIBS} rt)
    target_compile_options(ker-host-runtime-test PRIVATE -Wall -Wextra -Werror)
    add_test(NAME native-fstack-host-runtime COMMAND ker-host-runtime-test)
    set_tests_properties(native-fstack-host-runtime PROPERTIES TIMEOUT 30 LABELS "native-tcp;fstack")
    add_executable(ker-native-drain-test tests/posix/native-drain.c src/posix/lifecycle.c)
    target_include_directories(ker-native-drain-test PRIVATE "${PROJECT_SOURCE_DIR}/src/posix")
    target_include_directories(ker-native-drain-test SYSTEM PRIVATE
        "${ker_native_source}/tools/lkl/include" "${ker_native_tools}/include")
    target_link_libraries(ker-native-drain-test PRIVATE "${ker_native_tools}/liblkl.a" Threads::Threads ${CMAKE_DL_LIBS} rt)
    target_compile_options(ker-native-drain-test PRIVATE -Wall -Wextra -Werror)
    add_test(NAME native-dualstack-drain COMMAND ker-native-drain-test)
    set_tests_properties(native-dualstack-drain PROPERTIES TIMEOUT 30 LABELS native-tcp)
    add_executable(ker-posix-fstack-dualstack-test tests/posix/fstack-dualstack.c)
    target_compile_options(ker-posix-fstack-dualstack-test PRIVATE -Wall -Wextra -Werror)
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
    add_test(NAME native-fstack-worker-traffic
        COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/posix/worker-traffic.py"
            --worker "$<TARGET_FILE:ker-io-worker>")
    set_tests_properties(native-fstack-worker-traffic PROPERTIES TIMEOUT 60 LABELS "fstack;dpdk")
    add_test(NAME native-fstack-worker-clock-interop
        COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/posix/worker-traffic.py"
            --worker "$<TARGET_FILE:ker-io-worker>" --clock-probe "$<TARGET_FILE:ker-worker-clock-probe>")
    set_tests_properties(native-fstack-worker-clock-interop PROPERTIES TIMEOUT 60 LABELS "fstack;dpdk")
    add_test(NAME native-fstack-launcher-config
        COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/posix/test_ker_run_config.py")
    set_tests_properties(native-fstack-launcher-config PROPERTIES TIMEOUT 30 LABELS fstack)
    add_test(NAME native-fstack-config-lifecycle
        COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/posix/test_ker_config_lifecycle.py")
    set_tests_properties(native-fstack-config-lifecycle PROPERTIES TIMEOUT 30 LABELS fstack)
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
    add_executable(ker-startup-interface-test tests/posix/startup-interface.c)
    target_compile_options(ker-startup-interface-test PRIVATE -Wall -Wextra -Werror -UNDEBUG)
    add_test(NAME native-fstack-startup-lifecycle COMMAND ${ker_native_test_command}
        --startup-app "$<TARGET_FILE:ker-startup-interface-test>")
    set_tests_properties(native-fstack-startup-lifecycle PROPERTIES TIMEOUT 90 LABELS "native-tcp;fstack")
    add_library(ker-startup-failure-probe SHARED tests/posix/startup-failure-probe.c)
    target_compile_options(ker-startup-failure-probe PRIVATE -Wall -Wextra -Werror)
    target_link_libraries(ker-startup-failure-probe PRIVATE ${CMAKE_DL_LIBS})
    add_test(NAME native-fstack-startup-failures
        COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/posix/startup-failures.py"
            --launcher "${PROJECT_SOURCE_DIR}/tools/ker-run.py" --library "$<TARGET_FILE:ker-posix>"
            --worker "$<TARGET_FILE:ker-io-worker>" --app "$<TARGET_FILE:ker-startup-interface-test>"
            --probe "$<TARGET_FILE:ker-startup-failure-probe>")
    set_tests_properties(native-fstack-startup-failures PROPERTIES TIMEOUT 120 LABELS "native-tcp;fstack")
    add_executable(ker-ephemeral-ports-test tests/posix/ephemeral-ports.c)
    target_compile_options(ker-ephemeral-ports-test PRIVATE -Wall -Wextra -Werror)
    add_test(NAME native-fstack-ephemeral-ports
        COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/posix/ephemeral-ports.py"
            --launcher "${PROJECT_SOURCE_DIR}/tools/ker-run.py" --library "$<TARGET_FILE:ker-posix>"
            --worker "$<TARGET_FILE:ker-io-worker>" --app "$<TARGET_FILE:ker-ephemeral-ports-test>")
    set_tests_properties(native-fstack-ephemeral-ports PROPERTIES TIMEOUT 120 LABELS "native-tcp;fstack")
    add_executable(ker-network-sysctl-test tests/posix/network-sysctl.c)
    target_compile_options(ker-network-sysctl-test PRIVATE -Wall -Wextra -Werror)
    add_test(NAME native-fstack-network-sysctl
        COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/posix/network-sysctl.py"
            --launcher "${PROJECT_SOURCE_DIR}/tools/ker-run.py" --library "$<TARGET_FILE:ker-posix>"
            --worker "$<TARGET_FILE:ker-io-worker>" --app "$<TARGET_FILE:ker-network-sysctl-test>"
            --probe "$<TARGET_FILE:ker-startup-failure-probe>")
    set_tests_properties(native-fstack-network-sysctl PROPERTIES TIMEOUT 120 LABELS "native-tcp;fstack")
    add_test(NAME udp-validation-report-guards
        COMMAND "${Python3_EXECUTABLE}" -B -m unittest discover -s "${PROJECT_SOURCE_DIR}/tests" -p test_udp_validation.py)
    set_tests_properties(udp-validation-report-guards PROPERTIES TIMEOUT 30 LABELS provenance)
    add_executable(ker-udp-signal-boundary tests/posix/udp-signal-boundary.c)
    target_compile_options(ker-udp-signal-boundary PRIVATE -Wall -Wextra -Werror)
    target_link_libraries(ker-udp-signal-boundary PRIVATE Threads::Threads)
    add_test(NAME host-udp-signal-reference
        COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/posix/udp-validation.py"
            --app "$<TARGET_FILE:ker-udp-signal-boundary>" --signal-boundary --host-only)
    add_test(NAME native-udp-signal-boundary
        COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/posix/udp-validation.py"
            --app "$<TARGET_FILE:ker-udp-signal-boundary>" --signal-boundary
            --launcher "${PROJECT_SOURCE_DIR}/tools/ker-run.py"
            --library "$<TARGET_FILE:ker-posix>" --worker "$<TARGET_FILE:ker-io-worker>")
    set_tests_properties(host-udp-signal-reference native-udp-signal-boundary
        PROPERTIES TIMEOUT 30 LABELS "native-udp;compatibility-boundary")
    add_executable(ker-udp-wire-errors tests/posix/udp-wire-errors.c)
    target_compile_options(ker-udp-wire-errors PRIVATE -Wall -Wextra -Werror)
    add_test(NAME native-udp-wire-errors
        COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/posix/udp-wire-errors.py"
            --app "$<TARGET_FILE:ker-udp-wire-errors>" --launcher "${PROJECT_SOURCE_DIR}/tools/ker-run.py"
            --library "$<TARGET_FILE:ker-posix>" --worker "$<TARGET_FILE:ker-io-worker>")
    set_tests_properties(native-udp-wire-errors PROPERTIES TIMEOUT 90 LABELS "native-udp;fstack")
    add_executable(ker-udp-path-mtu tests/posix/udp-path-mtu.c)
    target_compile_options(ker-udp-path-mtu PRIVATE -Wall -Wextra -Werror)
    add_test(NAME native-udp-path-mtu
        COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/posix/udp-path-mtu.py"
            --app "$<TARGET_FILE:ker-udp-path-mtu>" --launcher "${PROJECT_SOURCE_DIR}/tools/ker-run.py"
            --library "$<TARGET_FILE:ker-posix>" --worker "$<TARGET_FILE:ker-io-worker>")
    set_tests_properties(native-udp-path-mtu PROPERTIES TIMEOUT 100 LABELS "native-udp;fstack")
    add_executable(ker-udp-network6 tests/posix/udp-network6.c)
    target_compile_options(ker-udp-network6 PRIVATE -Wall -Wextra -Werror)
    add_test(NAME native-udp-network6
        COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/posix/udp-network6.py"
            --app "$<TARGET_FILE:ker-udp-network6>" --launcher "${PROJECT_SOURCE_DIR}/tools/ker-run.py"
            --library "$<TARGET_FILE:ker-posix>" --worker "$<TARGET_FILE:ker-io-worker>")
    set_tests_properties(native-udp-network6 PROPERTIES TIMEOUT 180 LABELS "native-udp;fstack")
    add_executable(ker-udp-contract-matrix tests/posix/udp-contract-matrix.c)
    target_compile_options(ker-udp-contract-matrix PRIVATE -Wall -Wextra -Werror)
    add_test(NAME host-udp-contract-matrix
        COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/posix/udp-validation.py"
            --app "$<TARGET_FILE:ker-udp-contract-matrix>" --host-only)
    set_tests_properties(host-udp-contract-matrix PROPERTIES TIMEOUT 30 LABELS "native-udp;fstack")
    add_test(NAME native-udp-contract-matrix
        COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/posix/udp-validation.py"
            --app "$<TARGET_FILE:ker-udp-contract-matrix>" --launcher "${PROJECT_SOURCE_DIR}/tools/ker-run.py"
            --library "$<TARGET_FILE:ker-posix>" --worker "$<TARGET_FILE:ker-io-worker>")
    set_tests_properties(native-udp-contract-matrix PROPERTIES TIMEOUT 45 LABELS "native-udp;fstack")
    add_executable(ker-ipv6-route-test tests/posix/ipv6-route.c)
    target_compile_options(ker-ipv6-route-test PRIVATE -Wall -Wextra -Werror)
    add_test(NAME native-fstack-ipv6-route
        COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/posix/ipv6-route.py"
            --launcher "${PROJECT_SOURCE_DIR}/tools/ker-run.py" --library "$<TARGET_FILE:ker-posix>"
            --worker "$<TARGET_FILE:ker-io-worker>" --app "$<TARGET_FILE:ker-ipv6-route-test>")
    set_tests_properties(native-fstack-ipv6-route PROPERTIES TIMEOUT 120 LABELS "native-tcp;native-udp;fstack")
    add_executable(ker-promiscuous-test tests/posix/promiscuous.c)
    target_compile_options(ker-promiscuous-test PRIVATE -Wall -Wextra -Werror)
    add_test(NAME native-fstack-promiscuous
        COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/posix/promiscuous.py"
            --launcher "${PROJECT_SOURCE_DIR}/tools/ker-run.py" --library "$<TARGET_FILE:ker-posix>"
            --worker "$<TARGET_FILE:ker-io-worker>" --app "$<TARGET_FILE:ker-promiscuous-test>")
    set_tests_properties(native-fstack-promiscuous PROPERTIES TIMEOUT 120 LABELS "native-tcp;native-udp;fstack")
    add_executable(ker-ipv4-vlan-route-test tests/posix/ipv4-vlan-route.c)
    target_compile_options(ker-ipv4-vlan-route-test PRIVATE -Wall -Wextra -Werror)
    add_test(NAME native-fstack-ipv4-vlan-route
        COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/posix/ipv4-vlan-route.py"
            --launcher "${PROJECT_SOURCE_DIR}/tools/ker-run.py" --library "$<TARGET_FILE:ker-posix>"
            --worker "$<TARGET_FILE:ker-io-worker>" --app "$<TARGET_FILE:ker-ipv4-vlan-route-test>")
    set_tests_properties(native-fstack-ipv4-vlan-route PROPERTIES TIMEOUT 120 LABELS "native-tcp;native-udp;fstack")
    add_test(NAME native-fstack-ipv6-vlan-route
        COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/posix/ipv6-route.py" --vlan6
            --launcher "${PROJECT_SOURCE_DIR}/tools/ker-run.py" --library "$<TARGET_FILE:ker-posix>"
            --worker "$<TARGET_FILE:ker-io-worker>" --app "$<TARGET_FILE:ker-ipv6-route-test>")
    set_tests_properties(native-fstack-ipv6-vlan-route PROPERTIES TIMEOUT 120 LABELS "native-tcp;native-udp;fstack")
    add_executable(ker-ipv6-interop-test tests/posix/ipv6-interop.c)
    target_compile_options(ker-ipv6-interop-test PRIVATE -Wall -Wextra -Werror)
    add_test(NAME native-fstack-ipv6-interop
        COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/posix/ipv6-interop.py"
            --launcher "${PROJECT_SOURCE_DIR}/tools/ker-run.py" --library "$<TARGET_FILE:ker-posix>"
            --worker "$<TARGET_FILE:ker-io-worker>" --app "$<TARGET_FILE:ker-ipv6-interop-test>")
    set_tests_properties(native-fstack-ipv6-interop PROPERTIES TIMEOUT 90 LABELS "native-tcp;native-udp;fstack")
    add_executable(ker-ipv6-vlan-test tests/posix/ipv6-vlan.c)
    target_compile_options(ker-ipv6-vlan-test PRIVATE -Wall -Wextra -Werror)
    add_test(NAME native-fstack-ipv6-vlan
        COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/posix/ipv6-vlan.py"
            --launcher "${PROJECT_SOURCE_DIR}/tools/ker-run.py" --library "$<TARGET_FILE:ker-posix>"
            --worker "$<TARGET_FILE:ker-io-worker>" --app "$<TARGET_FILE:ker-ipv6-vlan-test>")
    set_tests_properties(native-fstack-ipv6-vlan PROPERTIES TIMEOUT 120 LABELS "native-tcp;fstack")
    add_executable(ker-ipv6-vip-test tests/posix/ipv6-vip.c)
    target_compile_options(ker-ipv6-vip-test PRIVATE -Wall -Wextra -Werror)
    add_test(NAME native-fstack-ipv6-vip
        COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/posix/ipv6-vip.py"
            --launcher "${PROJECT_SOURCE_DIR}/tools/ker-run.py" --library "$<TARGET_FILE:ker-posix>"
            --worker "$<TARGET_FILE:ker-io-worker>" --app "$<TARGET_FILE:ker-ipv6-vip-test>")
    set_tests_properties(native-fstack-ipv6-vip PROPERTIES TIMEOUT 90 LABELS "native-tcp;fstack")
    add_executable(ker-vip-addresses-test tests/posix/fstack-vip-addresses.c)
    target_compile_options(ker-vip-addresses-test PRIVATE -Wall -Wextra -Werror)
    add_test(NAME native-fstack-vip-addresses
        COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/posix/vip-addresses.py"
            --launcher "${PROJECT_SOURCE_DIR}/tools/ker-run.py" --library "$<TARGET_FILE:ker-posix>"
            --worker "$<TARGET_FILE:ker-io-worker>" --app "$<TARGET_FILE:ker-vip-addresses-test>")
    set_tests_properties(native-fstack-vip-addresses PROPERTIES TIMEOUT 90 LABELS "native-tcp;fstack")
    add_executable(ker-posix-fstack-ecn-test tests/posix/fstack-tcp-ecn.c)
    target_compile_options(ker-posix-fstack-ecn-test PRIVATE -Wall -Wextra -Werror)
    add_test(NAME native-fstack-tcp-ecn COMMAND ${ker_native_test_command}
        --ecn-app "$<TARGET_FILE:ker-posix-fstack-ecn-test>")
    set_tests_properties(native-fstack-tcp-ecn PROPERTIES TIMEOUT 120 LABELS "native-tcp;fstack")
    add_test(NAME native-fstack-lcore-mask COMMAND ${ker_native_test_command} --lcore-config)
    set_tests_properties(native-fstack-lcore-mask PROPERTIES TIMEOUT 90 LABELS "native-tcp;fstack")
    add_test(NAME native-fstack-launcher-config-interop COMMAND ${ker_native_test_command} --launcher-config)
    set_tests_properties(native-fstack-launcher-config-interop PROPERTIES TIMEOUT 90 LABELS "native-tcp;fstack")
    add_test(NAME native-fstack-worker-log-interop COMMAND ${ker_native_test_command}
        --worker-log --log-lifetime-probe "$<TARGET_FILE:ker-dpdk-log-lifetime-probe>")
    set_tests_properties(native-fstack-worker-log-interop PROPERTIES TIMEOUT 90 LABELS "native-tcp;fstack")
    add_test(NAME native-fstack-pcap-interop COMMAND ${ker_native_test_command} --capture)
    set_tests_properties(native-fstack-pcap-interop PROPERTIES TIMEOUT 90 LABELS "native-tcp;fstack")
    add_test(NAME native-fstack-dualstack COMMAND ${ker_native_test_command}
        --dualstack-app "$<TARGET_FILE:ker-posix-fstack-dualstack-test>")
    set_tests_properties(native-fstack-dualstack PROPERTIES TIMEOUT 90 LABELS "native-tcp;fstack")
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
    add_executable(ker-posix-fstack-udp-cork-test tests/posix/fstack-udp-cork.c)
    target_compile_options(ker-posix-fstack-udp-cork-test PRIVATE -Wall -Wextra -Werror)
    add_test(NAME native-fstack-udp-cork COMMAND ${ker_native_test_command}
        --udp-cork-app "$<TARGET_FILE:ker-posix-fstack-udp-cork-test>")
    set_tests_properties(native-fstack-udp-cork PROPERTIES TIMEOUT 90 LABELS "native-udp;fstack")
    add_executable(ker-vlan-test tests/posix/vlan.c)
    target_compile_options(ker-vlan-test PRIVATE -Wall -Wextra -Werror -UNDEBUG)
    add_test(NAME native-fstack-vlan COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/posix/vlan.py"
        --launcher "${PROJECT_SOURCE_DIR}/tools/ker-run.py" --library "$<TARGET_FILE:ker-posix>"
        --worker "$<TARGET_FILE:ker-io-worker>" --app "$<TARGET_FILE:ker-vlan-test>")
    set_tests_properties(native-fstack-vlan PROPERTIES TIMEOUT 120 LABELS "native-dpdk;fstack")
    add_executable(ker-posix-fstack-jumbo-test tests/posix/fstack-jumbo.c)
    target_compile_options(ker-posix-fstack-jumbo-test PRIVATE -Wall -Wextra -Werror)
    add_test(NAME native-fstack-jumbo-mtu COMMAND ${ker_native_test_command}
        --jumbo-app "$<TARGET_FILE:ker-posix-fstack-jumbo-test>")
    set_tests_properties(native-fstack-jumbo-mtu PROPERTIES TIMEOUT 90 LABELS "native-udp;fstack")
    add_test(NAME native-fstack-mbuf-scatter COMMAND ${ker_native_test_command}
        --jumbo-app "$<TARGET_FILE:ker-posix-fstack-jumbo-test>" --mbuf-scatter)
    set_tests_properties(native-fstack-mbuf-scatter PROPERTIES TIMEOUT 90 LABELS "native-dpdk;fstack")
    add_executable(ker-worker-mbuf-test tests/posix/worker-mbuf.c src/posix/worker-mbuf.c src/posix/worker-rx-drain.c)
    target_include_directories(ker-worker-mbuf-test PRIVATE src/posix)
    target_compile_options(ker-worker-mbuf-test PRIVATE -Wall -Wextra -Werror -UNDEBUG)
    target_link_libraries(ker-worker-mbuf-test PRIVATE PkgConfig::DPDK)
    add_test(NAME worker-mbuf COMMAND ker-worker-mbuf-test)
    string(JOIN ":" ker_worker_mbuf_library_path ${DPDK_LIBRARY_DIRS})
    set_tests_properties(worker-mbuf PROPERTIES TIMEOUT 30 LABELS "native-dpdk;fstack"
        ENVIRONMENT "LD_LIBRARY_PATH=${ker_worker_mbuf_library_path}:$ENV{LD_LIBRARY_PATH}")
    add_executable(ker-posix-fstack-udp-mtu-test tests/posix/fstack-udp-mtu.c)
    target_compile_options(ker-posix-fstack-udp-mtu-test PRIVATE -Wall -Wextra -Werror)
    add_test(NAME native-fstack-udp-mtu COMMAND ${ker_native_test_command}
        --udp-mtu-app "$<TARGET_FILE:ker-posix-fstack-udp-mtu-test>")
    set_tests_properties(native-fstack-udp-mtu PROPERTIES TIMEOUT 90 LABELS "native-udp;fstack")
    add_executable(ker-posix-fstack-udp-lowwater-test tests/posix/fstack-udp-lowwater.c)
    target_compile_options(ker-posix-fstack-udp-lowwater-test PRIVATE -Wall -Wextra -Werror)
    add_test(NAME native-fstack-udp-lowwater COMMAND ${ker_native_test_command}
        --udp-lowwater-app "$<TARGET_FILE:ker-posix-fstack-udp-lowwater-test>")
    set_tests_properties(native-fstack-udp-lowwater PROPERTIES TIMEOUT 90 LABELS "native-udp;fstack")

    add_executable(ker-posix-fstack-udp-waitforone-test tests/posix/fstack-udp-waitforone.c)
    target_compile_options(ker-posix-fstack-udp-waitforone-test PRIVATE -Wall -Wextra -Werror)
    add_test(NAME native-fstack-udp-waitforone COMMAND ${ker_native_test_command}
        --udp-waitforone-app "$<TARGET_FILE:ker-posix-fstack-udp-waitforone-test>")
    set_tests_properties(native-fstack-udp-waitforone PROPERTIES TIMEOUT 90 LABELS "native-udp;fstack")

    add_executable(ker-posix-fstack-udp-receive-truncation-test tests/posix/fstack-udp-receive-truncation.c)
    target_compile_options(ker-posix-fstack-udp-receive-truncation-test PRIVATE -Wall -Wextra -Werror)
    add_test(NAME native-fstack-udp-receive-truncation COMMAND ${ker_native_test_command}
        --udp-receive-truncation-app "$<TARGET_FILE:ker-posix-fstack-udp-receive-truncation-test>")
    set_tests_properties(native-fstack-udp-receive-truncation PROPERTIES TIMEOUT 90 LABELS "native-udp;fstack")
    add_executable(ker-posix-fstack-udp-timeouts-test tests/posix/fstack-udp-timeouts.c)
    target_compile_options(ker-posix-fstack-udp-timeouts-test PRIVATE -Wall -Wextra -Werror)
    add_test(NAME native-fstack-udp-timeouts COMMAND ${ker_native_test_command}
        --udp-receive-timeouts-app "$<TARGET_FILE:ker-posix-fstack-udp-timeouts-test>")
    set_tests_properties(native-fstack-udp-timeouts PROPERTIES TIMEOUT 90 LABELS "native-udp;fstack")

    add_executable(ker-posix-fstack-udp-multicast-test tests/posix/fstack-udp-multicast.c)
    target_compile_options(ker-posix-fstack-udp-multicast-test PRIVATE -Wall -Wextra -Werror)
    add_test(NAME native-fstack-udp-multicast COMMAND ${ker_native_test_command}
        --udp-multicast-app "$<TARGET_FILE:ker-posix-fstack-udp-multicast-test>")
    set_tests_properties(native-fstack-udp-multicast PROPERTIES TIMEOUT 90 LABELS "native-udp;fstack")
    add_test(NAME native-udp-source-multicast4
        COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/posix/udp-network6.py"
            --app "$<TARGET_FILE:ker-posix-fstack-udp-multicast-test>" --ssm4
            --launcher "${PROJECT_SOURCE_DIR}/tools/ker-run.py"
            --library "$<TARGET_FILE:ker-posix>" --worker "$<TARGET_FILE:ker-io-worker>")
    set_tests_properties(native-udp-source-multicast4 PROPERTIES TIMEOUT 90 LABELS "native-udp;fstack")
    add_executable(ker-posix-fstack-tcp-lowwater-test tests/posix/fstack-tcp-lowwater.c)
    target_compile_options(ker-posix-fstack-tcp-lowwater-test PRIVATE -Wall -Wextra -Werror)
    add_test(NAME native-fstack-tcp-lowwater COMMAND ${ker_native_test_command}
        --tcp-lowwater-app "$<TARGET_FILE:ker-posix-fstack-tcp-lowwater-test>")
    set_tests_properties(native-fstack-tcp-lowwater PROPERTIES TIMEOUT 90 LABELS "native-tcp;fstack")

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
    add_executable(ker-posix-fstack-tcp-linger-test tests/posix/fstack-tcp-linger.c)
    target_compile_options(ker-posix-fstack-tcp-linger-test PRIVATE -Wall -Wextra -Werror)
    add_test(NAME native-fstack-tcp-linger COMMAND ${ker_native_test_command}
        --linger-app "$<TARGET_FILE:ker-posix-fstack-tcp-linger-test>")
    set_tests_properties(native-fstack-tcp-linger PROPERTIES TIMEOUT 90 LABELS "native-tcp;fstack")

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
    add_executable(ker-posix-fstack-udp-reuseport-test tests/posix/fstack-udp-reuseport.c)
    target_compile_options(ker-posix-fstack-udp-reuseport-test PRIVATE -Wall -Wextra -Werror)
    add_test(NAME native-fstack-udp-reuseport COMMAND ${ker_native_test_command}
        --udp-reuseport-app "$<TARGET_FILE:ker-posix-fstack-udp-reuseport-test>")
    set_tests_properties(native-fstack-udp-reuseport PROPERTIES TIMEOUT 90 LABELS "native-udp;fstack")
    add_executable(ker-posix-fstack-udp-broadcast-test tests/posix/fstack-udp-broadcast.c)
    target_compile_options(ker-posix-fstack-udp-broadcast-test PRIVATE -Wall -Wextra -Werror)
    add_test(NAME native-fstack-udp-broadcast COMMAND ${ker_native_test_command}
        --udp-broadcast-app "$<TARGET_FILE:ker-posix-fstack-udp-broadcast-test>")
    set_tests_properties(native-fstack-udp-broadcast PROPERTIES TIMEOUT 90 LABELS "native-udp;fstack")
    add_test(NAME native-udp-limited-broadcast
        COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/posix/udp-network6.py"
            --app "$<TARGET_FILE:ker-posix-fstack-udp-broadcast-test>" --broadcast4
            --launcher "${PROJECT_SOURCE_DIR}/tools/ker-run.py"
            --library "$<TARGET_FILE:ker-posix>" --worker "$<TARGET_FILE:ker-io-worker>")
    set_tests_properties(native-udp-limited-broadcast PROPERTIES TIMEOUT 90 LABELS "native-udp;fstack")
    add_executable(ker-posix-fstack-tcp-fd-modes-test tests/posix/fstack-tcp-fd-modes.c)
    target_compile_options(ker-posix-fstack-tcp-fd-modes-test PRIVATE -Wall -Wextra -Werror)
    add_test(NAME native-fstack-tcp-fd-modes COMMAND ${ker_native_test_command}
        --fd-modes-app "$<TARGET_FILE:ker-posix-fstack-tcp-fd-modes-test>")
    set_tests_properties(native-fstack-tcp-fd-modes PROPERTIES TIMEOUT 90 LABELS "native-tcp;fstack")
    add_executable(ker-posix-fstack-udp-connect-test tests/posix/fstack-udp-connect.c)
    target_compile_options(ker-posix-fstack-udp-connect-test PRIVATE -Wall -Wextra -Werror)
    add_test(NAME native-fstack-udp-connect-lifecycle COMMAND ${ker_native_test_command}
        --udp-connect-app "$<TARGET_FILE:ker-posix-fstack-udp-connect-test>")
    set_tests_properties(native-fstack-udp-connect-lifecycle PROPERTIES TIMEOUT 90 LABELS "native-udp;fstack")
    add_executable(ker-posix-fstack-tcp-listener-restart-test tests/posix/fstack-tcp-listener-restart.c)
    target_compile_options(ker-posix-fstack-tcp-listener-restart-test PRIVATE -Wall -Wextra -Werror)
    add_test(NAME native-fstack-tcp-listener-restart COMMAND ${ker_native_test_command}
        --listener-restart-app "$<TARGET_FILE:ker-posix-fstack-tcp-listener-restart-test>")
    set_tests_properties(native-fstack-tcp-listener-restart PROPERTIES TIMEOUT 90 LABELS "native-tcp;fstack")
endif()
