# The full native kernel is isolated from the lightweight imported-header port.
# Protocol objects come from a pinned Linux stable tree, using the LKL arch port.
set(KER_NATIVE_LINUX_BUILD "${PROJECT_SOURCE_DIR}/build-native-linux" CACHE PATH
    "Output directory from tools/build-native-linux.py")
set(ker_native_manifest "${KER_NATIVE_LINUX_BUILD}/native-linux.json")
if(NOT EXISTS "${ker_native_manifest}")
    message(FATAL_ERROR "Run python3 tools/build-native-linux.py --build ${KER_NATIVE_LINUX_BUILD} first")
endif()
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
    find_package(Python3 REQUIRED COMPONENTS Interpreter)
    add_test(NAME native-ker-run-exit-status
        COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/posix/test_ker_run.py")
    set(ker_native_test_command "${Python3_EXECUTABLE}"
        "${PROJECT_SOURCE_DIR}/tests/posix/tcp-interop.py"
        --launcher "${PROJECT_SOURCE_DIR}/tools/ker-run.py"
        --library "$<TARGET_FILE:ker-posix>" --io-worker "$<TARGET_FILE:ker-io-worker>"
        --app "$<TARGET_FILE:ker-posix-tcp-echo-test>")
    add_test(NAME native-posix-tcp-interop COMMAND ${ker_native_test_command}
        --fd-app "$<TARGET_FILE:ker-posix-fd-compat-test>")
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
endif()
