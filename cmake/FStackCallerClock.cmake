# Caller cadence conversion only; Linux kernel timers remain unchanged.
if(KER_BUILD_EXAMPLES OR BUILD_TESTING)
    add_library(ker-example-caller-clock STATIC examples/caller-clock.c)
    target_include_directories(ker-example-caller-clock PUBLIC "${PROJECT_SOURCE_DIR}/examples"
        PRIVATE "${PROJECT_SOURCE_DIR}/third_party/fstack-caller-clock")
    target_compile_options(ker-example-caller-clock PRIVATE -Wall -Wextra -Werror)
    set_target_properties(ker-example-caller-clock PROPERTIES C_STANDARD 11 C_STANDARD_REQUIRED YES C_EXTENSIONS OFF)
endif()
if(BUILD_TESTING)
    list(GET DPDK_LIBRARY_DIRS 0 ker_caller_clock_pmd_root)
    add_executable(ker-caller-clock-source-test tests/posix/fstack-caller-clock.c)
    target_include_directories(ker-caller-clock-source-test PRIVATE
        "${PROJECT_SOURCE_DIR}/include" "${PROJECT_SOURCE_DIR}/tests")
    target_link_libraries(ker-caller-clock-source-test PRIVATE ker-example-caller-clock ${CMAKE_DL_LIBS})
    target_compile_options(ker-caller-clock-source-test PRIVATE -Wall -Wextra -Werror)
    add_executable(ker-caller-clock-round-down-test tests/posix/fstack-caller-clock.c
        tests/posix/caller-clock-round-down.c)
    target_include_directories(ker-caller-clock-round-down-test PRIVATE
        "${PROJECT_SOURCE_DIR}/include" "${PROJECT_SOURCE_DIR}/tests")
    target_link_libraries(ker-caller-clock-round-down-test PRIVATE ker-example-caller-clock ${CMAKE_DL_LIBS})
    target_compile_options(ker-caller-clock-round-down-test PRIVATE -Wall -Wextra -Werror)
    target_link_options(ker-caller-clock-round-down-test PRIVATE -Wl,--wrap=example_caller_interval_ticks)
    add_test(NAME native-fstack-caller-clock-source
        COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/posix/fstack-host-readiness.py"
            --launcher "${PROJECT_SOURCE_DIR}/tools/ker-run.py" --library "$<TARGET_FILE:ker-posix>"
            --worker "$<TARGET_FILE:ker-io-worker>" --app "$<TARGET_FILE:ker-caller-clock-source-test>"
            --pmd-root "${ker_caller_clock_pmd_root}" --profile clock-source)
    add_test(NAME native-fstack-caller-clock-round-down
        COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/posix/fstack-host-readiness.py"
            --launcher "${PROJECT_SOURCE_DIR}/tools/ker-run.py" --library "$<TARGET_FILE:ker-posix>"
            --worker "$<TARGET_FILE:ker-io-worker>" --app "$<TARGET_FILE:ker-caller-clock-round-down-test>"
            --pmd-root "${ker_caller_clock_pmd_root}" --profile clock-round-down)
    add_test(NAME native-fstack-caller-clock-consumer-100hz
        COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/posix/fstack-host-readiness.py"
            --launcher "${PROJECT_SOURCE_DIR}/tools/ker-run.py" --library "$<TARGET_FILE:ker-posix>"
            --worker "$<TARGET_FILE:ker-io-worker>" --app "$<TARGET_FILE:ker-host-readiness-echo>"
            --pmd-root "${ker_caller_clock_pmd_root}" --profile consumer --poll-hz 100)
    add_executable(ker-host-readiness-high-rate-test examples/host-readiness-echo.c
        tests/posix/caller-clock-high-rate-poll.c)
    target_include_directories(ker-host-readiness-high-rate-test PRIVATE "${PROJECT_SOURCE_DIR}/include")
    target_link_libraries(ker-host-readiness-high-rate-test PRIVATE ker-example-host-readiness
        ker-example-host-mapping ker-example-caller-clock ${CMAKE_DL_LIBS})
    target_compile_options(ker-host-readiness-high-rate-test PRIVATE -Wall -Wextra -Werror)
    target_link_options(ker-host-readiness-high-rate-test PRIVATE -Wl,--wrap=example_host_kqueue_poll)
    add_test(NAME native-fstack-caller-clock-consumer-high-rate-delayed-peer
        COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/posix/fstack-host-readiness.py"
            --launcher "${PROJECT_SOURCE_DIR}/tools/ker-run.py" --library "$<TARGET_FILE:ker-posix>"
            --worker "$<TARGET_FILE:ker-io-worker>" --app "$<TARGET_FILE:ker-host-readiness-high-rate-test>"
            --pmd-root "${ker_caller_clock_pmd_root}" --profile consumer-high-rate --poll-hz 1000000)
    add_test(NAME native-fstack-caller-clock-invalid-zero
        COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/posix/fstack-host-readiness.py"
            --launcher "${PROJECT_SOURCE_DIR}/tools/ker-run.py" --library "$<TARGET_FILE:ker-posix>"
            --worker "$<TARGET_FILE:ker-io-worker>" --app "$<TARGET_FILE:ker-host-readiness-echo>"
            --pmd-root "${ker_caller_clock_pmd_root}" --profile clock-invalid --poll-hz 0)
    add_test(NAME native-fstack-caller-clock-invalid-high
        COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/posix/fstack-host-readiness.py"
            --launcher "${PROJECT_SOURCE_DIR}/tools/ker-run.py" --library "$<TARGET_FILE:ker-posix>"
            --worker "$<TARGET_FILE:ker-io-worker>" --app "$<TARGET_FILE:ker-host-readiness-echo>"
            --pmd-root "${ker_caller_clock_pmd_root}" --profile clock-invalid --poll-hz 1000001)
    set_tests_properties(native-fstack-caller-clock-source native-fstack-caller-clock-round-down
        native-fstack-caller-clock-consumer-100hz native-fstack-caller-clock-consumer-high-rate-delayed-peer
        native-fstack-caller-clock-invalid-zero
        native-fstack-caller-clock-invalid-high PROPERTIES TIMEOUT 60 LABELS "native-tcp;fstack;fstack-newly-adapted")
    add_test(NAME fstack-caller-clock-original-import
        COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/fstack-caller-clock-import.py")
    set_tests_properties(fstack-caller-clock-original-import PROPERTIES LABELS "provenance;fstack")
endif()
