add_test(NAME native-nginx-companion-wire
    COMMAND "${CMAKE_COMMAND}" -E env
        "PYTHONPATH=${PROJECT_SOURCE_DIR}/tools"
        "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/posix/test_nginx_companion_wire.py")
set_tests_properties(native-nginx-companion-wire PROPERTIES
    LABELS "native;socket-broker;nginx-companion")
add_test(NAME native-ker-run-control-wire
    COMMAND "${Python3_EXECUTABLE}"
        "${PROJECT_SOURCE_DIR}/tests/posix/test_ker_run_control_wire.py")
add_test(NAME native-ker-run-control-process
    COMMAND "${Python3_EXECUTABLE}"
        "${PROJECT_SOURCE_DIR}/tests/posix/test_ker_run_control.py")
set_tests_properties(native-ker-run-control-wire native-ker-run-control-process
    PROPERTIES TIMEOUT 10 LABELS "native;socket-broker;inner-relay;unit")
add_test(NAME native-nginx-companion-installed-bundle
    COMMAND "${Python3_EXECUTABLE}"
        "${PROJECT_SOURCE_DIR}/tests/posix/test_nginx_companion_bundle.py"
        --launcher "${PROJECT_BINARY_DIR}/ker-run"
        --companion "${PROJECT_BINARY_DIR}/ker-nginx-companion"
        --tools "${PROJECT_BINARY_DIR}")
set_tests_properties(native-nginx-companion-installed-bundle PROPERTIES
    LABELS "native;socket-broker;nginx-companion;bundle")

add_executable(ker-nginx-companion-test-server
    "${PROJECT_SOURCE_DIR}/tests/posix/nginx-companion-test-server.c")
target_compile_options(ker-nginx-companion-test-server PRIVATE -Wall -Wextra -Werror)
add_test(NAME native-nginx-companion-process-ownership
    COMMAND "${Python3_EXECUTABLE}"
        "${PROJECT_SOURCE_DIR}/tests/posix/test_nginx_companion_process.py"
        --server "$<TARGET_FILE:ker-nginx-companion-test-server>"
        --tools "${PROJECT_BINARY_DIR}/"
        --helper "${PROJECT_BINARY_DIR}/ker-nginx-companion")
set_tests_properties(native-nginx-companion-process-ownership PROPERTIES
    TIMEOUT 30 LABELS "native;socket-broker;nginx-companion;process-ownership")

if(KER_BUILD_FSTACK_NGINX_RUNTIME AND KER_FSTACK_NGINX_BINARY)
    foreach(signal_name IN ITEMS term int)
        foreach(retention_mode IN ITEMS healthy unresolved)
            set(test_name "native-nginx-companion-real-gr0-${signal_name}-${retention_mode}")
            set(test_args)
            if(retention_mode STREQUAL "unresolved")
                list(APPEND test_args --break-helper)
            endif()
            add_test(NAME ${test_name}
                COMMAND "${Python3_EXECUTABLE}"
                    "${PROJECT_SOURCE_DIR}/tests/posix/native-nginx-companion-tap.py"
                    --launcher "${PROJECT_SOURCE_DIR}/tools/ker-run.py"
                    --library "$<TARGET_FILE:ker-posix>"
                    --worker "$<TARGET_FILE:ker-io-worker>"
                    --broker "$<TARGET_FILE:ker-socket-broker-readiness-fixture>"
                    --nginx "${KER_FSTACK_NGINX_BINARY}"
                    --fstack-runtime "$<TARGET_FILE:ker-fstack-nginx-runtime>"
                    --preload-library "$<TARGET_FILE:ker-socket-preload>"
                    --dpdk-plugin-dir "${ker_session_pmd_dir}"
                    --shutdown-signal ${signal_name} ${test_args})
            set_tests_properties(${test_name} PROPERTIES
                TIMEOUT 120 LABELS "native-tcp;fstack;socket-broker;nginx-companion;real-nginx")
        endforeach()
    endforeach()
    if(TARGET ker-fstack-nginx-owner-activation AND
       TARGET ker-fstack-nginx-worker-shim)
        add_test(NAME native-nginx-companion-owner-ready
            COMMAND "${Python3_EXECUTABLE}"
                "${PROJECT_SOURCE_DIR}/tests/posix/native-nginx-companion-tap.py"
                --launcher "${PROJECT_SOURCE_DIR}/tools/ker-run.py"
                --library "$<TARGET_FILE:ker-posix>"
                --worker "$<TARGET_FILE:ker-io-worker>"
                --broker "$<TARGET_FILE:ker-socket-broker-readiness-fixture>"
                --nginx "${KER_FSTACK_NGINX_BINARY}"
                --fstack-runtime "$<TARGET_FILE:ker-fstack-nginx-runtime>"
                --preload-library "$<TARGET_FILE:ker-socket-preload>"
                --dpdk-plugin-dir "${ker_session_pmd_dir}"
                --owner-activation-module "$<TARGET_FILE:ker-fstack-nginx-owner-activation>"
                --worker-shim "$<TARGET_FILE:ker-fstack-nginx-worker-shim>")
        set_tests_properties(native-nginx-companion-owner-ready PROPERTIES
            TIMEOUT 120 LABELS "native-tcp;fstack;socket-broker;nginx-companion;owner-ready")
        if(TARGET ker-socket-broker-rx-owner-relay-fixture AND
           TARGET ker-fstack-nginx-owner-activation-alias-test)
            add_test(NAME native-nginx-companion-rx-owner-relay
                COMMAND "${Python3_EXECUTABLE}"
                    "${PROJECT_SOURCE_DIR}/tests/posix/native-nginx-companion-tap.py"
                    --launcher "${PROJECT_SOURCE_DIR}/tools/ker-run.py"
                    --library "$<TARGET_FILE:ker-posix>"
                    --worker "$<TARGET_FILE:ker-io-worker>"
                    --broker "$<TARGET_FILE:ker-socket-broker-readiness-fixture>"
                    --rx-owner-relay-app "$<TARGET_FILE:ker-socket-broker-rx-owner-relay-fixture>"
                    --nginx "${KER_FSTACK_NGINX_BINARY}"
                    --fstack-runtime "$<TARGET_FILE:ker-fstack-nginx-runtime>"
                    --preload-library "$<TARGET_FILE:ker-socket-preload>"
                    --dpdk-plugin-dir "${ker_session_pmd_dir}"
                    --owner-activation-module "$<TARGET_FILE:ker-fstack-nginx-owner-activation-alias-test>"
                    --worker-shim "$<TARGET_FILE:ker-fstack-nginx-worker-shim>"
                    --rx-owner-relay)
            set_tests_properties(native-nginx-companion-rx-owner-relay PROPERTIES
                TIMEOUT 120
                LABELS "native-tcp;fstack;socket-broker;nginx-companion;rx-decision;owner-relay;transport-prerequisite"
                ENVIRONMENT "KER_RX_OWNER_RELAY_RECEIPT=${CMAKE_BINARY_DIR}/Testing/Temporary/rx-owner-relay-qualification.json")
            add_test(NAME native-nginx-companion-rx-source-flowmap
                COMMAND "${Python3_EXECUTABLE}"
                    "${PROJECT_SOURCE_DIR}/tests/posix/native-nginx-companion-tap.py"
                    --launcher "${PROJECT_SOURCE_DIR}/tools/ker-run.py"
                    --library "$<TARGET_FILE:ker-posix>"
                    --worker "$<TARGET_FILE:ker-io-worker>"
                    --broker "$<TARGET_FILE:ker-socket-broker-readiness-fixture>"
                    --rx-owner-relay-app "$<TARGET_FILE:ker-socket-broker-rx-owner-relay-fixture>"
                    --nginx "${KER_FSTACK_NGINX_BINARY}"
                    --fstack-runtime "$<TARGET_FILE:ker-fstack-nginx-runtime>"
                    --preload-library "$<TARGET_FILE:ker-socket-preload>"
                    --dpdk-plugin-dir "${ker_session_pmd_dir}"
                    --owner-activation-module "$<TARGET_FILE:ker-fstack-nginx-owner-activation-alias-test>"
                    --worker-shim "$<TARGET_FILE:ker-fstack-nginx-worker-shim>"
                    --rx-owner-relay --rx-owner-relay-source-flowmap
                    --source-nginx-module-source
                    "${KER_FSTACK_NGINX_SOURCE_ROOT}/app/nginx-1.28.0/src/event/modules/ngx_ff_module.c")
            set_tests_properties(native-nginx-companion-rx-source-flowmap PROPERTIES
                TIMEOUT 120
                LABELS "native-tcp;fstack;socket-broker;nginx-companion;rx-decision;owner-relay;source-classifier"
                ENVIRONMENT "KER_RX_OWNER_RELAY_RECEIPT=${CMAKE_BINARY_DIR}/Testing/Temporary/rx-source-flowmap-qualification.json")
            add_test(NAME native-nginx-companion-rx-owner-relay-pending-stop
                COMMAND "${Python3_EXECUTABLE}"
                    "${PROJECT_SOURCE_DIR}/tests/posix/native-nginx-companion-tap.py"
                    --launcher "${PROJECT_SOURCE_DIR}/tools/ker-run.py"
                    --library "$<TARGET_FILE:ker-posix>"
                    --worker "$<TARGET_FILE:ker-io-worker>"
                    --broker "$<TARGET_FILE:ker-socket-broker-readiness-fixture>"
                    --rx-owner-relay-app "$<TARGET_FILE:ker-socket-broker-rx-owner-relay-fixture>"
                    --nginx "${KER_FSTACK_NGINX_BINARY}"
                    --fstack-runtime "$<TARGET_FILE:ker-fstack-nginx-runtime>"
                    --preload-library "$<TARGET_FILE:ker-socket-preload>"
                    --dpdk-plugin-dir "${ker_session_pmd_dir}"
                    --owner-activation-module "$<TARGET_FILE:ker-fstack-nginx-owner-activation-alias-test>"
                    --worker-shim "$<TARGET_FILE:ker-fstack-nginx-worker-shim>"
                    --rx-owner-relay --rx-owner-relay-stop-pending)
            set_tests_properties(native-nginx-companion-rx-owner-relay-pending-stop PROPERTIES
                TIMEOUT 120
                LABELS "native-tcp;fstack;socket-broker;nginx-companion;rx-decision;owner-relay;pending-stop;failure-containment")
        endif()
        add_test(NAME native-nginx-companion-owner-ready-death
            COMMAND "${Python3_EXECUTABLE}"
                "${PROJECT_SOURCE_DIR}/tests/posix/native-nginx-companion-tap.py"
                --launcher "${PROJECT_SOURCE_DIR}/tools/ker-run.py"
                --library "$<TARGET_FILE:ker-posix>"
                --worker "$<TARGET_FILE:ker-io-worker>"
                --broker "$<TARGET_FILE:ker-socket-broker-readiness-fixture>"
                --nginx "${KER_FSTACK_NGINX_BINARY}"
                --fstack-runtime "$<TARGET_FILE:ker-fstack-nginx-runtime>"
                --preload-library "$<TARGET_FILE:ker-socket-preload>"
                --dpdk-plugin-dir "${ker_session_pmd_dir}"
                --owner-activation-module "$<TARGET_FILE:ker-fstack-nginx-owner-activation>"
                --worker-shim "$<TARGET_FILE:ker-fstack-nginx-worker-shim>"
                --owner-death)
        set_tests_properties(native-nginx-companion-owner-ready-death PROPERTIES
            TIMEOUT 120 LABELS "native-tcp;fstack;socket-broker;nginx-companion;owner-ready;failure-containment")
    endif()
endif()
