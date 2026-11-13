set(KER_SOURCE_MASTER_ABORT_RETRY_FAULT_RUNTIME "" CACHE PATH
    "Separate build directory containing the isolated original flip_fail_once libfstack.so")

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
            if(TARGET ker-nginx-owner-group-controller)
                add_test(NAME native-nginx-companion-rx-source-peer-continuity
                    COMMAND "${Python3_EXECUTABLE}"
                        "${PROJECT_SOURCE_DIR}/tests/posix/native-nginx-peer-source.py"
                        --build "${CMAKE_BINARY_DIR}"
                        --nginx "${KER_FSTACK_NGINX_BINARY}"
                        --dpdk-plugin-dir "${ker_session_pmd_dir}"
                        --source-nginx-module-source "${KER_FSTACK_NGINX_SOURCE_ROOT}/app/nginx-1.28.0/src/event/modules/ngx_ff_module.c")
                set_tests_properties(native-nginx-companion-rx-source-peer-continuity PROPERTIES
                    TIMEOUT 190
                    LABELS "native-tcp;fstack;socket-broker;nginx-companion;rx-decision;owner-relay;source-classifier;peer")
                add_test(NAME native-nginx-companion-rx-source-peer-accept-expiry
                    COMMAND "${Python3_EXECUTABLE}"
                        "${PROJECT_SOURCE_DIR}/tests/posix/native-nginx-peer-source.py"
                        --build "${CMAKE_BINARY_DIR}"
                        --nginx "${KER_FSTACK_NGINX_BINARY}"
                        --dpdk-plugin-dir "${ker_session_pmd_dir}"
                        --source-nginx-module-source
                        "${KER_FSTACK_NGINX_SOURCE_ROOT}/app/nginx-1.28.0/src/event/modules/ngx_ff_module.c"
                        --async-accept-expiry
                        --root "/dev/shm/kc28")
                set_tests_properties(native-nginx-companion-rx-source-peer-accept-expiry PROPERTIES
                    TIMEOUT 190
                    LABELS "native-tcp;fstack;socket-broker;nginx-companion;rx-decision;owner-relay;source-classifier;peer;async-accept;expiry;quarantine")
            endif()
            if(TARGET ker-nginx-owner-group-controller AND
               TARGET ker-socket-broker-rx-owner-relay-fixture AND
               TARGET ker-fstack-nginx-owner-activation)
                add_test(NAME native-nginx-source-master-first-hup
                    COMMAND "${Python3_EXECUTABLE}"
                        "${PROJECT_SOURCE_DIR}/tests/posix/native-nginx-source-master.py"
                        --build "${CMAKE_BINARY_DIR}"
                        --nginx "${KER_FSTACK_NGINX_BINARY}"
                        --dpdk-plugin-dir "${ker_session_pmd_dir}"
                        --source-nginx-module-source
                        "${KER_FSTACK_NGINX_SOURCE_ROOT}/app/nginx-1.28.0/src/event/modules/ngx_ff_module.c"
                        --root "${CMAKE_BINARY_DIR}/Testing/Temporary/native-nginx-source-master")
                set_tests_properties(native-nginx-source-master-first-hup PROPERTIES
                    TIMEOUT 300
                    LABELS "native-tcp;fstack;socket-broker;nginx-companion;source-bootstrap;source-master;first-hup")
                add_test(NAME native-nginx-source-master-two-successful-hups
                    COMMAND "${Python3_EXECUTABLE}"
                        "${PROJECT_SOURCE_DIR}/tests/posix/native-nginx-source-master-successor.py"
                        --build "${CMAKE_BINARY_DIR}"
                        --adapter-build "${CMAKE_BINARY_DIR}"
                        --runtime "${CMAKE_BINARY_DIR}"
                        --nginx "${KER_FSTACK_NGINX_BINARY}"
                        --dpdk-plugin-dir "${ker_session_pmd_dir}"
                        --source-nginx-module-source
                        "${KER_FSTACK_NGINX_SOURCE_ROOT}/app/nginx-1.28.0/src/event/modules/ngx_ff_module.c"
                        --root "${CMAKE_BINARY_DIR}/Testing/Temporary/native-nginx-source-master-successor")
                set_tests_properties(native-nginx-source-master-two-successful-hups PROPERTIES
                    TIMEOUT 300
                    LABELS "native-tcp;fstack;socket-broker;nginx-companion;source-bootstrap;source-master;successor;rv9-two-rounds")
                add_test(NAME native-nginx-source-master-expired-commit
                    COMMAND "${Python3_EXECUTABLE}"
                        "${PROJECT_SOURCE_DIR}/tests/posix/native-nginx-source-master.py"
                        --build "${CMAKE_BINARY_DIR}"
                        --nginx "${KER_FSTACK_NGINX_BINARY}"
                        --dpdk-plugin-dir "${ker_session_pmd_dir}"
                        --source-nginx-module-source
                        "${KER_FSTACK_NGINX_SOURCE_ROOT}/app/nginx-1.28.0/src/event/modules/ngx_ff_module.c"
                        --mode shared-budget-expiry
                        --root "${CMAKE_BINARY_DIR}/Testing/Temporary/native-nginx-source-master-expiry")
                set_tests_properties(native-nginx-source-master-expired-commit PROPERTIES
                    TIMEOUT 180
                    LABELS "native-tcp;fstack;socket-broker;nginx-companion;source-bootstrap;source-master;expiry;containment")
                if(KER_SOURCE_MASTER_ABORT_RETRY_FAULT_RUNTIME AND
                   EXISTS "${KER_SOURCE_MASTER_ABORT_RETRY_FAULT_RUNTIME}/libfstack.so")
                    add_test(NAME native-nginx-source-master-abort-retry
                        COMMAND "${Python3_EXECUTABLE}"
                            "${PROJECT_SOURCE_DIR}/tests/posix/native-nginx-source-master-abort-retry.py"
                            --build "${CMAKE_BINARY_DIR}"
                            --adapter-build "${CMAKE_BINARY_DIR}"
                            --fault-runtime "${KER_SOURCE_MASTER_ABORT_RETRY_FAULT_RUNTIME}"
                            --nginx "${KER_FSTACK_NGINX_BINARY}"
                            --dpdk-plugin-dir "${ker_session_pmd_dir}"
                            --source-nginx-module-source
                            "${KER_FSTACK_NGINX_SOURCE_ROOT}/app/nginx-1.28.0/src/event/modules/ngx_ff_module.c"
                            --root "${CMAKE_BINARY_DIR}/Testing/Temporary/native-nginx-source-master-abort-retry")
                    set_tests_properties(native-nginx-source-master-abort-retry PROPERTIES
                        TIMEOUT 360
                        LABELS "native-tcp;fstack;socket-broker;nginx-companion;source-bootstrap;source-master;abort;retry;rt24")
                endif()
            endif()
            if(TARGET ker-socket-broker-reuseport-group-client)
                add_test(NAME native-nginx-companion-rx-source-admission
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
                        --rx-owner-relay --rx-owner-relay-source-admission
                        --reuseport-group-client "$<TARGET_FILE:ker-socket-broker-reuseport-group-client>"
                        --source-nginx-module-source
                        "${KER_FSTACK_NGINX_SOURCE_ROOT}/app/nginx-1.28.0/src/event/modules/ngx_ff_module.c")
                set_tests_properties(native-nginx-companion-rx-source-admission PROPERTIES
                    TIMEOUT 150
                    LABELS "native-tcp;fstack;socket-broker;nginx-companion;rx-decision;owner-relay;source-admission"
                    ENVIRONMENT "KER_RX_OWNER_RELAY_RECEIPT=${CMAKE_BINARY_DIR}/Testing/Temporary/rx-source-admission-qualification.json")
                add_test(NAME native-nginx-companion-rx-source-admission-revoke
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
                        --rx-owner-relay --rx-owner-relay-source-admission
                        --rx-owner-relay-source-admission-revoke
                        --reuseport-group-client "$<TARGET_FILE:ker-socket-broker-reuseport-group-client>"
                        --source-nginx-module-source
                        "${KER_FSTACK_NGINX_SOURCE_ROOT}/app/nginx-1.28.0/src/event/modules/ngx_ff_module.c")
                set_tests_properties(native-nginx-companion-rx-source-admission-revoke PROPERTIES
                    TIMEOUT 150
                    LABELS "native-tcp;fstack;socket-broker;nginx-companion;rx-decision;owner-relay;source-admission;revoke"
                    ENVIRONMENT "KER_RX_OWNER_RELAY_RECEIPT=${CMAKE_BINARY_DIR}/Testing/Temporary/rx-source-admission-revoke-qualification.json")
                add_test(NAME native-nginx-companion-rx-source-admission-prepared-failure
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
                        --rx-owner-relay --rx-owner-relay-source-admission
                        --rx-owner-relay-source-admission-prepared-failure
                        --reuseport-group-client "$<TARGET_FILE:ker-socket-broker-reuseport-group-client>"
                        --source-nginx-module-source
                        "${KER_FSTACK_NGINX_SOURCE_ROOT}/app/nginx-1.28.0/src/event/modules/ngx_ff_module.c")
                set_tests_properties(native-nginx-companion-rx-source-admission-prepared-failure PROPERTIES
                    TIMEOUT 150
                    LABELS "native-tcp;fstack;socket-broker;nginx-companion;owner-relay;source-admission;rollback"
                    ENVIRONMENT "KER_RX_OWNER_RELAY_RECEIPT=${CMAKE_BINARY_DIR}/Testing/Temporary/rx-source-admission-prepared-failure-qualification.json")
            endif()
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
