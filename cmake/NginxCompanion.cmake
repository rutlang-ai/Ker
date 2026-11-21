# Private C34 control-channel codec and dedicated Nginx companion launcher.
# ker-run imports these siblings unconditionally, so they are installed with it.
configure_file(tools/broker_readiness_supervisor.py
    "${PROJECT_BINARY_DIR}/broker_readiness_supervisor.py" COPYONLY)
configure_file(tools/broker_readiness_wire.py
    "${PROJECT_BINARY_DIR}/broker_readiness_wire.py" COPYONLY)
configure_file(tools/ker_run_control.py
    "${PROJECT_BINARY_DIR}/ker_run_control.py" COPYONLY)
configure_file(tools/ker_run_control_wire.py
    "${PROJECT_BINARY_DIR}/ker_run_control_wire.py" COPYONLY)
configure_file(tools/nginx_companion_supervisor.py
    "${PROJECT_BINARY_DIR}/nginx_companion_supervisor.py" COPYONLY)
configure_file(tools/nginx_companion_wire.py
    "${PROJECT_BINARY_DIR}/nginx_companion_wire.py" COPYONLY)
configure_file(tools/ker-nginx-companion.py
    "${PROJECT_BINARY_DIR}/ker-nginx-companion" COPYONLY)
# Source observers resolve their private adapters beside the launcher.  Keep
# the source spelling too: the origin observer verifies and imports those
# exact launcher bytes rather than executing a second launcher process.
set(ker_source_observer_modules
    ker-run.py
    ker-nginx-companion.py
    source_network_startup.py
    nginx_companion_attach.py
    nginx_cycle_control.py
    nginx_source_bootstrap_supervisor.py
    nginx_source_c22_provider.py
    nginx_source_c34_artifact_provider.py
    nginx_source_c34_profile.py
    nginx_source_origin.py
    nginx_source_scope.py
    nginx_source_shell_controller.py
    nginx-source-shell-helper.py
    ker-source-shell-wrapper.py)
foreach(module IN LISTS ker_source_observer_modules)
    if(module STREQUAL "ker-run.py")
        configure_file("tools/${module}"
            "${PROJECT_BINARY_DIR}/${module}" @ONLY)
    else()
        configure_file("tools/${module}"
            "${PROJECT_BINARY_DIR}/${module}" COPYONLY)
    endif()
    if(module STREQUAL "ker-source-shell-wrapper.py")
        install(PROGRAMS "${PROJECT_BINARY_DIR}/${module}"
            DESTINATION ${CMAKE_INSTALL_BINDIR} COMPONENT fstack-nginx-runtime)
    else()
        install(FILES "${PROJECT_BINARY_DIR}/${module}"
            DESTINATION ${CMAKE_INSTALL_BINDIR} COMPONENT fstack-nginx-runtime)
    endif()
endforeach()
install(FILES
    "${PROJECT_BINARY_DIR}/broker_readiness_supervisor.py"
    "${PROJECT_BINARY_DIR}/broker_readiness_wire.py"
    "${PROJECT_BINARY_DIR}/ker_run_control.py"
    "${PROJECT_BINARY_DIR}/ker_run_control_wire.py"
    "${PROJECT_BINARY_DIR}/nginx_companion_supervisor.py"
    "${PROJECT_BINARY_DIR}/nginx_companion_wire.py"
    DESTINATION ${CMAKE_INSTALL_BINDIR} COMPONENT fstack-nginx-runtime)
install(PROGRAMS "${PROJECT_BINARY_DIR}/ker-nginx-companion"
    DESTINATION ${CMAKE_INSTALL_BINDIR} COMPONENT fstack-nginx-runtime)

if(BUILD_TESTING)
    include("${PROJECT_SOURCE_DIR}/cmake/NginxCompanionTests.cmake")
endif()
