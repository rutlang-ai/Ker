# Private C34 control-channel codec and dedicated Nginx companion launcher.
# ker-run imports these siblings unconditionally, so they are installed with it.
configure_file(tools/broker_readiness_supervisor.py
    "${PROJECT_BINARY_DIR}/broker_readiness_supervisor.py" COPYONLY)
configure_file(tools/broker_readiness_wire.py
    "${PROJECT_BINARY_DIR}/broker_readiness_wire.py" COPYONLY)
configure_file(tools/nginx_companion_supervisor.py
    "${PROJECT_BINARY_DIR}/nginx_companion_supervisor.py" COPYONLY)
configure_file(tools/nginx_companion_wire.py
    "${PROJECT_BINARY_DIR}/nginx_companion_wire.py" COPYONLY)
configure_file(tools/ker-nginx-companion.py
    "${PROJECT_BINARY_DIR}/ker-nginx-companion" COPYONLY)
install(FILES
    "${PROJECT_BINARY_DIR}/broker_readiness_supervisor.py"
    "${PROJECT_BINARY_DIR}/broker_readiness_wire.py"
    "${PROJECT_BINARY_DIR}/nginx_companion_supervisor.py"
    "${PROJECT_BINARY_DIR}/nginx_companion_wire.py"
    DESTINATION ${CMAKE_INSTALL_BINDIR} COMPONENT fstack-nginx-runtime)
install(PROGRAMS "${PROJECT_BINARY_DIR}/ker-nginx-companion"
    DESTINATION ${CMAKE_INSTALL_BINDIR} COMPONENT fstack-nginx-runtime)

if(BUILD_TESTING)
    include("${PROJECT_SOURCE_DIR}/cmake/NginxCompanionTests.cmake")
endif()
