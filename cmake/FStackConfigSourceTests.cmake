add_test(NAME fstack-config-source-test_ff_load_config_valid_minimal_ini COMMAND ker-test_ff_load_config_valid_minimal_ini)
set_tests_properties(fstack-config-source-test_ff_load_config_valid_minimal_ini PROPERTIES
    WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}/tests/upstream/fstack/tests/unit" TIMEOUT 30)
add_test(NAME fstack-config-source-test_ff_load_config_unknown_section COMMAND ker-test_ff_load_config_unknown_section)
set_tests_properties(fstack-config-source-test_ff_load_config_unknown_section PROPERTIES
    WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}/tests/upstream/fstack/tests/unit" TIMEOUT 30)
add_test(NAME fstack-config-source-test_ff_load_config_all_sections COMMAND ker-test_ff_load_config_all_sections)
set_tests_properties(fstack-config-source-test_ff_load_config_all_sections PROPERTIES
    WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}/tests/upstream/fstack/tests/unit" TIMEOUT 30)
add_test(NAME fstack-config-source-test_ff_load_config_dpdk_full COMMAND ker-test_ff_load_config_dpdk_full)
set_tests_properties(fstack-config-source-test_ff_load_config_dpdk_full PROPERTIES
    WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}/tests/upstream/fstack/tests/unit" TIMEOUT 30)
add_test(NAME fstack-config-source-test_ff_load_config_portlist_nonint COMMAND ker-test_ff_load_config_portlist_nonint)
set_tests_properties(fstack-config-source-test_ff_load_config_portlist_nonint PROPERTIES
    WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}/tests/upstream/fstack/tests/unit" TIMEOUT 30)
