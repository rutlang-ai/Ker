add_test(NAME fstack-config-source-test_ff_load_config_valid_minimal_ini COMMAND ker-test_ff_load_config_valid_minimal_ini)
set_tests_properties(fstack-config-source-test_ff_load_config_valid_minimal_ini PROPERTIES
    WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}/tests/upstream/fstack/tests/unit" TIMEOUT 30)
add_test(NAME fstack-config-source-test_ff_load_config_unknown_section COMMAND ker-test_ff_load_config_unknown_section)
set_tests_properties(fstack-config-source-test_ff_load_config_unknown_section PROPERTIES
    WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}/tests/upstream/fstack/tests/unit" TIMEOUT 30)
