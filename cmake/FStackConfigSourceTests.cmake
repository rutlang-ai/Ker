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
add_test(NAME fstack-config-source-test_rss_check_cfg_handler_no_port_no_vlan COMMAND ker-test_rss_check_cfg_handler_no_port_no_vlan)
set_tests_properties(fstack-config-source-test_rss_check_cfg_handler_no_port_no_vlan PROPERTIES
    WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}/tests/upstream/fstack/tests/unit" TIMEOUT 30)
add_test(NAME fstack-config-source-test_rss_tbl_cfg_handler_bad_tuple COMMAND ker-test_rss_tbl_cfg_handler_bad_tuple)
set_tests_properties(fstack-config-source-test_rss_tbl_cfg_handler_bad_tuple PROPERTIES
    WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}/tests/upstream/fstack/tests/unit" TIMEOUT 30)
add_test(NAME fstack-config-source-test_rss_check_thash_adjust_off_parses COMMAND ker-test_rss_check_thash_adjust_off_parses)
set_tests_properties(fstack-config-source-test_rss_check_thash_adjust_off_parses PROPERTIES
    WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}/tests/upstream/fstack/tests/unit" TIMEOUT 30)
add_test(NAME fstack-config-source-test_vlan_cfg_handler_id_not_in_filter_returns_one COMMAND ker-test_vlan_cfg_handler_id_not_in_filter_returns_one)
set_tests_properties(fstack-config-source-test_vlan_cfg_handler_id_not_in_filter_returns_one PROPERTIES
    WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}/tests/upstream/fstack/tests/unit" TIMEOUT 30)
add_test(NAME fstack-config-source-test_ff_load_config_vdev_full COMMAND ker-test_ff_load_config_vdev_full)
set_tests_properties(fstack-config-source-test_ff_load_config_vdev_full PROPERTIES
    WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}/tests/upstream/fstack/tests/unit" TIMEOUT 30)
add_test(NAME fstack-config-source-test_port_cfg_handler_id_over_max_returns_one COMMAND ker-test_port_cfg_handler_id_over_max_returns_one)
set_tests_properties(fstack-config-source-test_port_cfg_handler_id_over_max_returns_one PROPERTIES
    WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}/tests/upstream/fstack/tests/unit" TIMEOUT 30)
add_test(NAME fstack-config-source-test_ff_load_config_freebsd_boot_multi_entries COMMAND ker-test_ff_load_config_freebsd_boot_multi_entries)
set_tests_properties(fstack-config-source-test_ff_load_config_freebsd_boot_multi_entries PROPERTIES
    WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}/tests/upstream/fstack/tests/unit" TIMEOUT 30)
add_test(NAME fstack-config-source-test_ff_load_config_inet6_fixture_ignored COMMAND ker-test_ff_load_config_inet6_fixture_ignored)
set_tests_properties(fstack-config-source-test_ff_load_config_inet6_fixture_ignored PROPERTIES
    WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}/tests/upstream/fstack/tests/unit" TIMEOUT 30)
add_test(NAME fstack-config-source-test_ff_load_config_argv_t_override COMMAND ker-test_ff_load_config_argv_t_override)
set_tests_properties(fstack-config-source-test_ff_load_config_argv_t_override PROPERTIES
    WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}/tests/upstream/fstack/tests/unit" TIMEOUT 30)
add_test(NAME fstack-config-source-test_vlan_cfg_handler_portid_over_max_skips COMMAND ker-test_vlan_cfg_handler_portid_over_max_skips)
set_tests_properties(fstack-config-source-test_vlan_cfg_handler_portid_over_max_skips PROPERTIES
    WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}/tests/upstream/fstack/tests/unit" TIMEOUT 30)
add_test(NAME fstack-config-source-test_parse_lcore_mask_proc_id_in_range COMMAND ker-test_parse_lcore_mask_proc_id_in_range)
set_tests_properties(fstack-config-source-test_parse_lcore_mask_proc_id_in_range PROPERTIES
    WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}/tests/upstream/fstack/tests/unit" TIMEOUT 30)
add_test(NAME fstack-config-source-test_parse_lcore_mask_proc_id_over_count_fails COMMAND ker-test_parse_lcore_mask_proc_id_over_count_fails)
set_tests_properties(fstack-config-source-test_parse_lcore_mask_proc_id_over_count_fails PROPERTIES
    WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}/tests/upstream/fstack/tests/unit" TIMEOUT 30)
add_test(NAME fstack-config-source-test_ff_load_config_dpdk_extra_keys COMMAND ker-test_ff_load_config_dpdk_extra_keys)
set_tests_properties(fstack-config-source-test_ff_load_config_dpdk_extra_keys PROPERTIES
    WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}/tests/upstream/fstack/tests/unit" TIMEOUT 30)
add_test(NAME fstack-config-source-test_ff_load_config_bond_vdev_repeat_keys_no_leak COMMAND ker-test_ff_load_config_bond_vdev_repeat_keys_no_leak)
set_tests_properties(fstack-config-source-test_ff_load_config_bond_vdev_repeat_keys_no_leak PROPERTIES
    WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}/tests/upstream/fstack/tests/unit" TIMEOUT 30)
add_test(NAME fstack-config-source-test_parse_lcore_mask_calloc_oom_returns_error COMMAND ker-test_parse_lcore_mask_calloc_oom_returns_error)
set_tests_properties(fstack-config-source-test_parse_lcore_mask_calloc_oom_returns_error PROPERTIES
    WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}/tests/upstream/fstack/tests/unit" TIMEOUT 30)
add_test(NAME fstack-config-source-test_ff_load_config_thread_mode_enabled COMMAND ker-test_ff_load_config_thread_mode_enabled)
set_tests_properties(fstack-config-source-test_ff_load_config_thread_mode_enabled PROPERTIES
    WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}/tests/upstream/fstack/tests/unit" TIMEOUT 30)
add_test(NAME fstack-config-source-test_ff_load_config_thread_mode_default_off COMMAND ker-test_ff_load_config_thread_mode_default_off)
set_tests_properties(fstack-config-source-test_ff_load_config_thread_mode_default_off PROPERTIES
    WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}/tests/upstream/fstack/tests/unit" TIMEOUT 30)
add_test(NAME fstack-config-source-test_ff_load_config_thread_mode_secondary_conflict COMMAND ker-test_ff_load_config_thread_mode_secondary_conflict)
set_tests_properties(fstack-config-source-test_ff_load_config_thread_mode_secondary_conflict PROPERTIES
    WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}/tests/upstream/fstack/tests/unit" TIMEOUT 30)
add_test(NAME fstack-config-source-test_ff_load_config_tcp_ecn_default_off COMMAND ker-test_ff_load_config_tcp_ecn_default_off)
set_tests_properties(fstack-config-source-test_ff_load_config_tcp_ecn_default_off PROPERTIES
    WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}/tests/upstream/fstack/tests/unit" TIMEOUT 30)
add_test(NAME fstack-config-source-test_graceful_reload_default_off COMMAND ker-test_graceful_reload_default_off)
set_tests_properties(fstack-config-source-test_graceful_reload_default_off PROPERTIES
    WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}/tests/upstream/fstack/tests/unit" TIMEOUT 30)
