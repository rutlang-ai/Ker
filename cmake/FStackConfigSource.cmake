# Exercise legacy configuration documents independently of the Ker launcher.
add_library(ker-test-fstack-config STATIC
    "${PROJECT_SOURCE_DIR}/third_party/fstack-config/ff_config.c"
    "${PROJECT_SOURCE_DIR}/examples/fstack-config-ini.c"
    "${PROJECT_SOURCE_DIR}/examples/fstack-config-policy.c")
target_include_directories(ker-test-fstack-config PUBLIC
    "${PROJECT_SOURCE_DIR}/examples" "${PROJECT_SOURCE_DIR}/third_party/fstack-reload"
    PRIVATE "${PROJECT_SOURCE_DIR}/third_party/inih" "${PROJECT_SOURCE_DIR}/third_party/fstack-ipc")
target_link_libraries(ker-test-fstack-config PRIVATE PkgConfig::DPDK)
target_compile_definitions(ker-test-fstack-config PUBLIC FF_KERNEL_COEXIST)
set_target_properties(ker-test-fstack-config PROPERTIES C_STANDARD 11
    C_STANDARD_REQUIRED YES C_EXTENSIONS OFF)
set_source_files_properties("${PROJECT_SOURCE_DIR}/third_party/fstack-config/ff_config.c"
    PROPERTIES COMPILE_DEFINITIONS
    "_GNU_SOURCE;ff_global_cfg=example_upstream_global_cfg;ff_load_config=example_upstream_load_config;ff_unload_config=example_upstream_unload_config;dpdk_argc=example_upstream_dpdk_argc;dpdk_argv=example_upstream_dpdk_argv;short_options=example_upstream_short_options;long_options=example_upstream_long_options;FF_LOG_FILENAME_PREFIX=example_upstream_log_filename_prefix;ini_parse=example_upstream_ini_parse")

function(fstack_config_case case)
    add_executable("ker-${case}" fstack-config-case.c)
    target_compile_definitions("ker-${case}" PRIVATE
        "SOURCE_FUNCTION=${case}" "SOURCE_INCLUDE=fstack-config-source/${case}.inc")
    target_compile_options("ker-${case}" PRIVATE -Wall -Wextra -Werror)
    target_link_libraries("ker-${case}" PRIVATE ker-test-fstack-config)
    # Resolve transitive shared libraries from the selected DPDK build.
    target_link_options("ker-${case}" PRIVATE -Wl,--disable-new-dtags)
    set_target_properties("ker-${case}" PROPERTIES BUILD_RPATH "${DPDK_LIBRARY_DIRS}")
endfunction()

fstack_config_case(test_ff_load_config_valid_minimal_ini)
add_test(NAME fstack-config-source-test_ff_load_config_valid_minimal_ini
    COMMAND ker-test_ff_load_config_valid_minimal_ini)
set_tests_properties(fstack-config-source-test_ff_load_config_valid_minimal_ini PROPERTIES
    WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}/tests/upstream/fstack/tests/unit"
    TIMEOUT 30 LABELS fstack)

fstack_config_case(test_ff_load_config_unknown_section)
add_test(NAME fstack-config-source-test_ff_load_config_unknown_section COMMAND ker-test_ff_load_config_unknown_section)
set_tests_properties(fstack-config-source-test_ff_load_config_unknown_section PROPERTIES
    WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}/tests/upstream/fstack/tests/unit"
    TIMEOUT 30 LABELS fstack)

fstack_config_case(test_ff_load_config_all_sections)
add_test(NAME fstack-config-source-test_ff_load_config_all_sections COMMAND ker-test_ff_load_config_all_sections)
set_tests_properties(fstack-config-source-test_ff_load_config_all_sections PROPERTIES
    WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}/tests/upstream/fstack/tests/unit"
    TIMEOUT 30 LABELS fstack)

fstack_config_case(test_ff_load_config_dpdk_full)
add_test(NAME fstack-config-source-test_ff_load_config_dpdk_full COMMAND ker-test_ff_load_config_dpdk_full)
set_tests_properties(fstack-config-source-test_ff_load_config_dpdk_full PROPERTIES
    WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}/tests/upstream/fstack/tests/unit"
    TIMEOUT 30 LABELS fstack)

fstack_config_case(test_ff_load_config_freebsd_boot_multi_entries)
add_test(NAME fstack-config-source-test_ff_load_config_freebsd_boot_multi_entries COMMAND ker-test_ff_load_config_freebsd_boot_multi_entries)
set_tests_properties(fstack-config-source-test_ff_load_config_freebsd_boot_multi_entries PROPERTIES
    WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}/tests/upstream/fstack/tests/unit"
    TIMEOUT 30 LABELS fstack)

fstack_config_case(test_ff_load_config_tcp_ecn_default_off)
add_test(NAME fstack-config-source-test_ff_load_config_tcp_ecn_default_off COMMAND ker-test_ff_load_config_tcp_ecn_default_off)
set_tests_properties(fstack-config-source-test_ff_load_config_tcp_ecn_default_off PROPERTIES
    WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}/tests/upstream/fstack/tests/unit"
    TIMEOUT 30 LABELS fstack)

fstack_config_case(test_ff_load_config_inet6_fixture_ignored)
add_test(NAME fstack-config-source-test_ff_load_config_inet6_fixture_ignored COMMAND ker-test_ff_load_config_inet6_fixture_ignored)
set_tests_properties(fstack-config-source-test_ff_load_config_inet6_fixture_ignored PROPERTIES
    WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}/tests/upstream/fstack/tests/unit"
    TIMEOUT 30 LABELS fstack)

fstack_config_case(test_ff_load_config_repeat_keys_no_leak)
add_test(NAME fstack-config-source-test_ff_load_config_repeat_keys_no_leak COMMAND ker-test_ff_load_config_repeat_keys_no_leak)
set_tests_properties(fstack-config-source-test_ff_load_config_repeat_keys_no_leak PROPERTIES
    WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}/tests/upstream/fstack/tests/unit"
    TIMEOUT 30 LABELS fstack)

fstack_config_case(test_ff_load_config_dpdk_extra_keys)
add_test(NAME fstack-config-source-test_ff_load_config_dpdk_extra_keys COMMAND ker-test_ff_load_config_dpdk_extra_keys)
set_tests_properties(fstack-config-source-test_ff_load_config_dpdk_extra_keys PROPERTIES
    WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}/tests/upstream/fstack/tests/unit"
    TIMEOUT 30 LABELS fstack)

fstack_config_case(test_ff_load_config_vdev_full)
add_test(NAME fstack-config-source-test_ff_load_config_vdev_full COMMAND ker-test_ff_load_config_vdev_full)
set_tests_properties(fstack-config-source-test_ff_load_config_vdev_full PROPERTIES
    WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}/tests/upstream/fstack/tests/unit"
    TIMEOUT 30 LABELS fstack)

fstack_config_case(test_ff_load_config_bond_vdev_repeat_keys_no_leak)
add_test(NAME fstack-config-source-test_ff_load_config_bond_vdev_repeat_keys_no_leak COMMAND ker-test_ff_load_config_bond_vdev_repeat_keys_no_leak)
set_tests_properties(fstack-config-source-test_ff_load_config_bond_vdev_repeat_keys_no_leak PROPERTIES
    WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}/tests/upstream/fstack/tests/unit"
    TIMEOUT 30 LABELS fstack)

fstack_config_case(test_vlan_cfg_handler_id_not_in_filter_returns_one)
add_test(NAME fstack-config-source-test_vlan_cfg_handler_id_not_in_filter_returns_one COMMAND ker-test_vlan_cfg_handler_id_not_in_filter_returns_one)
set_tests_properties(fstack-config-source-test_vlan_cfg_handler_id_not_in_filter_returns_one PROPERTIES
    WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}/tests/upstream/fstack/tests/unit"
    TIMEOUT 30 LABELS fstack)

fstack_config_case(test_vlan_cfg_handler_portid_over_max_skips)
add_test(NAME fstack-config-source-test_vlan_cfg_handler_portid_over_max_skips COMMAND ker-test_vlan_cfg_handler_portid_over_max_skips)
set_tests_properties(fstack-config-source-test_vlan_cfg_handler_portid_over_max_skips PROPERTIES
    WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}/tests/upstream/fstack/tests/unit"
    TIMEOUT 30 LABELS fstack)

fstack_config_case(test_port_cfg_handler_id_over_max_returns_one)
add_test(NAME fstack-config-source-test_port_cfg_handler_id_over_max_returns_one COMMAND ker-test_port_cfg_handler_id_over_max_returns_one)
set_tests_properties(fstack-config-source-test_port_cfg_handler_id_over_max_returns_one PROPERTIES
    WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}/tests/upstream/fstack/tests/unit"
    TIMEOUT 30 LABELS fstack)

fstack_config_case(test_rss_tbl_cfg_handler_bad_tuple)
add_test(NAME fstack-config-source-test_rss_tbl_cfg_handler_bad_tuple COMMAND ker-test_rss_tbl_cfg_handler_bad_tuple)
set_tests_properties(fstack-config-source-test_rss_tbl_cfg_handler_bad_tuple PROPERTIES
    WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}/tests/upstream/fstack/tests/unit"
    TIMEOUT 30 LABELS fstack)

fstack_config_case(test_rss_check_thash_adjust_off_parses)
add_test(NAME fstack-config-source-test_rss_check_thash_adjust_off_parses COMMAND ker-test_rss_check_thash_adjust_off_parses)
set_tests_properties(fstack-config-source-test_rss_check_thash_adjust_off_parses PROPERTIES
    WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}/tests/upstream/fstack/tests/unit"
    TIMEOUT 30 LABELS fstack)

fstack_config_case(test_parse_lcore_mask_proc_id_in_range)
add_test(NAME fstack-config-source-test_parse_lcore_mask_proc_id_in_range COMMAND ker-test_parse_lcore_mask_proc_id_in_range)
set_tests_properties(fstack-config-source-test_parse_lcore_mask_proc_id_in_range PROPERTIES
    WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}/tests/upstream/fstack/tests/unit"
    TIMEOUT 30 LABELS fstack)

fstack_config_case(test_parse_lcore_mask_proc_id_over_count_fails)
add_test(NAME fstack-config-source-test_parse_lcore_mask_proc_id_over_count_fails COMMAND ker-test_parse_lcore_mask_proc_id_over_count_fails)
set_tests_properties(fstack-config-source-test_parse_lcore_mask_proc_id_over_count_fails PROPERTIES
    WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}/tests/upstream/fstack/tests/unit"
    TIMEOUT 30 LABELS fstack)

fstack_config_case(test_ff_load_config_argv_t_override)
add_test(NAME fstack-config-source-test_ff_load_config_argv_t_override COMMAND ker-test_ff_load_config_argv_t_override)
set_tests_properties(fstack-config-source-test_ff_load_config_argv_t_override PROPERTIES
    WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}/tests/upstream/fstack/tests/unit"
    TIMEOUT 30 LABELS fstack)

fstack_config_case(test_ipfw_pr_cfg_handler_isolated)
add_test(NAME fstack-config-source-test_ipfw_pr_cfg_handler_isolated COMMAND ker-test_ipfw_pr_cfg_handler_isolated)
set_tests_properties(fstack-config-source-test_ipfw_pr_cfg_handler_isolated PROPERTIES
    WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}/tests/upstream/fstack/tests/unit"
    TIMEOUT 30 LABELS fstack)

fstack_config_case(test_ff_load_config_bond_full)
add_test(NAME fstack-config-source-test_ff_load_config_bond_full COMMAND ker-test_ff_load_config_bond_full)
set_tests_properties(fstack-config-source-test_ff_load_config_bond_full PROPERTIES
    WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}/tests/upstream/fstack/tests/unit"
    TIMEOUT 30 LABELS fstack)

fstack_config_case(test_ff_check_config_kni_method_reject_ok)
add_test(NAME fstack-config-source-test_ff_check_config_kni_method_reject_ok COMMAND ker-test_ff_check_config_kni_method_reject_ok)
set_tests_properties(fstack-config-source-test_ff_check_config_kni_method_reject_ok PROPERTIES
    WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}/tests/upstream/fstack/tests/unit"
    TIMEOUT 30 LABELS fstack)

fstack_config_case(test_ff_check_config_kni_method_invalid_fails)
add_test(NAME fstack-config-source-test_ff_check_config_kni_method_invalid_fails COMMAND ker-test_ff_check_config_kni_method_invalid_fails)
set_tests_properties(fstack-config-source-test_ff_check_config_kni_method_invalid_fails PROPERTIES
    WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}/tests/upstream/fstack/tests/unit"
    TIMEOUT 30 LABELS fstack)

fstack_config_case(test_ff_check_config_kni_primary_lcore_present_ok)
add_test(NAME fstack-config-source-test_ff_check_config_kni_primary_lcore_present_ok COMMAND ker-test_ff_check_config_kni_primary_lcore_present_ok)
set_tests_properties(fstack-config-source-test_ff_check_config_kni_primary_lcore_present_ok PROPERTIES
    WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}/tests/upstream/fstack/tests/unit"
    TIMEOUT 30 LABELS fstack)

fstack_config_case(test_ff_check_config_kni_primary_lcore_missing_fails)
add_test(NAME fstack-config-source-test_ff_check_config_kni_primary_lcore_missing_fails COMMAND ker-test_ff_check_config_kni_primary_lcore_missing_fails)
set_tests_properties(fstack-config-source-test_ff_check_config_kni_primary_lcore_missing_fails PROPERTIES
    WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}/tests/upstream/fstack/tests/unit"
    TIMEOUT 30 LABELS fstack)

fstack_config_case(test_ff_load_config_thread_mode_enabled)
add_test(NAME fstack-config-source-test_ff_load_config_thread_mode_enabled COMMAND ker-test_ff_load_config_thread_mode_enabled)
set_tests_properties(fstack-config-source-test_ff_load_config_thread_mode_enabled PROPERTIES
    WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}/tests/upstream/fstack/tests/unit"
    TIMEOUT 30 LABELS fstack)

fstack_config_case(test_ff_load_config_thread_mode_default_off)
add_test(NAME fstack-config-source-test_ff_load_config_thread_mode_default_off COMMAND ker-test_ff_load_config_thread_mode_default_off)
set_tests_properties(fstack-config-source-test_ff_load_config_thread_mode_default_off PROPERTIES
    WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}/tests/upstream/fstack/tests/unit"
    TIMEOUT 30 LABELS fstack)

fstack_config_case(test_ff_load_config_thread_mode_secondary_conflict)
add_test(NAME fstack-config-source-test_ff_load_config_thread_mode_secondary_conflict COMMAND ker-test_ff_load_config_thread_mode_secondary_conflict)
set_tests_properties(fstack-config-source-test_ff_load_config_thread_mode_secondary_conflict PROPERTIES
    WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}/tests/upstream/fstack/tests/unit"
    TIMEOUT 30 LABELS fstack)

fstack_config_case(test_graceful_reload_default_off)
add_test(NAME fstack-config-source-test_graceful_reload_default_off COMMAND ker-test_graceful_reload_default_off)
set_tests_properties(fstack-config-source-test_graceful_reload_default_off PROPERTIES
    WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}/tests/upstream/fstack/tests/unit"
    TIMEOUT 30 LABELS fstack)

fstack_config_case(test_graceful_reload_parse)
add_test(NAME fstack-config-source-test_graceful_reload_parse COMMAND ker-test_graceful_reload_parse)
set_tests_properties(fstack-config-source-test_graceful_reload_parse PROPERTIES
    WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}/tests/upstream/fstack/tests/unit"
    TIMEOUT 30 LABELS fstack)

fstack_config_case(test_graceful_reload_requires_slim)
add_test(NAME fstack-config-source-test_graceful_reload_requires_slim COMMAND ker-test_graceful_reload_requires_slim)
set_tests_properties(fstack-config-source-test_graceful_reload_requires_slim PROPERTIES
    WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}/tests/upstream/fstack/tests/unit"
    TIMEOUT 30 LABELS fstack)

fstack_config_case(test_greload_thread_mode_mutex)
add_test(NAME fstack-config-source-test_greload_thread_mode_mutex COMMAND ker-test_greload_thread_mode_mutex)
set_tests_properties(fstack-config-source-test_greload_thread_mode_mutex PROPERTIES
    WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}/tests/upstream/fstack/tests/unit"
    TIMEOUT 30 LABELS fstack)

fstack_config_case(test_greload_off_no_new_checks)
add_test(NAME fstack-config-source-test_greload_off_no_new_checks COMMAND ker-test_greload_off_no_new_checks)
set_tests_properties(fstack-config-source-test_greload_off_no_new_checks PROPERTIES
    WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}/tests/upstream/fstack/tests/unit"
    TIMEOUT 30 LABELS fstack)

fstack_config_case(test_greload_bad_value_atoi)
add_test(NAME fstack-config-source-test_greload_bad_value_atoi COMMAND ker-test_greload_bad_value_atoi)
set_tests_properties(fstack-config-source-test_greload_bad_value_atoi PROPERTIES
    WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}/tests/upstream/fstack/tests/unit"
    TIMEOUT 30 LABELS fstack)

fstack_config_case(test_ut_nr_20_queue_mapping_config)
add_test(NAME fstack-config-source-test_ut_nr_20_queue_mapping_config COMMAND ker-test_ut_nr_20_queue_mapping_config)
set_tests_properties(fstack-config-source-test_ut_nr_20_queue_mapping_config PROPERTIES
    WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}/tests/upstream/fstack/tests/unit"
    TIMEOUT 30 LABELS fstack)

fstack_config_case(test_ut_nr_25_drain_ring_size_config)
add_test(NAME fstack-config-source-test_ut_nr_25_drain_ring_size_config COMMAND ker-test_ut_nr_25_drain_ring_size_config)
set_tests_properties(fstack-config-source-test_ut_nr_25_drain_ring_size_config PROPERTIES
    WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}/tests/upstream/fstack/tests/unit"
    TIMEOUT 30 LABELS fstack)

fstack_config_case(test_ff_load_config_stack_coexist_enabled)
add_test(NAME fstack-config-source-test_ff_load_config_stack_coexist_enabled COMMAND ker-test_ff_load_config_stack_coexist_enabled)
set_tests_properties(fstack-config-source-test_ff_load_config_stack_coexist_enabled PROPERTIES
    WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}/tests/upstream/fstack/tests/unit"
    TIMEOUT 30 LABELS fstack)

fstack_config_case(test_ff_load_config_stack_absent_defaults_disabled)
add_test(NAME fstack-config-source-test_ff_load_config_stack_absent_defaults_disabled COMMAND ker-test_ff_load_config_stack_absent_defaults_disabled)
set_tests_properties(fstack-config-source-test_ff_load_config_stack_absent_defaults_disabled PROPERTIES
    WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}/tests/upstream/fstack/tests/unit"
    TIMEOUT 30 LABELS fstack)

fstack_config_case(test_ff_load_config_stack_garbage_defaults_disabled)
add_test(NAME fstack-config-source-test_ff_load_config_stack_garbage_defaults_disabled COMMAND ker-test_ff_load_config_stack_garbage_defaults_disabled)
set_tests_properties(fstack-config-source-test_ff_load_config_stack_garbage_defaults_disabled PROPERTIES
    WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}/tests/upstream/fstack/tests/unit"
    TIMEOUT 30 LABELS fstack)

fstack_config_case(test_ff_load_config_stack_coexist_disabled_explicit)
add_test(NAME fstack-config-source-test_ff_load_config_stack_coexist_disabled_explicit COMMAND ker-test_ff_load_config_stack_coexist_disabled_explicit)
set_tests_properties(fstack-config-source-test_ff_load_config_stack_coexist_disabled_explicit PROPERTIES
    WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}/tests/upstream/fstack/tests/unit"
    TIMEOUT 30 LABELS fstack)

fstack_config_case(test_ff_load_config_portlist_nonint)
target_sources(ker-test_ff_load_config_portlist_nonint PRIVATE fstack-config-rejection.c)
target_link_libraries(ker-test_ff_load_config_portlist_nonint PRIVATE PkgConfig::DPDK)
target_include_directories(ker-test_ff_load_config_portlist_nonint PRIVATE "${PROJECT_SOURCE_DIR}/third_party/inih")
target_compile_definitions(ker-test_ff_load_config_portlist_nonint PRIVATE
    FSTACK_CONFIG_VERIFY_REJECTION
    "FSTACK_CONFIG_REJECTION_FIXTURE=\"fixtures/invalid_portlist_nonint.ini\""
    FSTACK_CONFIG_REJECT_LIST)
target_link_options(ker-test_ff_load_config_portlist_nonint PRIVATE -Wl,--wrap=rte_strsplit)
add_test(NAME fstack-config-source-test_ff_load_config_portlist_nonint COMMAND ker-test_ff_load_config_portlist_nonint)
set_tests_properties(fstack-config-source-test_ff_load_config_portlist_nonint PROPERTIES
    WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}/tests/upstream/fstack/tests/unit"
    TIMEOUT 30 LABELS fstack)

fstack_config_case(test_rss_check_cfg_handler_no_port_no_vlan)
target_sources(ker-test_rss_check_cfg_handler_no_port_no_vlan PRIVATE fstack-config-rejection.c)
target_link_libraries(ker-test_rss_check_cfg_handler_no_port_no_vlan PRIVATE PkgConfig::DPDK)
target_include_directories(ker-test_rss_check_cfg_handler_no_port_no_vlan PRIVATE "${PROJECT_SOURCE_DIR}/third_party/inih")
target_compile_definitions(ker-test_rss_check_cfg_handler_no_port_no_vlan PRIVATE
    FSTACK_CONFIG_VERIFY_REJECTION
    "FSTACK_CONFIG_REJECTION_FIXTURE=\"fixtures/invalid_rss_check_no_port.ini\""
    "FSTACK_CONFIG_REJECT_SECTION=\"rss_check\""
    "FSTACK_CONFIG_REJECT_KEY=\"enable\"")
target_link_options(ker-test_rss_check_cfg_handler_no_port_no_vlan PRIVATE -Wl,--wrap=example_upstream_ini_parse)
add_test(NAME fstack-config-source-test_rss_check_cfg_handler_no_port_no_vlan COMMAND ker-test_rss_check_cfg_handler_no_port_no_vlan)
set_tests_properties(fstack-config-source-test_rss_check_cfg_handler_no_port_no_vlan PROPERTIES
    WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}/tests/upstream/fstack/tests/unit"
    TIMEOUT 30 LABELS fstack)

fstack_config_case(test_bond_cfg_handler_no_nb_bond)
target_sources(ker-test_bond_cfg_handler_no_nb_bond PRIVATE fstack-config-rejection.c)
target_link_libraries(ker-test_bond_cfg_handler_no_nb_bond PRIVATE PkgConfig::DPDK)
target_include_directories(ker-test_bond_cfg_handler_no_nb_bond PRIVATE "${PROJECT_SOURCE_DIR}/third_party/inih")
target_compile_definitions(ker-test_bond_cfg_handler_no_nb_bond PRIVATE
    FSTACK_CONFIG_VERIFY_REJECTION
    "FSTACK_CONFIG_REJECTION_FIXTURE=\"fixtures/invalid_bond_no_nb_bond.ini\""
    "FSTACK_CONFIG_REJECT_SECTION=\"bond0\""
    "FSTACK_CONFIG_REJECT_KEY=\"mode\"")
target_link_options(ker-test_bond_cfg_handler_no_nb_bond PRIVATE -Wl,--wrap=example_upstream_ini_parse)
add_test(NAME fstack-config-source-test_bond_cfg_handler_no_nb_bond COMMAND ker-test_bond_cfg_handler_no_nb_bond)
set_tests_properties(fstack-config-source-test_bond_cfg_handler_no_nb_bond PROPERTIES
    WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}/tests/upstream/fstack/tests/unit"
    TIMEOUT 30 LABELS fstack)

fstack_config_case(test_bond_cfg_handler_bad_section)
target_sources(ker-test_bond_cfg_handler_bad_section PRIVATE fstack-config-rejection.c)
target_link_libraries(ker-test_bond_cfg_handler_bad_section PRIVATE PkgConfig::DPDK)
target_include_directories(ker-test_bond_cfg_handler_bad_section PRIVATE "${PROJECT_SOURCE_DIR}/third_party/inih")
target_compile_definitions(ker-test_bond_cfg_handler_bad_section PRIVATE
    FSTACK_CONFIG_VERIFY_REJECTION
    "FSTACK_CONFIG_REJECTION_FIXTURE=\"fixtures/invalid_bond_bad_section.ini\""
    "FSTACK_CONFIG_REJECT_SECTION=\"bond_xx\""
    "FSTACK_CONFIG_REJECT_KEY=\"mode\"")
target_link_options(ker-test_bond_cfg_handler_bad_section PRIVATE -Wl,--wrap=example_upstream_ini_parse)
add_test(NAME fstack-config-source-test_bond_cfg_handler_bad_section COMMAND ker-test_bond_cfg_handler_bad_section)
set_tests_properties(fstack-config-source-test_bond_cfg_handler_bad_section PROPERTIES
    WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}/tests/upstream/fstack/tests/unit"
    TIMEOUT 30 LABELS fstack)

fstack_config_case(test_vdev_cfg_handler_no_nb_vdev_returns_zero)
target_sources(ker-test_vdev_cfg_handler_no_nb_vdev_returns_zero PRIVATE fstack-config-rejection.c)
target_link_libraries(ker-test_vdev_cfg_handler_no_nb_vdev_returns_zero PRIVATE PkgConfig::DPDK)
target_include_directories(ker-test_vdev_cfg_handler_no_nb_vdev_returns_zero PRIVATE "${PROJECT_SOURCE_DIR}/third_party/inih")
target_compile_definitions(ker-test_vdev_cfg_handler_no_nb_vdev_returns_zero PRIVATE
    FSTACK_CONFIG_VERIFY_REJECTION
    "FSTACK_CONFIG_REJECTION_FIXTURE=\"fixtures/invalid_vdev_no_nb_vdev.ini\""
    "FSTACK_CONFIG_REJECT_SECTION=\"vdev0\""
    "FSTACK_CONFIG_REJECT_KEY=\"iface\"")
target_link_options(ker-test_vdev_cfg_handler_no_nb_vdev_returns_zero PRIVATE -Wl,--wrap=example_upstream_ini_parse)
add_test(NAME fstack-config-source-test_vdev_cfg_handler_no_nb_vdev_returns_zero COMMAND ker-test_vdev_cfg_handler_no_nb_vdev_returns_zero)
set_tests_properties(fstack-config-source-test_vdev_cfg_handler_no_nb_vdev_returns_zero PROPERTIES
    WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}/tests/upstream/fstack/tests/unit"
    TIMEOUT 30 LABELS fstack)

fstack_config_case(test_vdev_cfgs_calloc_oom_returns_error)
target_sources(ker-test_vdev_cfgs_calloc_oom_returns_error PRIVATE fstack-config-allocation.c)
target_link_libraries(ker-test_vdev_cfgs_calloc_oom_returns_error PRIVATE PkgConfig::DPDK)
target_compile_definitions(ker-test_vdev_cfgs_calloc_oom_returns_error PRIVATE
    FSTACK_CONFIG_CHECK_ALLOCATION
    FSTACK_CONFIG_ALLOCATED_TYPE=ff_vdev_cfg
    FSTACK_CONFIG_ALLOCATED_FIELD=vdev_cfgs
    "FSTACK_CONFIG_RECOVERY_FIXTURE=\"valid_vdev.ini\"")
target_link_options(ker-test_vdev_cfgs_calloc_oom_returns_error PRIVATE -Wl,--wrap=calloc)
add_test(NAME fstack-config-source-test_vdev_cfgs_calloc_oom_returns_error COMMAND ker-test_vdev_cfgs_calloc_oom_returns_error)
set_tests_properties(fstack-config-source-test_vdev_cfgs_calloc_oom_returns_error PROPERTIES
    WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}/tests/upstream/fstack/tests/unit"
    TIMEOUT 30 LABELS fstack)

add_test(NAME fstack-config-source-import
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/fstack-config-import.py")
set_tests_properties(fstack-config-source-import PROPERTIES TIMEOUT 30 LABELS "fstack;provenance")
