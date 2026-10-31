# Fifty additional F-Stack source contracts, one PR each

This series starts at `50111783520b3566d3e8be5161196e55a72ad08a` and adds
**50 distinct original source cases in 50 separate PRs (#393–#442)**.
The previous batches and historical `fstack-unfinished-completed.json` are excluded.

The source audit verifies exactly one case disposition changes in each PR,
and exactly these50 cases change from blocked/partial to scenario-adapted.
The pinned106-file test snapshot, historical completion ledger and existing
Linux/DPDK/F-Stack dependency blobs remain unchanged. New imported parser and
literal helper fragments retain their pinned source hashes.

Scope:37 configuration-parser contracts, one configuration/generation/name
contract using actual public Ker reload/IPC adapters, and12 software RSS
table/hash contracts with an actual caller-side Ker dispatcher consumer.
This does not apply legacy configuration to Ker or qualify Linux PCB port
allocation, physical RSS, protocol interoperability or complete reload.

Current catalog:334 scenario-adapted,2 partial,27 blocked,15 architecture-specific
and55 harness-only out of433. **29 behavioral cases remain unfinished.**

Validation: each source case has its whole original assertions and provenance.
GCC shared, Clang static and ASan/UBSan runs pass; the final strict
`-Wall -Wextra -Werror` profiles each pass104 related CTests, including all50
new source cases and their consumers/import checks. Immutable upstream
diagnostics remain visible through narrow compile-unit/include boundaries;
Ker-owned adaptation code retains strict checks. All21 catalog tests pass.

The RSS example transports128 IPv4/IPv6 metadata fixtures through one original
ring-PMD queue and the public dispatcher. Independent software hashing predicts
32/96 application-ring classifications; exact bytes/pointers/counters and unique
pool511/511 recovery are checked. Separate installed-library consumers and
missing-cleanup, constant-generation and always-local negative controls fail
at the corresponding original/independent assertions.

Implementation commit snapshots and exact CTest bindings are in the
[machine index](../tests/fstack-migration-pr-series-393-442.json). Snapshot SHAs
identify the validated implementation before this documentation-only report.

| PR | Complete original source case | CTest |
|---|---|---|
| [#393](https://github.com/rutlang-ai/Ker/pull/393) | `tests/unit/test_ff_config.c::test_ff_unload_config_zeroes_state` | `fstack-config-original-unload` |
| [#394](https://github.com/rutlang-ai/Ker/pull/394) | `tests/unit/test_ff_config.c::test_ff_load_config_valid_minimal_ini` | `fstack-config-source-test_ff_load_config_valid_minimal_ini` |
| [#395](https://github.com/rutlang-ai/Ker/pull/395) | `tests/unit/test_ff_config.c::test_ff_load_config_unknown_section` | `fstack-config-source-test_ff_load_config_unknown_section` |
| [#396](https://github.com/rutlang-ai/Ker/pull/396) | `tests/unit/test_ff_config.c::test_ff_load_config_all_sections` | `fstack-config-source-test_ff_load_config_all_sections` |
| [#397](https://github.com/rutlang-ai/Ker/pull/397) | `tests/unit/test_ff_config.c::test_ff_load_config_dpdk_full` | `fstack-config-source-test_ff_load_config_dpdk_full` |
| [#398](https://github.com/rutlang-ai/Ker/pull/398) | `tests/unit/test_ff_config.c::test_ff_load_config_portlist_nonint` | `fstack-config-source-test_ff_load_config_portlist_nonint` |
| [#399](https://github.com/rutlang-ai/Ker/pull/399) | `tests/unit/test_ff_config.c::test_rss_check_cfg_handler_no_port_no_vlan` | `fstack-config-source-test_rss_check_cfg_handler_no_port_no_vlan` |
| [#400](https://github.com/rutlang-ai/Ker/pull/400) | `tests/unit/test_ff_config.c::test_rss_tbl_cfg_handler_bad_tuple` | `fstack-config-source-test_rss_tbl_cfg_handler_bad_tuple` |
| [#401](https://github.com/rutlang-ai/Ker/pull/401) | `tests/unit/test_ff_config.c::test_rss_check_thash_adjust_off_parses` | `fstack-config-source-test_rss_check_thash_adjust_off_parses` |
| [#402](https://github.com/rutlang-ai/Ker/pull/402) | `tests/unit/test_ff_config.c::test_vlan_cfg_handler_id_not_in_filter_returns_one` | `fstack-config-source-test_vlan_cfg_handler_id_not_in_filter_returns_one` |
| [#403](https://github.com/rutlang-ai/Ker/pull/403) | `tests/unit/test_ff_config.c::test_ff_load_config_vdev_full` | `fstack-config-source-test_ff_load_config_vdev_full` |
| [#404](https://github.com/rutlang-ai/Ker/pull/404) | `tests/unit/test_ff_config.c::test_port_cfg_handler_id_over_max_returns_one` | `fstack-config-source-test_port_cfg_handler_id_over_max_returns_one` |
| [#405](https://github.com/rutlang-ai/Ker/pull/405) | `tests/unit/test_ff_config.c::test_ff_load_config_freebsd_boot_multi_entries` | `fstack-config-source-test_ff_load_config_freebsd_boot_multi_entries` |
| [#406](https://github.com/rutlang-ai/Ker/pull/406) | `tests/unit/test_ff_config.c::test_ff_load_config_inet6_fixture_ignored` | `fstack-config-source-test_ff_load_config_inet6_fixture_ignored` |
| [#407](https://github.com/rutlang-ai/Ker/pull/407) | `tests/unit/test_ff_config.c::test_ff_load_config_argv_t_override` | `fstack-config-source-test_ff_load_config_argv_t_override` |
| [#408](https://github.com/rutlang-ai/Ker/pull/408) | `tests/unit/test_ff_config.c::test_vlan_cfg_handler_portid_over_max_skips` | `fstack-config-source-test_vlan_cfg_handler_portid_over_max_skips` |
| [#409](https://github.com/rutlang-ai/Ker/pull/409) | `tests/unit/test_ff_config.c::test_parse_lcore_mask_proc_id_in_range` | `fstack-config-source-test_parse_lcore_mask_proc_id_in_range` |
| [#410](https://github.com/rutlang-ai/Ker/pull/410) | `tests/unit/test_ff_config.c::test_parse_lcore_mask_proc_id_over_count_fails` | `fstack-config-source-test_parse_lcore_mask_proc_id_over_count_fails` |
| [#411](https://github.com/rutlang-ai/Ker/pull/411) | `tests/unit/test_ff_config.c::test_ff_load_config_dpdk_extra_keys` | `fstack-config-source-test_ff_load_config_dpdk_extra_keys` |
| [#412](https://github.com/rutlang-ai/Ker/pull/412) | `tests/unit/test_ff_config.c::test_ff_load_config_bond_vdev_repeat_keys_no_leak` | `fstack-config-source-test_ff_load_config_bond_vdev_repeat_keys_no_leak` |
| [#413](https://github.com/rutlang-ai/Ker/pull/413) | `tests/unit/test_ff_config.c::test_parse_lcore_mask_calloc_oom_returns_error` | `fstack-config-source-test_parse_lcore_mask_calloc_oom_returns_error` |
| [#414](https://github.com/rutlang-ai/Ker/pull/414) | `tests/unit/test_ff_config.c::test_ff_load_config_thread_mode_enabled` | `fstack-config-source-test_ff_load_config_thread_mode_enabled` |
| [#415](https://github.com/rutlang-ai/Ker/pull/415) | `tests/unit/test_ff_config.c::test_ff_load_config_thread_mode_default_off` | `fstack-config-source-test_ff_load_config_thread_mode_default_off` |
| [#416](https://github.com/rutlang-ai/Ker/pull/416) | `tests/unit/test_ff_config.c::test_ff_load_config_thread_mode_secondary_conflict` | `fstack-config-source-test_ff_load_config_thread_mode_secondary_conflict` |
| [#417](https://github.com/rutlang-ai/Ker/pull/417) | `tests/unit/test_ff_config.c::test_ff_load_config_tcp_ecn_default_off` | `fstack-config-source-test_ff_load_config_tcp_ecn_default_off` |
| [#418](https://github.com/rutlang-ai/Ker/pull/418) | `tests/unit/test_ff_config.c::test_graceful_reload_default_off` | `fstack-config-source-test_graceful_reload_default_off` |
| [#419](https://github.com/rutlang-ai/Ker/pull/419) | `tests/unit/test_ff_config.c::test_graceful_reload_parse` | `fstack-config-source-test_graceful_reload_parse` |
| [#420](https://github.com/rutlang-ai/Ker/pull/420) | `tests/unit/test_ff_config.c::test_graceful_reload_requires_slim` | `fstack-config-source-test_graceful_reload_requires_slim` |
| [#421](https://github.com/rutlang-ai/Ker/pull/421) | `tests/unit/test_ff_config.c::test_greload_thread_mode_mutex` | `fstack-config-source-test_greload_thread_mode_mutex` |
| [#422](https://github.com/rutlang-ai/Ker/pull/422) | `tests/unit/test_ff_config.c::test_greload_off_no_new_checks` | `fstack-config-source-test_greload_off_no_new_checks` |
| [#423](https://github.com/rutlang-ai/Ker/pull/423) | `tests/unit/test_ff_config.c::test_greload_bad_value_atoi` | `fstack-config-source-test_greload_bad_value_atoi` |
| [#424](https://github.com/rutlang-ai/Ker/pull/424) | `tests/unit/test_ff_config.c::test_ut_nr_20_queue_mapping_config` | `fstack-config-source-test_ut_nr_20_queue_mapping_config` |
| [#425](https://github.com/rutlang-ai/Ker/pull/425) | `tests/unit/test_ff_config.c::test_ut_nr_25_drain_ring_size_config` | `fstack-config-source-test_ut_nr_25_drain_ring_size_config` |
| [#426](https://github.com/rutlang-ai/Ker/pull/426) | `tests/unit/test_ff_config.c::test_ff_load_config_stack_coexist_enabled` | `fstack-config-source-test_ff_load_config_stack_coexist_enabled` |
| [#427](https://github.com/rutlang-ai/Ker/pull/427) | `tests/unit/test_ff_config.c::test_ff_load_config_stack_absent_defaults_disabled` | `fstack-config-source-test_ff_load_config_stack_absent_defaults_disabled` |
| [#428](https://github.com/rutlang-ai/Ker/pull/428) | `tests/unit/test_ff_config.c::test_ff_load_config_stack_garbage_defaults_disabled` | `fstack-config-source-test_ff_load_config_stack_garbage_defaults_disabled` |
| [#429](https://github.com/rutlang-ai/Ker/pull/429) | `tests/unit/test_ff_config.c::test_ff_load_config_stack_coexist_disabled_explicit` | `fstack-config-source-test_ff_load_config_stack_coexist_disabled_explicit` |
| [#430](https://github.com/rutlang-ai/Ker/pull/430) | `tests/unit/test_ff_config.c::test_ut_nr_12_generation_mapping` | `fstack-config-generation-mapping` |
| [#431](https://github.com/rutlang-ai/Ker/pull/431) | `tests/unit/test_ff_dpdk_if.c::test_ff_rss_tbl_set_portrange_no_cfg` | `fstack-rss-table-no-config` |
| [#432](https://github.com/rutlang-ai/Ker/pull/432) | `tests/unit/test_ff_dpdk_if.c::test_ff_rss_tbl_set_portrange_disabled` | `fstack-rss-table-test_ff_rss_tbl_set_portrange_disabled` |
| [#433](https://github.com/rutlang-ai/Ker/pull/433) | `tests/unit/test_ff_dpdk_if.c::test_ff_rss_tbl_set_portrange_inverted_range` | `fstack-rss-table-test_ff_rss_tbl_set_portrange_inverted_range` |
| [#434](https://github.com/rutlang-ai/Ker/pull/434) | `tests/unit/test_ff_dpdk_if.c::test_ff_rss_tbl_get_portrange_no_cfg` | `fstack-rss-table-test_ff_rss_tbl_get_portrange_no_cfg` |
| [#435](https://github.com/rutlang-ai/Ker/pull/435) | `tests/unit/test_ff_dpdk_if.c::test_ff_rss_tbl_get_portrange_disabled` | `fstack-rss-table-test_ff_rss_tbl_get_portrange_disabled` |
| [#436](https://github.com/rutlang-ai/Ker/pull/436) | `tests/unit/test_ff_dpdk_if.c::test_ff_rss_tbl_get_portrange_smoke` | `fstack-rss-table-test_ff_rss_tbl_get_portrange_smoke` |
| [#437](https://github.com/rutlang-ai/Ker/pull/437) | `tests/unit/test_ff_dpdk_if.c::test_ff_rss_tbl_get_portrange_hit` | `fstack-rss-table-test_ff_rss_tbl_get_portrange_hit` |
| [#438](https://github.com/rutlang-ai/Ker/pull/438) | `tests/unit/test_ff_dpdk_if.c::test_ff_rss_tbl_get_portrange_rotation` | `fstack-rss-table-test_ff_rss_tbl_get_portrange_rotation` |
| [#439](https://github.com/rutlang-ai/Ker/pull/439) | `tests/unit/test_ff_dpdk_if.c::test_ff_rss_tbl_get_portrange_miss` | `fstack-rss-table-test_ff_rss_tbl_get_portrange_miss` |
| [#440](https://github.com/rutlang-ai/Ker/pull/440) | `tests/unit/test_ff_dpdk_if.c::test_ff_rss_check6_landing` | `fstack-rss-table-test_ff_rss_check6_landing` |
| [#441](https://github.com/rutlang-ai/Ker/pull/441) | `tests/unit/test_ff_dpdk_if.c::test_ff_rss_check6_single_queue` | `fstack-rss-table-test_ff_rss_check6_single_queue` |
| [#442](https://github.com/rutlang-ai/Ker/pull/442) | `tests/unit/test_ff_dpdk_if.c::test_ff_rss_tbl6_set_get` | `fstack-rss-table-test_ff_rss_tbl6_set_get` |
