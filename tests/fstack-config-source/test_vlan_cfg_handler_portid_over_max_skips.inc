static void
test_vlan_cfg_handler_portid_over_max_skips(void **state)
{
    (void)state;
    int rv = load_with_fixture(FIXTURE_PATH("valid_vlan_portid_overmax.ini"));
    assert_int_equal(rv, 0);
}
