static void
test_vdev_cfg_handler_no_nb_vdev_returns_zero(void **state)
{
    (void)state;
    int rv = load_with_fixture(FIXTURE_PATH("invalid_vdev_no_nb_vdev.ini"));
    assert_int_equal(rv, -1);
}
