static void
test_parse_lcore_mask_proc_id_over_count_fails(void **state)
{
    (void)state;
    int rv = load_with_proc(FIXTURE_PATH("valid_lcore_blank_multibit.ini"),
                            "primary", "5");
    assert_int_equal(rv, -1);
}
