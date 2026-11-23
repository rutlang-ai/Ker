static void
test_ff_load_config_argv_t_override(void **state)
{
    (void)state;
    /* Build argv: f-stack -c <fixture> -t secondary -p 0 */
    char prog[]  = "f-stack";
    char dashc[] = "-c";
    char dasht[] = "-t";
    char dashp[] = "-p";
    char path[]  = FIXTURE_PATH("valid_minimal.ini");
    char tval[]  = "secondary";
    char pval[]  = "0";
    char *argv[] = { prog, dashc, path, dasht, tval, dashp, pval, NULL };
    extern int optind;
    optind = 1;
    int rv = ff_load_config(7, argv);
    assert_int_equal(rv, 0);
    assert_string_equal(ff_global_cfg.dpdk.proc_type, "secondary");
    assert_int_equal(ff_global_cfg.dpdk.proc_id, 0);
}
