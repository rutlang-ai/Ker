static void
test_ipfw_pr_cfg_handler_isolated(void **state)
{
    (void)state;
    char prog[]  = "f-stack";
    char dashc[] = "-c";
    char path[]  = FIXTURE_PATH("valid_minimal.ini");
    char dasht[] = "-t";
    char bogus[] = "bogus_proc_type";

    char *argv[] = { prog, dashc, path, dasht, bogus, NULL };
    extern int optind;
    optind = 1;
    int rv = ff_load_config(5, argv);
    assert_int_equal(rv, -1);
}
