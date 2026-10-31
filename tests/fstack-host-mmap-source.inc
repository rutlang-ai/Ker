static void
test_ff_mmap_failure_exits(void **state)
{
    (void)state;
    /* MAP_SHARED + MAP_PRIVATE both set is invalid per mmap(2). */
    expect_assert_failure(
        ff_mmap(NULL, 4096, ff_PROT_READ | ff_PROT_WRITE,
                ff_MAP_SHARED | ff_MAP_PRIVATE | ff_MAP_ANON,
                -1, 0));
}
