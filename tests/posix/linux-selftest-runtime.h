#ifndef KER_LINUX_SELFTEST_RUNTIME_H
#define KER_LINUX_SELFTEST_RUNTIME_H
/* Private tests-ON fixture ABI; never installed. */
enum ker_linux_selftest_operation {
    KER_TEST_UNSHARE, KER_TEST_SETNS, KER_TEST_OPEN, KER_TEST_ACCESS,
    KER_TEST_MKDIR, KER_TEST_RMDIR, KER_TEST_MOUNT, KER_TEST_UMOUNT,
    KER_TEST_NETLINK, KER_TEST_FD_NUMBER, KER_TEST_FINALIZE, KER_TEST_IF_UP, KER_TEST_OPERATION_COUNT
};
long ker_linux_selftest_call(unsigned operation, const unsigned long arguments[6]);
#endif
