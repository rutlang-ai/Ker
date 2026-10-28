#include <ker/address-policy.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include "check.h"
#define ff_regist_pcblddr_fun ker_address_policy_register
#define ff_in_pcbladdr ker_address_policy_select
#define assert_int_equal(a, b) CHECK((a) == (b))
#define assert_ptr_equal(a, b) CHECK((a) == (b))
#include "fstack-address-source.inc"
int main(int argc, char **argv)
{
    CHECK(argc == 2);
    if (!strcmp(argv[1], "register")) test_ff_regist_pcblddr_fun_smoke(NULL);
    else if (!strcmp(argv[1], "default")) test_ff_in_pcbladdr_no_callback(NULL);
    else if (!strcmp(argv[1], "ipv4")) test_ff_in_pcbladdr_af_inet_dispatches(NULL);
    else { CHECK(!strcmp(argv[1], "ipv6")); test_ff_in_pcbladdr_af_inet6_freebsd_to_linux_remap(NULL); }
    puts("PASS: complete original address-callback source assertions");
    return 0;
}
