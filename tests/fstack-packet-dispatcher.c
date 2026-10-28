#include <ker/packet-dispatcher.h>
#include <string.h>
#include "check.h"
#define ff_dispatcher_context ker_dispatcher_context
#define ff_regist_packet_dispatcher ker_packet_dispatcher_register
#define ff_regist_packet_dispatcher_context ker_packet_dispatcher_register_context
#define ff_unregist_packet_dispatcher ker_packet_dispatcher_unregister
#define ff_unregist_packet_dispatcher_context ker_packet_dispatcher_unregister_context
#include "fstack-dispatch-source.inc"
int main(int argc, char **argv)
{
    CHECK(argc == 2);
    if (!strcmp(argv[1], "plain")) test_ff_regist_packet_dispatcher_smoke(NULL);
    else if (!strcmp(argv[1], "context")) test_ff_regist_packet_dispatcher_context_smoke(NULL);
    else { CHECK(!strcmp(argv[1], "unregister")); test_ut_nr_24_unregist_dispatcher(NULL); }
    puts("PASS: complete original packet-dispatcher source tests");
    return 0;
}
