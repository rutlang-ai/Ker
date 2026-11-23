/* Real original-EAL primary/provider and secondary/caller fixture. The
 * provider implements no FreeBSD operation: replies explicitly say unsupported. */
#define _GNU_SOURCE
#include <ker/reload.h>
#include "check.h"
#include <inttypes.h>
#include <rte_eal.h>
#include <rte_memzone.h>
#include <rte_mempool.h>
#include <rte_ring.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#define POOL "ker_ipc_mp_pool"
#define ZONE "ker_ipc_mp_identity"
#define MAGIC UINT64_C(0x4b45524950434d50)
struct identity { uint64_t magic, nonce; uint32_t primary; };
struct endpoint { struct rte_ring *input, *output, *reload; };
static struct endpoint endpoints[7];
static struct rte_mempool *pool;
static uint64_t nonce(void)
{
    const char *text = getenv("KER_IPC_MP_NONCE"); CHECK(text && *text);
    char *end; uint64_t value = strtoull(text, &end, 16); CHECK(!*end && value);
    return value;
}
static void ready(void) { CHECK(!fflush(stdout)); }
static void totals(unsigned *in, unsigned *out)
{
    *in = *out = 0;
    for (unsigned i = 0; i < 7; i++) {
        *in += rte_ring_count(endpoints[i].input);
        *out += rte_ring_count(endpoints[i].output) + rte_ring_count(endpoints[i].reload);
    }
}
static void provider(void)
{
    CHECK(rte_eal_process_type() == RTE_PROC_PRIMARY);
    const struct rte_memzone *zone = rte_memzone_reserve(ZONE, sizeof(struct identity), SOCKET_ID_ANY, 0); CHECK(zone);
    *(struct identity *)zone->addr = (struct identity){MAGIC, nonce(), (uint32_t)getpid()};
    pool = ker_ipc_pool_create(POOL, 64, 64); CHECK(pool);
    void *reload_state = calloc(1, ker_reload_state_size()); CHECK(reload_state);
    CHECK(!ker_reload_state_init(reload_state, ker_reload_state_size(), 1));
    CHECK(!ker_reload_bind_state(reload_state, ker_reload_state_size(), 2, 1));
    const char *coordinates[] = {"0:0", "1:0", "1:0:3", "2:1:1", "0:1:2", "0:0", "1:0"};
    for (unsigned i = 0; i < 7; i++) {
        CHECK(ker_ipc_select_or_exit(coordinates[i], NULL) >= 0);
        char name[RTE_RING_NAMESIZE];
        struct ker_ipc_address address; CHECK(!ker_ipc_address(&address));
        CHECK(!ker_ipc_format_ring(name, sizeof(name), &address, 0, FF_UNKNOWN, i < 5));
        endpoints[i].input = rte_ring_create(name, 32, SOCKET_ID_ANY, 0); CHECK(endpoints[i].input);
        CHECK(!ker_ipc_format_ring(name, sizeof(name), &address, 1, FF_SYSCTL, i < 5));
        endpoints[i].output = rte_ring_create(name, 32, SOCKET_ID_ANY, 0); CHECK(endpoints[i].output);
        CHECK(!ker_ipc_format_ring(name, sizeof(name), &address, 1, FF_RELOAD, i < 5));
        endpoints[i].reload = rte_ring_create(name, 32, SOCKET_ID_ANY, 0); CHECK(endpoints[i].reload);
    }
    printf("READY {\"pid\":%u,\"nonce\":\"%" PRIx64 "\",\"available\":%u}\n",(unsigned)getpid(),nonce(),rte_mempool_avail_count(pool)); ready();
    char command[64];
    while (fgets(command, sizeof(command), stdin)) {
        if (!strcmp(command, "pump\n")) {
            unsigned handled = 0;
            for (unsigned i = 0; i < 7; i++) {
                void *object;
                while (!rte_ring_dequeue(endpoints[i].input, &object)) {
                    ker_ipc_message *message = object;
                    CHECK(rte_mempool_from_obj(message) == pool && message->ipc_cookie && message->ipc_owner_pid);
                    CHECK(message->msg_type == FF_SYSCTL || message->msg_type == FF_RELOAD);
                    message->result = -EOPNOTSUPP;
                    if (message->msg_type == FF_RELOAD && message->reload.cmd == FF_RELOAD_CMD_QUERY) {
                        int cmd, gen, status; uint64_t hb;
                        CHECK(!ker_reload_message_parse(message, &cmd, &gen, &status, &hb));
                        ker_reload_message_fill(message, cmd, gen, status, hb);
                    }
                    CHECK(!rte_ring_enqueue(message->msg_type == FF_RELOAD ? endpoints[i].reload : endpoints[i].output, message));
                    handled++;
                }
            }
            printf("PUMP {\"handled\":%u}\n", handled); ready();
        } else if (!strncmp(command, "cancel ", 7)) {
            unsigned owner, cancelled = 0; CHECK(sscanf(command,"cancel %u",&owner) == 1 && owner);
            /* The controller sends this only after that exact caller reports
             * its probe has returned. No active helper retains these objects. */
            for (unsigned i = 0; i < 7; i++) {
                void *object;
                while (!rte_ring_dequeue(endpoints[i].input, &object)) {
                    ker_ipc_message *message = object;
                    CHECK(message->ipc_owner_pid == owner && message->ipc_cookie);
                    CHECK(message->msg_type == FF_RELOAD && message->reload.cmd == FF_RELOAD_CMD_QUERY);
                    CHECK(!message->original_buf);
                    rte_mempool_put(pool,message); cancelled++;
                }
            }
            printf("CANCEL {\"cancelled\":%u}\n",cancelled); ready();
        } else if (!strcmp(command, "status\n")) {
            unsigned in, out; totals(&in, &out);
            printf("STATUS {\"available\":%u,\"input\":%u,\"output\":%u}\n",rte_mempool_avail_count(pool),in,out); ready();
        } else if (!strcmp(command, "quit\n")) {
            unsigned in, out; totals(&in, &out);
            CHECK(!in && !out && rte_mempool_avail_count(pool) == 64);
            for (unsigned i = 0; i < 7; i++) {
                rte_ring_free(endpoints[i].input); rte_ring_free(endpoints[i].output); rte_ring_free(endpoints[i].reload);
            }
            ker_reload_unbind_state(); free(reload_state);
            rte_mempool_free(pool); CHECK(!rte_memzone_free(zone) && !rte_eal_cleanup());
            puts("CLOSED {\"available\":64,\"outstanding\":0}"); ready(); return;
        } else CHECK(0);
    }
    CHECK(0); /* An unexpected controller EOF is not a successful teardown. */
}
static void caller(const char *process, const char *generation, int legacy)
{
    CHECK(rte_eal_process_type() == RTE_PROC_SECONDARY);
    const struct rte_memzone *zone = rte_memzone_lookup(ZONE); CHECK(zone);
    const struct identity *identity = zone->addr;
    const char *parent = getenv("KER_IPC_MP_PRIMARY_PID"); CHECK(parent);
    CHECK(identity->magic == MAGIC && identity->nonce == nonce() && identity->primary == strtoul(parent, NULL, 10));
    pool = rte_mempool_lookup(POOL); CHECK(pool && pool->size == 64 && pool->cache_size == 0);
    CHECK(ker_ipc_select_or_exit(process, generation) >= 0);
    struct ker_ipc_address address; CHECK(!ker_ipc_address(&address));
    char name[RTE_RING_NAMESIZE];
    int named = ker_ipc_ring_name(name, sizeof(name), 0, FF_UNKNOWN);
    int attached = address.generation != KER_IPC_GEN_AUTO;
    if (legacy) {
        CHECK(!attached && named == -EAGAIN && !ker_ipc_attach(pool));
        CHECK(!ker_ipc_ring_name(name, sizeof(name), 0, FF_UNKNOWN));
        CHECK(rte_ring_lookup(name)); attached = 1;
    } else if (attached) CHECK(!named && rte_ring_lookup(name) && !ker_ipc_attach(pool));
    else CHECK(named == -EAGAIN);
    printf("ATTACHED {\"pid\":%u,\"primary\":%u,\"process\":%u,\"generation\":%d,\"epoch\":%u,\"input\":",
        (unsigned)getpid(),identity->primary,address.process,address.generation,address.epoch);
    if (attached) printf("\"%s\"",name); else printf("null");
    puts("}"); ready();
    char command[64], payload[64]; ker_ipc_message *sent = NULL;
    int control = 0;
    while (fgets(command, sizeof(command), stdin)) {
        if (!strncmp(command, "send ", 5)) {
            control = 0;
            unsigned type, private; CHECK(sscanf(command,"send %u %u",&type,&private) == 2);
            CHECK(attached && (type == FF_SYSCTL || type == FF_RELOAD));
            sent = ker_ipc_alloc(); CHECK(sent && sent->buf_addr == (char *)sent + sizeof(*sent));
            CHECK(sent->ipc_owner_pid == (uint32_t)getpid() && sent->ipc_cookie && sent->buf_len >= sizeof(payload));
            CHECK(snprintf(payload, sizeof(payload), "owner-%u-nonce-%" PRIx64,(unsigned)getpid(),nonce()) > 0);
            if (private) {
                /* A process-private address becomes inaccessible at real death;
                 * an orphan reader must never dereference/free this address. */
                sent->original_buf = sent->buf_addr; sent->original_buf_len = sent->buf_len;
                sent->buf_addr = malloc(64); CHECK(sent->buf_addr);
            }
            strcpy(sent->buf_addr,payload); sent->msg_type = (enum FF_MSG_TYPE)type;
            CHECK(!ker_ipc_send(sent));
            printf("SENT {\"pid\":%u,\"cookie\":%u,\"type\":%u}\n",(unsigned)getpid(),sent->ipc_cookie,type); ready();
        } else if (!strncmp(command, "control ", 8)) {
            CHECK(attached && !sent && sscanf(command, "control %d", &control) == 1);
            sent = ker_ipc_alloc(); CHECK(sent);
            strcpy(payload, "control caller bytes"); strcpy(sent->buf_addr, payload);
            ker_reload_message_fill(sent, control, 1, 7, 12345);
            CHECK(!ker_ipc_send(sent));
            printf("SENT {\"pid\":%u,\"cookie\":%u,\"type\":10}\n", (unsigned)getpid(), sent->ipc_cookie); ready();
        } else if (!strncmp(command,"recv ",5)) {
            unsigned type; CHECK(sscanf(command,"recv %u",&type) == 1 && attached);
            ker_ipc_message *received = (void *)(uintptr_t)1;
            int result = ker_ipc_recv(&received,(enum FF_MSG_TYPE)type);
            if (!result) {
                CHECK(received == sent && received->ipc_owner_pid == (uint32_t)getpid());
                CHECK(received->result == (control == FF_RELOAD_CMD_QUERY ? 0 : -EOPNOTSUPP));
                CHECK(!strcmp(received->buf_addr,payload));
                if (control) {
                    int cmd, gen, status; uint64_t hb;
                    CHECK(!ker_reload_message_parse(received, &cmd, &gen, &status, &hb));
                    CHECK(cmd == control && gen == 1 && status == 7 && hb == 12345);
                    if (cmd == FF_RELOAD_CMD_QUERY)
                        CHECK(received->reload.active_gen == 1 && received->reload.epoch == 2);
                }
                CHECK(!ker_ipc_free(received)); sent = NULL;
            } else CHECK(received == (void *)(uintptr_t)1);
            uint64_t requeued, orphan, lost; ker_ipc_reply_stats(&requeued,&orphan,&lost);
            printf("RECV {\"result\":%d,\"requeued\":%" PRIu64 ",\"orphan\":%" PRIu64 ",\"lost\":%" PRIu64 "}\n", result,requeued,orphan,lost); ready();
        } else if (!strcmp(command,"probe\n")) {
            CHECK(attached); uint32_t epoch = 77; int generation_value = 77;
            int result = ker_ipc_probe(&epoch,&generation_value);
            uint64_t requeued, orphan, lost; ker_ipc_reply_stats(&requeued,&orphan,&lost);
            printf("PROBE {\"result\":%d,\"epoch\":%u,\"generation\":%d,\"requeued\":%" PRIu64 ",\"orphan\":%" PRIu64 ",\"lost\":%" PRIu64 "}\n",result,epoch,generation_value,requeued,orphan,lost); ready();
        } else if (!strcmp(command,"busy\n")) {
            CHECK(attached && ker_ipc_detach() == -EBUSY);
            puts("BUSY {\"result\":-16}"); ready();
        } else if (!strcmp(command,"crash\n")) _exit(0);
        else if (!strcmp(command,"exit\n")) {
            if (attached) CHECK(!ker_ipc_detach());
            CHECK(!rte_eal_cleanup()); puts("CLOSED {\"outstanding\":0}"); ready(); return;
        } else CHECK(0);
    }
    CHECK(0);
}
int main(int argc, char **argv)
{
    CHECK(argc >= 3);
    int primary = !strcmp(argv[1],"primary");
    CHECK(primary || ((!strcmp(argv[1],"client") || !strcmp(argv[1],"legacy")) && argc >= 5));
    const char *process = primary || !strcmp(argv[2],"-") ? NULL : argv[2];
    const char *generation = primary || !strcmp(argv[3],"-") ? NULL : argv[3];
    int offset = primary ? 1 : 3;
    CHECK(rte_eal_init(argc-offset,argv+offset) >= 0);
    if (primary) provider(); else caller(process,generation,!strcmp(argv[1],"legacy"));
    return 0;
}
