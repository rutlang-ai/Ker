/* SPDX-License-Identifier: GPL-2.0-only */
#define _GNU_SOURCE
#include "io-session.h"
#include "session-packet.h"
#include "session-generation-rings.h"
#include "packet-channel.h"
#include <sys/uio.h>
#include "worker-exception.h"
#include <sys/types.h>
#include <net/if.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/random.h>
#include <sys/time.h>
#include <stdbool.h>
#include <poll.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_errno.h>
#include <rte_memzone.h>
#include <rte_ring.h>
#include <rte_ring_peek.h>
#ifdef KER_SESSION_TEST_HOOKS
#include <pthread.h>
#endif
#include <rte_mbuf.h>
#include <time.h>
#ifndef SO_PEERPIDFD
#define SO_PEERPIDFD 77
#endif
#define CLIENTS 64
#define QUEUES (KER_SESSION_SLOTS * KER_SESSION_GENERATIONS * KER_SESSION_PROCESSES * KER_SESSION_CHANNELS)
enum kind { UNUSED, UNBOUND, MASTER, RESERVED, ATTACHED, RELEASED };
struct client {
    int fd, pidfd;
    pid_t pid;
    enum kind kind;
    unsigned slot, generation, process;
    uint64_t sequence, probe_sequence, heartbeat_ms;
    bool generation_admitted, drain_mode, peer_only, detach_done, detach_armed, detach_foreign;
    bool detach_peer_snapshot;
    unsigned detach_peer_generation, detach_peer_process;
    unsigned detach_peer_client;
    pid_t detach_peer_pid;
    int detach_peer_pidfd;
    uint64_t detach_pmd_owner;
    uintptr_t detach_pmd_packet, detach_pmd_rx_packet;
    uint16_t detach_pmd_port;
    bool detach_pmd_configured;
    unsigned detach_owner_client, detach_owner_slot, detach_owner_generation, detach_owner_process;
    pid_t detach_owner_pid;
    int detach_owner_pidfd;
    uint64_t detach_owner_epoch;
    struct ker_generation_cleanup_config detach_cleanup;
    uint64_t detach_peer_epoch, detach_sequence;
    unsigned handoff_state, handoff_peer;
    int handoff_peer_pidfd, handoff_peer_client_pidfd;
    pid_t handoff_peer_pid;
    unsigned handoff_peer_slot, handoff_peer_generation, handoff_peer_process;
    uint64_t handoff_peer_epoch;
    uint64_t handoff_capability, handoff_owner_key, handoff_tx_lease_id, handoff_rx_lease_id;
    uint64_t handoff_started_ms;
    uintptr_t handoff_tx_pointer, handoff_rx_pointer, handoff_exception_ring;
    uintptr_t handoff_packet_rx_ring, handoff_packet_tx_ring;
    int handoff_owner_pidfd, handoff_exception_fd;
    pid_t handoff_owner_pid;
    unsigned handoff_owner_slot, handoff_owner_generation, handoff_owner_process;
    uint64_t handoff_owner_epoch;
    unsigned handoff_exception_ifindex, handoff_ring_pmd;
    unsigned handoff_rx_queues, handoff_tx_queues;
    uint16_t handoff_port;
    bool handoff_pmd_configured, pmd_parked;
    bool frame_pending;
    uint32_t frame_object_index;
    uint64_t frame_pool_tag, frame_lease_id, frame_capability;
    uint16_t frame_port, frame_queue;
    unsigned frame_consumer_client;
    int frame_consumer_pidfd, frame_producer_pidfd;
    struct ker_generation_identity frame_producer_identity, frame_consumer_identity;
    uint64_t pmd_tx_lease_id, pmd_rx_lease_id;
    uint64_t peer_capability, detach_capability;
    unsigned detach_peer_slot, detach_rx_count, detach_tx_count;
    struct rte_mbuf *leased_packet;
    struct ker_session_message request, reply;
};
struct slot {
    uint64_t epoch, token;
    int master;
    pid_t worker_pid[KER_SESSION_GENERATIONS][KER_SESSION_PROCESSES];
    uint64_t worker_heartbeat_ms[KER_SESSION_GENERATIONS][KER_SESSION_PROCESSES];
    bool worker_drain_mode[KER_SESSION_GENERATIONS][KER_SESSION_PROCESSES];
    uint64_t peer_capability, peer_epoch;
    unsigned peer_generation, peer_process;
    int peer_master, peer_child, peer_child_pidfd;
    pid_t peer_child_pid;
};
#define KER_SESSION_PEER_STALE_MS 2000U
static uint64_t monotonic_ms(void);
static struct client clients[CLIENTS];
static struct slot slots[KER_SESSION_SLOTS];
static struct rte_ring *rings[QUEUES];
static struct rte_mempool *message_pool;
static struct rte_mbuf *message_objects[KER_SESSION_OBJECTS];
static struct ker_generation_cleanup_config generation_cleanup_config;
static const struct rte_memzone *zone;
static struct ker_session_directory *directory;
static uint64_t next_epoch = 1;
static unsigned ring_pmd;
static uint16_t pmd_port;
static bool pmd_configured;
static unsigned pmd_rx_queues, pmd_tx_queues;
#ifdef KER_SESSION_TEST_HOOKS
static bool generation_empty_cleanup_test;
static bool generation_test_corrupt_after_collection;
static bool generation_frame_drain_test;
static bool tc3_probe_gate;
static bool tc3_drain_requested;
static bool tc3_observer;
static bool directory_test_hooks;
static bool directory_test_replay_attached;
struct directory_test_header {
    uint64_t magic, version, size, session;
    uint32_t slots, generations, processes, channels, capacity;
};
static struct directory_test_header directory_test_original;
#endif
static int pmd_client = -1;
static int handoff_client = -1, handoff_peer = -1;
static unsigned handoff_state;
static uint64_t handoff_capability, next_pmd_lease_id = 1;
enum { HANDOFF_NONE, HANDOFF_PREPARED, HANDOFF_PARKED };
#define KER_SESSION_HANDOFF_TIMEOUT_MS 5000U
static struct rte_mbuf *pmd_packet, *pmd_rx_packet;
static struct rte_ring *packet_rx, *packet_tx;
static bool generation_rings_enabled;
static struct ker_generation_rings *generation_rings;
/* Live ownership transfer is proven only for the one-queue net_ring port
 * created by ker_session_packet_create(). Other PMDs need their own stop and
 * queue-ownership contract before they can use this operation. */
static bool exact_handoff_ring_port(void)
{
    uint16_t named_port = UINT16_MAX;
    struct rte_eth_dev_info info = {0};
    return ring_pmd == 2 && pmd_configured && pmd_rx_queues == 1 && pmd_tx_queues == 1 && packet_rx && packet_tx &&
        packet_rx != packet_tx &&
        !rte_eth_dev_get_port_by_name(KER_SESSION_PACKET_PORT, &named_port) &&
        named_port == pmd_port && !rte_eth_dev_info_get(pmd_port, &info) &&
        info.driver_name && !strcmp(info.driver_name, "net_ring") &&
        rte_ring_lookup(KER_SESSION_PACKET_RX) == packet_rx &&
        rte_ring_lookup(KER_SESSION_PACKET_TX) == packet_tx;
}
static int merge_packet_stats(struct ker_session_packet_stats *total,
    const struct ker_session_packet_stats *part)
{
#define ADD_STAT(field) do { if (UINT64_MAX-total->field<part->field) return -EOVERFLOW; total->field+=part->field; } while (0)
    ADD_STAT(tx); ADD_STAT(rx); ADD_STAT(to_wire); ADD_STAT(from_wire);
    ADD_STAT(exception_to_wire); ADD_STAT(exception_from_wire);
    ADD_STAT(exception_to_native); ADD_STAT(fragment_to_native);
#undef ADD_STAT
    if (total->exception_endpoint_owner_key && part->exception_endpoint_owner_key &&
        total->exception_endpoint_owner_key!=part->exception_endpoint_owner_key) return -ESTALE;
    if (!total->exception_endpoint_owner_key) total->exception_endpoint_owner_key=part->exception_endpoint_owner_key;
    if (UINT_MAX-total->retained<part->retained) return -EOVERFLOW;
    total->retained+=part->retained;
    total->status=part->status;
    return 0;
}
static bool generation_cleanup_equal(const struct ker_generation_cleanup_config *a,
    const struct ker_generation_cleanup_config *b)
{
    return a && b && a->version==b->version && a->size==b->size && a->ports==b->ports &&
        a->queues==b->queues && a->rx_queue_mask==b->rx_queue_mask &&
        a->tx_queue_mask==b->tx_queue_mask;
}
#ifdef KER_SESSION_TEST_HOOKS
static struct rte_ring *generation_test_original[8];
static struct rte_mbuf *generation_test_original_packet[8];
static bool generation_test_hold_started;
static pthread_t generation_test_hold_thread;
static struct {
    struct ker_generation_rings *rings;
    struct ker_generation_identity identity;
} generation_test_hold_context;
static void *generation_test_hold_rx_dequeue(void *unused)
{
    (void)unused;
    struct rte_mbuf *packet=NULL;
    int result=ker_generation_rx_dequeue(generation_test_hold_context.rings,
        &generation_test_hold_context.identity,0,0,&packet);
    fprintf(stderr,"ker session: held generation dequeue returned unexpectedly %d\n",result);
    return NULL;
}
#endif
static struct ker_worker_exception session_exception_keeper = {.fd=-1};
static char session_exception_iface[IFNAMSIZ], session_exception_ring[RTE_RING_NAMESIZE];
static int dead(int fd);
static uint64_t pmd_key(const struct client *client)
{
    return 1 + ((uint64_t)client->slot * KER_SESSION_GENERATIONS + client->generation) * KER_SESSION_PROCESSES + client->process;
}
static struct ker_generation_identity generation_identity(const struct client *client)
{
    return (struct ker_generation_identity){.session=directory->session,
        .epoch=slots[client->slot].epoch,.slot=client->slot,
        .generation=client->generation,.process=client->process,.pid=(uint32_t)client->pid};
}
static bool frame_command(uint64_t command)
{
    return command==KER_SESSION_FRAME_PREPARE || command==KER_SESSION_FRAME_COMMIT ||
        command==KER_SESSION_FRAME_CANCEL;
}
enum frame_resolution { FRAME_COMMITTED, FRAME_CANCELLED, FRAME_DEAD_REAPED };
static void frame_pending_clear(struct client *client, enum frame_resolution resolution)
{
    if (!client) return;
    if (resolution < FRAME_COMMITTED || resolution > FRAME_DEAD_REAPED || !client->frame_pending)
        _Exit(125);
    if (client->frame_consumer_pidfd>=0) close(client->frame_consumer_pidfd);
    if (client->frame_producer_pidfd>=0) close(client->frame_producer_pidfd);
    client->frame_pending=false;
    client->frame_object_index=0;
    client->frame_pool_tag=client->frame_lease_id=client->frame_capability=0;
    client->frame_port=client->frame_queue=0;
    client->frame_consumer_client=UINT_MAX;
    client->frame_consumer_pidfd=client->frame_producer_pidfd=-1;
    memset(&client->frame_producer_identity,0,sizeof(client->frame_producer_identity));
    memset(&client->frame_consumer_identity,0,sizeof(client->frame_consumer_identity));
}
static bool frame_source_matches(const struct client *producer)
{
    if (!producer || producer->kind!=ATTACHED || producer->peer_only ||
        !producer->generation_admitted || !producer->pmd_parked ||
        producer->handoff_state!=HANDOFF_PARKED || producer->slot>=KER_SESSION_SLOTS ||
        producer->generation>=KER_SESSION_GENERATIONS || producer->process>=KER_SESSION_PROCESSES ||
        producer->handoff_owner_pidfd!=producer->pidfd || producer->handoff_owner_pid!=producer->pid ||
        producer->handoff_owner_slot!=producer->slot || producer->handoff_owner_generation!=producer->generation ||
        producer->handoff_owner_process!=producer->process ||
        producer->handoff_owner_epoch!=slots[producer->slot].epoch || dead(producer->pidfd)) return false;
    return true;
}
static bool frame_consumer_matches(const struct client *producer)
{
    if (!producer || !producer->frame_pending || !frame_source_matches(producer) ||
        producer->frame_consumer_client>=CLIENTS || pmd_client!=(int)producer->frame_consumer_client ||
        producer->frame_consumer_pidfd<0 || producer->frame_producer_pidfd<0 ||
        dead(producer->frame_consumer_pidfd) || dead(producer->frame_producer_pidfd)) return false;
    const struct client *consumer=&clients[producer->frame_consumer_client];
    if (consumer->kind!=ATTACHED || consumer->peer_only || !consumer->generation_admitted ||
        dead(consumer->pidfd) || consumer->pidfd<0 ||
        producer->handoff_peer!=(unsigned)producer->frame_consumer_client ||
        producer->handoff_peer_pidfd<0 || dead(producer->handoff_peer_pidfd) ||
        producer->handoff_peer_client_pidfd!=consumer->pidfd ||
        consumer->pid!=(pid_t)producer->frame_consumer_identity.pid ||
        consumer->slot!=producer->frame_consumer_identity.slot ||
        consumer->generation!=producer->frame_consumer_identity.generation ||
        consumer->generation!=(producer->generation^1U) ||
        consumer->process!=producer->frame_consumer_identity.process ||
        slots[consumer->slot].epoch!=producer->frame_consumer_identity.epoch ||
        producer->frame_consumer_identity.session!=directory->session ||
        atomic_load_explicit(&directory->pmd_owner,memory_order_acquire)!=pmd_key(consumer)) return false;
    return true;
}
static int handle_frame_request(struct client *client,const struct ker_session_message *request,
    struct ker_session_message *reply)
{
    if (!generation_rings_enabled || !generation_rings || ring_pmd!=2 || request->status ||
        request->session!=directory->session || request->slot!=client->slot ||
        request->epoch!=slots[client->slot].epoch || request->generation!=client->generation ||
        request->process!=client->process || request->token!=slots[client->slot].token ||
        request->capability!=client->handoff_capability || !client->handoff_capability ||
        !frame_source_matches(client)) return -EPERM;
    uint64_t tag=ker_generation_packet_pool_tag(generation_rings);
    if (!tag || request->packet_pool_tag!=tag || request->packet_port!=0 || request->packet_queue>=2)
        return -EOPNOTSUPP;
    if (request->command==KER_SESSION_FRAME_PREPARE) {
        if (client->frame_pending || request->packet_object_index!=UINT32_MAX ||
            request->tx_lease_id || request->rx_lease_id) return -EBUSY;
        unsigned peer=(unsigned)client->handoff_peer;
        if (peer>=CLIENTS || pmd_client!=(int)peer || dead(client->handoff_peer_pidfd) ||
            dead(client->handoff_peer_client_pidfd)) return -ESTALE;
        struct client *consumer=&clients[peer];
        if (consumer->kind!=ATTACHED || consumer->peer_only || !consumer->generation_admitted ||
            dead(consumer->pidfd) || consumer->pidfd!=client->handoff_peer_client_pidfd ||
            consumer->pid!=client->handoff_peer_pid || consumer->slot!=client->handoff_peer_slot ||
            consumer->generation!=client->handoff_peer_generation ||
            consumer->process!=client->handoff_peer_process ||
            slots[consumer->slot].epoch!=client->handoff_peer_epoch ||
            consumer->generation!=(client->generation^1U) ||
            atomic_load_explicit(&directory->pmd_owner,memory_order_acquire)!=pmd_key(consumer)) return -ESTALE;
        int source_pidfd=fcntl(client->pidfd,F_DUPFD_CLOEXEC,3);
        if (source_pidfd<0) return -errno;
        int consumer_pidfd=fcntl(consumer->pidfd,F_DUPFD_CLOEXEC,3);
        if (consumer_pidfd<0) { close(source_pidfd); return -errno; }
        if (dead(source_pidfd) || dead(consumer_pidfd)) {
            close(source_pidfd); close(consumer_pidfd); return -ESTALE;
        }
        struct ker_generation_identity source_identity=generation_identity(client);
        struct ker_generation_identity consumer_identity=generation_identity(consumer);
        uint32_t object_index=UINT32_MAX; uint64_t lease=0;
        int result=ker_generation_packet_prepare(generation_rings,&source_identity,&consumer_identity,
            request->packet_port,request->packet_queue,&object_index,&lease);
        if (result) { close(source_pidfd); close(consumer_pidfd); return result; }
        if (dead(source_pidfd) || dead(consumer_pidfd)) {
            if (ker_generation_packet_cancel(generation_rings,&source_identity,object_index,lease)) _Exit(125);
            close(source_pidfd); close(consumer_pidfd); return -ESTALE;
        }
        client->frame_pending=true; client->frame_object_index=object_index;
        client->frame_pool_tag=tag; client->frame_lease_id=lease; client->frame_capability=client->handoff_capability;
        client->frame_port=request->packet_port; client->frame_queue=request->packet_queue;
        client->frame_consumer_client=peer; client->frame_consumer_pidfd=consumer_pidfd;
        client->frame_producer_pidfd=source_pidfd; client->frame_producer_identity=source_identity;
        client->frame_consumer_identity=consumer_identity;
        reply->packet_object_index=object_index; reply->tx_lease_id=lease;
        return 0;
    }
    if (!client->frame_pending || request->packet_object_index!=client->frame_object_index ||
        request->packet_pool_tag!=client->frame_pool_tag || request->packet_port!=client->frame_port ||
        request->packet_queue!=client->frame_queue || request->tx_lease_id!=client->frame_lease_id ||
        request->rx_lease_id || request->capability!=client->frame_capability ||
        memcmp(&client->frame_producer_identity,&(struct ker_generation_identity){
            .session=request->session,.epoch=request->epoch,.slot=(uint32_t)request->slot,
            .generation=(uint32_t)request->generation,.process=(uint32_t)request->process,
            .pid=(uint32_t)client->pid},sizeof(client->frame_producer_identity))) return -ESTALE;
    struct ker_generation_identity source_identity=client->frame_producer_identity;
    if (request->command==KER_SESSION_FRAME_CANCEL) {
        int result=ker_generation_packet_cancel(generation_rings,&source_identity,
            client->frame_object_index,client->frame_lease_id);
        if (!result) frame_pending_clear(client,FRAME_CANCELLED);
        return result;
    }
    if (request->command!=KER_SESSION_FRAME_COMMIT) return -EOPNOTSUPP;
    if (!frame_consumer_matches(client)) {
        int cancel=ker_generation_packet_cancel(generation_rings,&source_identity,
            client->frame_object_index,client->frame_lease_id);
        if (cancel) _Exit(125);
        frame_pending_clear(client,FRAME_CANCELLED);
        return -ESTALE;
    }
    int result=ker_generation_packet_commit(generation_rings,&source_identity,
        client->frame_port,client->frame_queue,client->frame_object_index,client->frame_lease_id);
    if (!result) { frame_pending_clear(client,FRAME_COMMITTED); return 0; }
    /* Commit can fail after write_complete only while the journal is PREPARED
     * (most notably a full ring). Return that exact object exactly once before
     * making the failure visible; ambiguity terminates the resident. */
    int cancel=ker_generation_packet_cancel(generation_rings,&source_identity,
        client->frame_object_index,client->frame_lease_id);
    if (cancel) _Exit(125);
    frame_pending_clear(client,FRAME_CANCELLED);
    return result;
}

static int selected_peer_only(unsigned source_index, unsigned *peer_slot, uint64_t *peer_epoch,
    unsigned *peer_client)
{
    const struct client *source=&clients[source_index];
    uint64_t now=monotonic_ms(), newest=0;
    unsigned selected=0, selected_client=UINT_MAX;
    for (unsigned i=0;i<CLIENTS;i++) {
        const struct client *candidate=&clients[i];
        if (candidate->kind!=ATTACHED || !candidate->peer_only || candidate->slot==source->slot ||
            candidate->generation!=source->generation || candidate->process!=source->process ||
            dead(candidate->pidfd) || candidate->slot>=KER_SESSION_SLOTS ||
            slots[candidate->slot].epoch==0 || candidate->pid!=(pid_t)slots[candidate->slot].worker_pid[candidate->generation][candidate->process])
            continue;
        int master=slots[candidate->slot].master;
        if (master<0 || clients[master].kind!=MASTER || dead(clients[master].pidfd) ||
            !candidate->heartbeat_ms || now<candidate->heartbeat_ms ||
            now-candidate->heartbeat_ms>KER_SESSION_PEER_STALE_MS) continue;
        if (slots[candidate->slot].epoch>newest) {
            newest=slots[candidate->slot].epoch; selected=candidate->slot; selected_client=i;
        }
    }
    if (!selected) return 0;
    *peer_slot=selected; *peer_epoch=newest; *peer_client=selected_client; return 1;
}

static volatile sig_atomic_t stopping;
static void stop_signal(int value) { (void)value; stopping = 1; }
static int dead(int fd)
{
    struct pollfd p = {.fd = fd, .events = POLLIN};
    int result;
    do result = poll(&p, 1, 0); while (result < 0 && errno == EINTR);
    /* Unknown liveness is never death proof. */
    return result > 0 && (p.revents & POLLIN);
}
static unsigned ring_index(unsigned s, unsigned g, unsigned p, unsigned c)
{
    return (((s * KER_SESSION_GENERATIONS) + g) * KER_SESSION_PROCESSES + p) * KER_SESSION_CHANNELS + c;
}
static int ring_name(char *name, size_t size, unsigned s, unsigned g, unsigned p, unsigned c)
{
    static const char *const names[] = {"ctl", "rx", "tx", "reply"};
    int result = snprintf(name, size, "ker_s%u_g%u_p%u_%s", s, g, p, names[c]);
    return result < 0 || (size_t)result >= size ? -ENAMETOOLONG : 0;
}
/* One production boundary for every secondary's view of the resident
 * directory. Keep the ticket, EAL peer and shared header checks together so
 * a missing or incompatible mapping cannot reach any ring lookup/ATTACHED. */
static int session_directory_lookup_validate(const struct ker_session_message *ticket,
    uint32_t primary_pid, const struct ker_session_directory **out)
{
    const struct rte_memzone *shared = rte_memzone_lookup(KER_SESSION_ZONE);
    if (!out) return -EINVAL;
    *out = NULL;
    if (!shared) return -ENOENT;
    if (shared->len < sizeof(struct ker_session_directory)) return -EPROTO;
    const struct ker_session_directory *d = shared->addr;
    if (!d || atomic_load_explicit(&d->state, memory_order_acquire) != KER_SESSION_READY ||
        d->magic != KER_SESSION_MAGIC || d->version != KER_SESSION_VERSION ||
        d->size != sizeof(*d) || d->session != ticket->session ||
        d->primary_pid != primary_pid || d->slots != KER_SESSION_SLOTS ||
        d->generations != KER_SESSION_GENERATIONS || d->processes != KER_SESSION_PROCESSES ||
        d->channels != KER_SESSION_CHANNELS || d->capacity != KER_SESSION_CAPACITY ||
        ticket->slot == 0 || ticket->slot >= KER_SESSION_SLOTS ||
        ticket->generation >= KER_SESSION_GENERATIONS || ticket->process >= KER_SESSION_PROCESSES ||
        atomic_load_explicit(&d->epoch[ticket->slot], memory_order_acquire) != ticket->epoch)
        return -EPROTO;
    *out = d;
    return 0;
}

static int validate_shared_rings(void)
{
    unsigned count = 0;
    for (unsigned s = 0; s < KER_SESSION_SLOTS; s++)
        for (unsigned g = 0; g < KER_SESSION_GENERATIONS; g++)
            for (unsigned p = 0; p < KER_SESSION_PROCESSES; p++)
                for (unsigned c = 0; c < KER_SESSION_CHANNELS; c++) {
                    char name[RTE_RING_NAMESIZE];
                    if (ring_name(name, sizeof(name), s, g, p, c)) return -EINVAL;
                    struct rte_ring *ring = rte_ring_lookup(name);
                    if (!ring || rte_ring_get_capacity(ring) != KER_SESSION_CAPACITY ||
                        !rte_ring_is_prod_single(ring) || !rte_ring_is_cons_single(ring)) return -EUCLEAN;
                    count++;
                }
    return (int)count;
}
static int random_id(uint64_t *value)
{
    ssize_t result;
    do result = getrandom(value, sizeof(*value), 0); while (result < 0 && errno == EINTR);
    return result == sizeof(*value) && *value ? 0 : -EIO;
}
static void remember_object(struct rte_mempool *pool, void *context,
    void *object, unsigned index)
{
    (void)pool; (void)context;
    if (index < KER_SESSION_OBJECTS) message_objects[index] = object;
}
static bool known_object(struct rte_mbuf *packet)
{
    for (unsigned i = 0; i < KER_SESSION_OBJECTS; i++)
        if (message_objects[i] == packet && packet) return true;
    return false;
}
#ifdef KER_SESSION_TEST_HOOKS
struct generation_frame_drain_context {
    struct ker_generation_rings *rings;
    struct ker_generation_identity identity;
};
static int generation_frame_drain_control(char command, void *opaque)
{
    if(command!='G')return 0;
    struct generation_frame_drain_context *context=opaque;
    uint32_t tx_before=0,pool_before=0,tx_after=0,pool_after=0;
    if(ker_generation_test_tx_snapshot(context->rings,0,0,0,&tx_before,&pool_before)||tx_before!=1)
        return -EUCLEAN;
    struct rte_mbuf *packet=NULL;
    int dequeued=ker_generation_tx_dequeue_peer(context->rings,&context->identity,0,0,&packet);
    if(dequeued!=1||!packet||packet->nb_segs!=1||
        rte_mbuf_refcnt_read(packet)!=1||(packet->ol_flags&RTE_MBUF_F_EXTERNAL)||
        packet->pkt_len<14||packet->pkt_len>1518||packet->data_len!=packet->pkt_len)return -EUCLEAN;
    const uint8_t *bytes=rte_pktmbuf_mtod(packet,const uint8_t *);
    static const char expected[]="KER-A09-HANDOFF-UDP seq=2\n";
    const uint8_t app_mac[6]={0x02,0x4b,0x45,0x52,0x00,0x02};
    const uint8_t host_mac[6]={0x02,0x4b,0x45,0x52,0x00,0x01};
    const size_t payload_length=sizeof(expected)-1, frame_length=14+20+8+payload_length;
    uint16_t fragment=(uint16_t)((bytes[20]<<8)|bytes[21]);
    if(packet->pkt_len!=frame_length||memcmp(bytes,host_mac,6)||memcmp(bytes+6,app_mac,6)||
        bytes[12]!=0x08||bytes[13]!=0x00||bytes[14]!=0x45||bytes[23]!=17||
        (fragment&0x3fff)||bytes[26]!=198||bytes[27]!=18||bytes[28]!=0||bytes[29]!=2||
        bytes[30]!=198||bytes[31]!=18||bytes[32]!=0||bytes[33]!=1||
        bytes[34]!=0xaf||bytes[35]!=0xc8||bytes[36]!=0xaf||bytes[37]!=0xc9||
        memcmp(bytes+42,expected,payload_length))return -EPROTO;
    uint16_t ip_total=(uint16_t)((bytes[16]<<8)|bytes[17]);
    uint16_t udp_length=(uint16_t)((bytes[38]<<8)|bytes[39]);
    if(ip_total!=20+8+payload_length||udp_length!=8+payload_length)return -EPROTO;
    uint32_t object_index=UINT32_MAX;
    if(ker_generation_test_packet_object_index(context->rings,packet,&object_index))return -EUCLEAN;
    char frame_hex[1518*2+1];
    static const char hex[]="0123456789abcdef";
    for(unsigned i=0;i<packet->pkt_len;i++){frame_hex[i*2]=hex[bytes[i]>>4];frame_hex[i*2+1]=hex[bytes[i]&15];}
    frame_hex[packet->pkt_len*2]='\0';
    uintptr_t pointer=(uintptr_t)packet;
    uint64_t tag=ker_generation_packet_pool_tag(context->rings);
    uint16_t length=packet->pkt_len;
    if(!tag||ker_generation_packet_release(context->rings,&context->identity,packet)||
        ker_generation_test_tx_snapshot(context->rings,0,0,0,&tx_after,&pool_after)||
        tx_after!=0||pool_after+1!=pool_before)return -EUCLEAN;
    printf("KER_SESSION_FRAME_DRAINED {\"sequence\":2,\"object_index\":%u,\"pool_tag\":%llu,\"packet_pointer\":\"%p\",\"length\":%u,\"tx_before\":%u,\"tx_after\":%u,\"pool_in_use_before\":%u,\"pool_in_use_after\":%u,\"frame_hex\":\"%s\"}\n",
        object_index,(unsigned long long)tag,(void *)pointer,(unsigned)length,tx_before,tx_after,
        pool_before,pool_after,frame_hex);fflush(stdout);
    return 1;
}
#endif
/* The primary never services data while a borrower is alive. After exact
 * pidfd death, it may drain only the sole privately journaled ring-PMD lease. */
static void reclaim_pmd(unsigned index)
{
    if (pmd_client != (int)index) return;
    if (!dead(clients[index].pidfd) || !pmd_packet || !known_object(pmd_packet) ||
        pmd_packet->pool != message_pool || pmd_packet->nb_segs != 1 ||
        rte_mbuf_refcnt_read(pmd_packet) != 1 || (pmd_packet->ol_flags & RTE_MBUF_F_EXTERNAL) ||
        atomic_load_explicit(&directory->pmd_owner, memory_order_acquire) != pmd_key(&clients[index]) ||
        atomic_load_explicit(&directory->pmd_lease, memory_order_acquire) != (uintptr_t)pmd_packet) _Exit(125);
    if (ring_pmd == 2 && session_exception_keeper.pending &&
        ker_worker_exception_session_reclaim(&session_exception_keeper, pmd_rx_packet) < 0) _Exit(125);
    uint32_t exception_phase = ring_pmd == 2 ? atomic_load_explicit(&directory->pmd_exception_phase, memory_order_acquire) : 0;
    if (exception_phase > 8 || exception_phase == 2 || exception_phase == 3 || exception_phase == 6 || exception_phase == 8)
        _Exit(125); /* A destructive TAP or external-wire syscall may have transferred the frame. */
    if (ring_pmd == 2 && (exception_phase == 4 || exception_phase == 5 || exception_phase == 7)) {
        uint64_t previous = atomic_fetch_add_explicit(&directory->pmd_exception_discarded, 1, memory_order_acq_rel);
        if (previous == UINT64_MAX) _Exit(125);
        fprintf(stdout, "KER_SESSION_EXCEPTION_RECLAIM {\"phase\":%u,\"discarded\":1,\"total\":%llu}\n",
            exception_phase, (unsigned long long)(previous + 1)); fflush(stdout);
    }
    struct rte_mbuf *packet;
    unsigned seen = 0;
    if (ring_pmd == 2 && (!pmd_rx_packet || pmd_rx_packet == pmd_packet || !known_object(pmd_rx_packet) ||
        pmd_rx_packet->pool != message_pool || pmd_rx_packet->nb_segs != 1 ||
        rte_mbuf_refcnt_read(pmd_rx_packet) != 1 || (pmd_rx_packet->ol_flags & RTE_MBUF_F_EXTERNAL) ||
        atomic_load_explicit(&directory->pmd_rx_lease, memory_order_acquire) != (uintptr_t)pmd_rx_packet)) _Exit(125);
    while (rte_eth_rx_burst(pmd_port, 0, &packet, 1))
        if (packet != (ring_pmd == 2 ? pmd_rx_packet : pmd_packet) || ++seen > 1) _Exit(125);
    if (ring_pmd == 2) {
        bool saw_tx = false, saw_rx_tx = false;
        while (!rte_ring_dequeue(packet_tx, (void **)&packet)) {
            if (packet == pmd_packet && !saw_tx) saw_tx = true;
            else if (packet == pmd_rx_packet && !saw_rx_tx) saw_rx_tx = true;
            else _Exit(125);
        }
        atomic_store_explicit(&directory->pmd_exception_phase, 0, memory_order_release);
        atomic_store_explicit(&directory->pmd_rx_lease, 0, memory_order_release);
        rte_pktmbuf_reset(pmd_rx_packet); rte_pktmbuf_free(pmd_rx_packet); pmd_rx_packet = NULL;
    }
    atomic_store_explicit(&directory->pmd_lease, 0, memory_order_release);
    rte_pktmbuf_reset(pmd_packet);
    rte_pktmbuf_free(pmd_packet);
    pmd_packet = NULL; pmd_client = -1;
    atomic_store_explicit(&directory->pmd_owner, 0, memory_order_release);
    atomic_store_explicit(&directory->pmd_tx_lease_id, 0, memory_order_release);
    atomic_store_explicit(&directory->pmd_rx_lease_id, 0, memory_order_release);
}
static void reclaim_control(unsigned index)
{
    reclaim_pmd(index);
    struct client *client = &clients[index];
    if (client->generation_admitted) {
        struct ker_generation_identity identity=generation_identity(client);
        if (!generation_rings || ker_generation_reap_dead(generation_rings,&identity)) {
            fprintf(stderr,"ker session: generation packet journal lacks exact-death recovery proof\n");_Exit(125);
        }
        client->generation_admitted=false;
        /* Exact producer death is the only non-commit path that clears a
         * resident frame lease after the generation journal has recovered it. */
        if (client->frame_pending) frame_pending_clear(client,FRAME_DEAD_REAPED);
    }
    struct rte_mbuf *owned = client->leased_packet;
    /* The private resident journal predates RESERVE's acknowledgement. Queue
     * emptiness is not evidence that an object was never borrowed. */
    if (!owned || !known_object(owned) || !dead(client->pidfd) ||
        owned->pool != message_pool || owned->nb_segs != 1 ||
        rte_mbuf_refcnt_read(owned) != 1 || (owned->ol_flags & RTE_MBUF_F_EXTERNAL)) {
        fprintf(stderr, "ker session: control lease lacks death/ownership proof\n"); _Exit(125);
    }
    unsigned seen = 0;
    for (unsigned channel = 0; channel < KER_SESSION_CHANNELS; channel += 3) {
        struct rte_ring *ring = rings[ring_index(client->slot, client->generation, client->process, channel)];
        struct rte_mbuf *packet;
        while (!rte_ring_dequeue(ring, (void **)&packet)) {
            if (packet != owned || ++seen > 1) {
                fprintf(stderr, "ker session: foreign or duplicated leased control object\n"); _Exit(125);
            }
        }
    }
    _Atomic uintptr_t *lease = &directory->lease[client->slot][client->generation][client->process];
    if (atomic_load_explicit(lease, memory_order_acquire) != (uintptr_t)owned) {
        fprintf(stderr, "ker session: shared control lease changed\n"); _Exit(125);
    }
    atomic_store_explicit(lease, 0, memory_order_release);
    /* Recover allocation-before-enqueue and reply-dequeue-before-reuse too.
     * The borrower never returns leased objects to the original mempool. */
    rte_pktmbuf_reset(owned);
    rte_pktmbuf_free(owned);
    client->leased_packet = NULL;
}
#ifdef KER_SESSION_TEST_HOOKS
static int verify_tc3_probe_barrier(void)
{
    struct client *pair[2] = {0};
    unsigned count = 0;
    for (unsigned i = 0; i < CLIENTS; i++) {
        struct client *client = &clients[i];
        if (client->kind != ATTACHED || client->generation != 0 || client->process != 0 || dead(client->pidfd)) continue;
        if (count == 2) return -E2BIG;
        pair[count++] = client;
    }
    if (count != 2 || pair[0]->slot == pair[1]->slot || slots[pair[0]->slot].epoch == slots[pair[1]->slot].epoch) return -EAGAIN;
    struct rte_ring *input[2] = {0};
    struct rte_mbuf *packet[2] = {0};
    for (unsigned n = 0; n < 2; n++) {
        input[n] = rings[ring_index(pair[n]->slot, 0, 0, 0)];
        if (!input[n] || rte_ring_count(input[n]) != 1 ||
            rte_ring_get_capacity(input[n]) != KER_SESSION_CAPACITY) return -EAGAIN;
        if (!rte_ring_is_prod_single(input[n]) || !rte_ring_is_cons_single(input[n])) return -EUCLEAN;
        unsigned started = rte_ring_dequeue_bulk_start(input[n], (void **)&packet[n], 1, NULL);
        if (started != 1) return -EAGAIN;
        /* The preview API above must not remove a token. Cancel the dequeue reservation. */
        rte_ring_dequeue_finish(input[n], 0);
        if (packet[n] != pair[n]->leased_packet || !known_object(packet[n]) ||
            packet[n]->pool != message_pool || packet[n]->nb_segs != 1 ||
            packet[n]->data_len != sizeof(struct ker_session_probe) || packet[n]->pkt_len != packet[n]->data_len) return -EUCLEAN;
        const struct ker_session_probe *probe = rte_pktmbuf_mtod(packet[n], const struct ker_session_probe *);
        struct ker_session_message expected = {.session=directory->session, .epoch=slots[pair[n]->slot].epoch,
            .slot=pair[n]->slot, .generation=0, .process=0};
        if (ker_session_probe_check(probe, &expected, pair[n]->probe_sequence)) return -EPROTO;
    }
    if (input[0] == input[1]) return -EUCLEAN;
    if (atomic_load_explicit(&directory->pmd_owner, memory_order_acquire) == 0 ||
        atomic_load_explicit(&directory->exception_ifindex, memory_order_acquire) == 0 || pmd_client < 0 ||
        (clients[pmd_client].generation != 0 || clients[pmd_client].process != 0 ||
         (clients[pmd_client].slot != pair[0]->slot && clients[pmd_client].slot != pair[1]->slot)) ||
        atomic_load_explicit(&directory->pmd_owner, memory_order_acquire) != pmd_key(&clients[pmd_client])) return -EUCLEAN;
    printf("KER_SESSION_TC3_TOKENS_PENDING {\"generation\":0,\"process\":0,\"count\":2,\"slots\":[%u,%u],\"epochs\":[%llu,%llu],\"rings_distinct\":true,\"owner_epoch\":%llu,\"exception_ifindex\":%u}\n",
        pair[0]->slot, pair[1]->slot, (unsigned long long)slots[pair[0]->slot].epoch, (unsigned long long)slots[pair[1]->slot].epoch,
        (unsigned long long)slots[clients[pmd_client].slot].epoch,
        atomic_load_explicit(&directory->exception_ifindex, memory_order_acquire)); fflush(stdout);
    return 0;
}
#endif
static void serve_probes(void)
{
#ifdef KER_SESSION_TEST_HOOKS
    if (tc3_probe_gate) return;
#endif
    for (unsigned i = 0; i < CLIENTS; i++) {
        struct client *client = &clients[i];
        if (client->kind != ATTACHED || dead(client->pidfd)) continue;
        struct rte_ring *input = rings[ring_index(client->slot, client->generation, client->process, 0)];
        struct rte_ring *output = rings[ring_index(client->slot, client->generation, client->process, 3)];
        /* Keep ownership on the input when the reply channel is full. */
        for (unsigned budget = 0; budget < KER_SESSION_CAPACITY && rte_ring_free_count(output); budget++) {
            struct rte_mbuf *packet;
            if (rte_ring_dequeue(input, (void **)&packet)) break;
            if (packet != client->leased_packet || !known_object(packet) || packet->nb_segs != 1 ||
                packet->data_len != sizeof(struct ker_session_probe) || packet->pkt_len != packet->data_len) {
                fprintf(stderr, "ker session: invalid control envelope\n"); _Exit(125);
            }
            struct ker_session_probe *probe = rte_pktmbuf_mtod(packet, struct ker_session_probe *);
            struct ker_session_message *m = &probe->identity;
            struct ker_session_message expected = {.session = directory->session,
                .epoch = slots[client->slot].epoch, .slot = client->slot,
                .generation = client->generation, .process = client->process};
            m->status = ker_session_probe_check(probe, &expected, client->probe_sequence);
            if (!m->status) client->probe_sequence = m->sequence;
            probe->responder = (uint64_t)getpid();
            if (rte_ring_enqueue(output, packet)) {
                /* One producer, with capacity checked above: never discard an
                 * owned reply or fabricate success if the invariant fails. */
                fprintf(stderr, "ker session: reply ownership invariant failed\n"); _Exit(125);
            }
        }
    }
}
#ifdef KER_SESSION_TEST_HOOKS
static struct rte_mbuf *generation_test_packet(struct rte_mempool *pool,uint8_t value)
{
    struct rte_mbuf *packet=rte_pktmbuf_alloc(pool);
    if(!packet)return NULL;
    uint8_t *data=(uint8_t *)rte_pktmbuf_append(packet,1);
    if(!data){rte_pktmbuf_free(packet);return NULL;}
    *data=value;return packet;
}
static struct rte_mbuf *generation_test_empty(struct rte_mempool *pool)
{ return rte_pktmbuf_alloc(pool); }
static struct rte_ring *generation_test_ring(unsigned direction,unsigned q,unsigned g)
{
    char name[RTE_RING_NAMESIZE];
    int n=snprintf(name,sizeof(name),"drain_%s_p0_q%u_g%u",direction?"tx":"rx",q,g);
    return n<0||(size_t)n>=sizeof(name)?NULL:rte_ring_lookup(name);
}
static int generation_detach_observe_packet(struct rte_ring *ring, struct rte_mbuf **packet)
{
    void *objects[1]={0};
    unsigned count=rte_ring_dequeue_bulk_start(ring,objects,1,NULL);
    if(count!=1)return -EUCLEAN;
    rte_ring_dequeue_finish(ring,0);
    if(!objects[0])return -EUCLEAN;
    *packet=objects[0];
    return 0;
}
static int generation_detach_pre_matrix(struct rte_ring **before, struct rte_mbuf **packets,
    unsigned generation, bool preserve_packets)
{
    for(unsigned direction=0;direction<2;direction++)for(unsigned q=0;q<2;q++)for(unsigned g=0;g<2;g++){
        unsigned index=(direction*2+q)*2+g;
        struct rte_ring *ring=generation_test_ring(direction,q,g);
        if(!ring||(before&&before[index]&&ring!=before[index]))return -EUCLEAN;
        if(before&&!before[index])before[index]=ring;
        if(rte_ring_count(ring)!=1)return -EUCLEAN;
        bool consumer_owns_ring=direction?(g==(generation^1U)):(g==generation);
        if(preserve_packets&&consumer_owns_ring){
            struct rte_mbuf *packet=NULL;
            if(generation_detach_observe_packet(ring,&packet))return -EUCLEAN;
            if(packets&&packets[index]&&packets[index]!=packet)return -EUCLEAN;
            if(packets&&!packets[index])packets[index]=packet;
        }
    }
    return 0;
}
static int generation_detach_post_matrix(unsigned tx_count, bool foreign, bool nonowner_detach,
    bool empty_cleanup, unsigned generation, struct rte_ring **before, struct rte_mbuf **packets)
{
    for(unsigned direction=0;direction<2;direction++)for(unsigned q=0;q<2;q++)for(unsigned g=0;g<2;g++){
        unsigned index=(direction*2+q)*2+g;
        struct rte_ring *ring=generation_test_ring(direction,q,g);
        if(!ring||(before&&before[index]&&ring!=before[index])){
            fprintf(stderr,"generation detach matrix ring changed direction=%u q=%u g=%u\n",direction,q,g);
            return -EUCLEAN;
        }
        unsigned expected=1;
        if(!empty_cleanup&&!direction&&q==0&&g==0)expected=0;
        if(!empty_cleanup&&direction&&q==1&&g==0&&tx_count==1&&!foreign&&!nonowner_detach)expected=0;
        unsigned count=rte_ring_count(ring);
        if(count!=expected){
            fprintf(stderr,"generation detach matrix count direction=%u q=%u g=%u expected=%u got=%u\n",
                direction,q,g,expected,count);
            return -EUCLEAN;
        }
        bool consumer_owns_ring=direction?(g==(generation^1U)):(g==generation);
        if(empty_cleanup&&consumer_owns_ring){
            struct rte_mbuf *packet=NULL;
            if(!packets||!packets[index]){
                fprintf(stderr,"generation detach matrix missing saved packet direction=%u q=%u g=%u generation=%u\n",
                    direction,q,g,generation);
                return -EUCLEAN;
            }
            int observe=generation_detach_observe_packet(ring,&packet);
            if(observe){
                fprintf(stderr,"generation detach matrix packet peek failed direction=%u q=%u g=%u generation=%u status=%d\n",
                    direction,q,g,generation,observe);
                return -EUCLEAN;
            }
            if(packet!=packets[index]){
                fprintf(stderr,"generation detach matrix packet changed direction=%u q=%u g=%u generation=%u expected=%p got=%p\n",
                    direction,q,g,generation,(void *)packets[index],(void *)packet);
                return -EUCLEAN;
            }
        }
    }
    return 0;
}
static int generation_detach_seed(struct ker_generation_rings *rings,
    const struct ker_generation_identity *identity,struct rte_mempool *pool)
{
    struct rte_mbuf *rejected=generation_test_empty(pool);
    if(!rejected)return -ENOMEM;
    if(ker_generation_rx_enqueue(rings,identity,0,0,identity->generation,rejected)!=-EINVAL ||
        rte_mbuf_refcnt_read(rejected)!=1){rte_pktmbuf_free(rejected);return -EUCLEAN;}
    rte_pktmbuf_free(rejected);
    for(unsigned q=0;q<2;q++){
        struct rte_mbuf *packet=generation_test_empty(pool);if(!packet)return -ENOMEM;
        if(ker_generation_rx_enqueue(rings,identity,0,q,identity->generation^1U,packet)){
            rte_pktmbuf_free(packet);return -EUCLEAN;
        }
        packet=generation_test_empty(pool);if(!packet)return -ENOMEM;
        if(ker_generation_tx_enqueue(rings,identity,0,q,packet)){rte_pktmbuf_free(packet);return -EUCLEAN;}
    }
    return 0;
}
static int generation_detach_release_retained(struct ker_generation_rings *rings,
    const struct ker_generation_identity *identity,bool foreign,bool nonowner_detach,bool empty_cleanup)
{
    for(unsigned q=0;q<2;q++){
        struct rte_mbuf *packet=NULL;
        int expected_rx=empty_cleanup?1:((identity->generation==0&&q==0)?0:1);
        int got=ker_generation_rx_dequeue(rings,identity,0,q,&packet);
        if(got!=expected_rx||(!got&&packet)||(got==1&&(!packet||ker_generation_packet_release(rings,identity,packet))))return -EUCLEAN;
        packet=NULL;
        int expected_tx=1;
        if(!empty_cleanup&&identity->generation==1&&q==1&&!foreign&&!nonowner_detach)expected_tx=0;
        got=ker_generation_tx_dequeue_peer(rings,identity,0,q,&packet);
        if(got!=expected_tx||(!got&&packet)||(got==1&&(!packet||ker_generation_packet_release(rings,identity,packet))))return -EUCLEAN;
    }
    return 0;
}
static int generation_test_step(struct ker_generation_rings *rings,
    const struct ker_generation_identity *identity,struct rte_mempool *pool,unsigned step,
    bool detach_test,bool foreign,bool nonowner_detach,bool empty_cleanup,bool tx_full_test)
{
    struct rte_mbuf *packet=NULL;
    if(tx_full_test&&step==0&&identity->generation==0){
        struct rte_ring *ring=generation_test_ring(1,0,0);
        if(!ring)return -EUCLEAN;
        unsigned capacity=rte_ring_get_capacity(ring);
        for(unsigned i=0;i<capacity;i++){
            packet=generation_test_packet(pool,(uint8_t)i);if(!packet)return -ENOMEM;
            if(ker_generation_tx_enqueue(rings,identity,0,0,packet)){rte_pktmbuf_free(packet);return -EUCLEAN;}
        }
        packet=generation_test_packet(pool,0xee);if(!packet)return -ENOMEM;
        int rejected=ker_generation_tx_enqueue(rings,identity,0,0,packet);
        int intact=rte_mbuf_refcnt_read(packet)==1&&rte_pktmbuf_mtod(packet,uint8_t*)[0]==0xee;
        rte_pktmbuf_free(packet);
        return rejected==-ENOBUFS&&intact&&rte_ring_count(ring)==capacity?0:-EUCLEAN;
    }
    if(tx_full_test&&step==0&&identity->generation==1){
        unsigned before=rte_mempool_avail_count(pool);
        struct rte_ring *ring=generation_test_ring(1,0,0);
        if(!ring||rte_ring_count(ring)!=rte_ring_get_capacity(ring))return -EUCLEAN;
        unsigned capacity=rte_ring_get_capacity(ring);
        for(unsigned i=0;i<capacity;i++){
            packet=NULL;
            if(ker_generation_tx_dequeue_peer(rings,identity,0,0,&packet)!=1||!packet||
                rte_pktmbuf_mtod(packet,uint8_t*)[0]!=(uint8_t)i||
                ker_generation_packet_release(rings,identity,packet))return -EUCLEAN;
        }
        return rte_ring_count(ring)==0&&
            rte_mempool_avail_count(pool)==before+capacity?0:-EUCLEAN;
    }
    if(detach_test&&step==3){
        for(unsigned index=0;index<8;index++)generation_test_original_packet[index]=NULL;
        if(generation_detach_seed(rings,identity,pool))return -EUCLEAN;
        for(unsigned direction=0;direction<2;direction++)for(unsigned q=0;q<2;q++)for(unsigned g=0;g<2;g++){
            unsigned index=(direction*2+q)*2+g;
            struct rte_ring *ring=generation_test_ring(direction,q,g);
            if(!ring||(generation_test_original[index]&&generation_test_original[index]!=ring))return -EUCLEAN;
            generation_test_original[index]=ring;
        }
        return 0;
    }
    if(detach_test&&step==4){
        return generation_detach_pre_matrix(generation_test_original,generation_test_original_packet,
            identity->generation,empty_cleanup);
    }
    if(detach_test&&step==5){
        return generation_detach_release_retained(rings,identity,foreign,nonowner_detach,empty_cleanup);
    }
    if(identity->generation==0&&step==0){
        packet=generation_test_packet(pool,0x42);if(!packet)return -ENOMEM;
        if(ker_generation_rx_enqueue(rings,identity,0,0,0,packet)!=-EINVAL ||
            ker_generation_rx_enqueue(rings,identity,0,2,1,packet)!=-EINVAL ||
            rte_mbuf_refcnt_read(packet)!=1){rte_pktmbuf_free(packet);return -EUCLEAN;}
        if(ker_generation_rx_enqueue(rings,identity,0,0,1,packet)){rte_pktmbuf_free(packet);return -EUCLEAN;}
        return 0;
    }
    if(identity->generation==1&&step==0){
        if(ker_generation_rx_dequeue(rings,identity,0,0,&packet)!=1||!packet||
            rte_pktmbuf_mtod(packet,uint8_t*)[0]!=0x42)return -EUCLEAN;
        if(ker_generation_packet_release(rings,identity,packet))return -EUCLEAN;
        if(ker_generation_rx_dequeue(rings,identity,0,1,&packet)!=0||packet)return -EUCLEAN;
        if(ker_generation_tx_dequeue_peer(rings,identity,0,0,&packet)!=0||packet)return -EUCLEAN;
        if(ker_generation_tx_dequeue_peer(rings,identity,0,1,&packet)!=0||packet)return -EUCLEAN;
        return 0;
    }
    if(identity->generation==0&&step==1){
        packet=generation_test_packet(pool,0x43);if(!packet)return -ENOMEM;
        if(ker_generation_tx_enqueue(rings,identity,0,0,packet)){rte_pktmbuf_free(packet);return -EUCLEAN;}
        return 0;
    }
    if(identity->generation==1&&step==1){
        if(ker_generation_tx_dequeue_peer(rings,identity,0,0,&packet)!=1||!packet||
            rte_pktmbuf_mtod(packet,uint8_t*)[0]!=0x43)return -EUCLEAN;
        if(ker_generation_packet_release(rings,identity,packet))return -EUCLEAN;
        if(ker_generation_tx_dequeue_peer(rings,identity,0,1,&packet)!=0||packet)return -EUCLEAN;
        return 0;
    }
    if(identity->generation==0&&step==2){
        uint64_t before=ker_generation_rx_full_count(rings,0,0,1);
        for(unsigned i=0;i<KER_GENERATION_RING_CAPACITY;i++){
            packet=generation_test_packet(pool,(uint8_t)i);if(!packet)return -ENOMEM;
            if(ker_generation_rx_enqueue(rings,identity,0,0,1,packet)){rte_pktmbuf_free(packet);return -EUCLEAN;}
        }
        packet=generation_test_packet(pool,0xee);if(!packet)return -ENOMEM;
        int rejected=ker_generation_rx_enqueue(rings,identity,0,0,1,packet);
        int intact=rte_mbuf_refcnt_read(packet)==1;rte_pktmbuf_free(packet);
        return rejected==-ENOBUFS&&intact&&ker_generation_rx_full_count(rings,0,0,1)==before+1?0:-EUCLEAN;
    }
    if(identity->generation==1&&step==2){
        unsigned before=rte_mempool_avail_count(pool);
        for(unsigned i=0;i<KER_GENERATION_RING_CAPACITY;i++){
            packet=NULL;
            if(ker_generation_rx_dequeue(rings,identity,0,0,&packet)!=1||!packet||
                rte_pktmbuf_mtod(packet,uint8_t*)[0]!=(uint8_t)i||
                ker_generation_packet_release(rings,identity,packet))return -EUCLEAN;
        }
        return rte_mempool_avail_count(pool)==before+KER_GENERATION_RING_CAPACITY?0:-EUCLEAN;
    }
    return -EINVAL;
}
#endif
static void drop_client(unsigned i)
{
    if (clients[i].frame_pending) _Exit(125); /* Pending ownership is cleared only by commit/cancel/exact reap. */
    if (clients[i].handoff_state!=HANDOFF_NONE && clients[i].handoff_peer_pidfd>=0)
        close(clients[i].handoff_peer_pidfd);
    for(unsigned s=1;s<KER_SESSION_SLOTS;s++)
        if(slots[s].peer_child==(int)i){
            slots[s].peer_capability=0;slots[s].peer_epoch=0;slots[s].peer_master=-1;
            slots[s].peer_child=-1;slots[s].peer_child_pidfd=-1;slots[s].peer_child_pid=0;
        }
    if (clients[i].fd >= 0) close(clients[i].fd);
    if (clients[i].pidfd >= 0) close(clients[i].pidfd);
    clients[i] = (struct client){.fd = -1, .pidfd = -1,
        .frame_consumer_pidfd = -1, .frame_producer_pidfd = -1,
        .frame_consumer_client = UINT_MAX};
}
/* Only registered EAL borrowers and masters need lifetime tracking after EOF. */
static void disconnect_client(unsigned i)
{
    if (clients[i].kind == UNBOUND || clients[i].kind == RELEASED) drop_client(i);
    else if (clients[i].fd >= 0) { close(clients[i].fd); clients[i].fd = -1; }
}
static unsigned users(unsigned slot)
{
    unsigned result = 0;
    for (unsigned i = 0; i < CLIENTS; i++)
        if ((clients[i].kind == RESERVED || clients[i].kind == ATTACHED) && clients[i].slot == slot)
            result++;
    return result;
}
static int release_slot(unsigned s)
{
    if (users(s)) return -EBUSY;
    uint64_t now = monotonic_ms();
    for (unsigned g = 0; g < KER_SESSION_GENERATIONS; g++)
        for (unsigned p = 0; p < KER_SESSION_PROCESSES; p++) {
            uint64_t stamp = slots[s].worker_heartbeat_ms[g][p];
            if (slots[s].worker_drain_mode[g][p] && stamp && now >= stamp &&
                now - stamp <= KER_SESSION_PEER_STALE_MS) return -EBUSY;
        }
    for (unsigned g = 0; g < KER_SESSION_GENERATIONS; g++)
        for (unsigned p = 0; p < KER_SESSION_PROCESSES; p++) {
            if (atomic_load_explicit(&directory->lease[s][g][p], memory_order_acquire)) return -EBUSY;
            for (unsigned c = 0; c < KER_SESSION_CHANNELS; c++)
                if (!rte_ring_empty(rings[ring_index(s, g, p, c)])) return -EBUSY;
        }
    atomic_store_explicit(&directory->epoch[s], 0, memory_order_release);
        slots[s] = (struct slot){.master = -1, .peer_master=-1, .peer_child=-1, .peer_child_pidfd=-1};
    return 0;
}
static void reap_clients(void)
{
    /* EOF is not proof that an EAL borrower has stopped. Retain its pidfd. */
    for (unsigned i = 0; i < CLIENTS; i++)
        if (clients[i].kind != UNUSED && dead(clients[i].pidfd)) {
            if ((int)i == handoff_client && handoff_state != HANDOFF_NONE) _Exit(125);
            if ((int)i == handoff_peer && handoff_state != HANDOFF_NONE) _Exit(125);
            if (clients[i].kind == MASTER) {
                if (!release_slot(clients[i].slot)) drop_client(i);
            } else {
                if (clients[i].kind == RESERVED || clients[i].kind == ATTACHED) {
                    if (clients[i].kind == ATTACHED && !clients[i].drain_mode) {
                        slots[clients[i].slot].worker_pid[clients[i].generation][clients[i].process] = 0;
                        slots[clients[i].slot].worker_heartbeat_ms[clients[i].generation][clients[i].process] = 0;
                    }
                    reclaim_control(i);
                }
                drop_client(i);
            }
        }
    for (unsigned s = 1; s < KER_SESSION_SLOTS; s++) {
        int m = slots[s].master;
        if (m >= 0 && dead(clients[m].pidfd) && !release_slot(s)) drop_client((unsigned)m);
    }
}
static int direct_child(pid_t pid, pid_t parent)
{
    char path[64], buffer[4096], state;
    int ppid = -1;
    snprintf(path, sizeof(path), "/proc/%ld/stat", (long)pid);
    FILE *file = fopen(path, "r");
    if (!file) return 0;
    char *result = fgets(buffer, sizeof(buffer), file);
    fclose(file);
    if (!result) return 0;
    char *end = strrchr(buffer, ')');
    return end && sscanf(end + 1, " %c %d", &state, &ppid) == 2 && ppid == parent;
}
#ifdef KER_SESSION_TEST_HOOKS
static void directory_test_save_header(void)
{
    directory_test_original = (struct directory_test_header){
        .magic=directory->magic, .version=directory->version, .size=directory->size,
        .session=directory->session, .slots=directory->slots,
        .generations=directory->generations, .processes=directory->processes,
        .channels=directory->channels, .capacity=directory->capacity};
}
static void directory_test_restore_header(void)
{
    directory->magic=directory_test_original.magic;
    directory->version=directory_test_original.version;
    directory->size=directory_test_original.size;
    directory->session=directory_test_original.session;
    directory->slots=directory_test_original.slots;
    directory->generations=directory_test_original.generations;
    directory->processes=directory_test_original.processes;
    directory->channels=directory_test_original.channels;
    directory->capacity=directory_test_original.capacity;
}
static void directory_test_snapshot(void)
{
    printf("KER_SESSION_TEST_SNAPSHOT {\"header\":[%llu,%llu,%llu,%llu,%u,%u,%u,%u,%u,%u],\"next_epoch\":%llu,\"pool\":[%u,%u],\"pmd\":[%llu,%u,%llu,%llu,%u,%llu],\"pmd_identity\":[%llu,%llu,%u,%u],\"slots\":[",
        (unsigned long long)directory->magic,(unsigned long long)directory->version,
        (unsigned long long)directory->size,(unsigned long long)directory->session,
        directory->primary_pid,directory->slots,directory->generations,directory->processes,
        directory->channels,directory->capacity,
        (unsigned long long)next_epoch,
        message_pool ? rte_mempool_avail_count(message_pool) : 0,
        message_pool ? rte_mempool_in_use_count(message_pool) : 0,
        (unsigned long long)atomic_load_explicit(&directory->pmd_owner,memory_order_acquire),
        atomic_load_explicit(&directory->exception_ifindex,memory_order_acquire),
        (unsigned long long)atomic_load_explicit(&directory->pmd_lease,memory_order_acquire),
        (unsigned long long)atomic_load_explicit(&directory->pmd_rx_lease,memory_order_acquire),
        atomic_load_explicit(&directory->pmd_exception_phase,memory_order_acquire),
        (unsigned long long)atomic_load_explicit(&directory->pmd_exception_discarded,memory_order_acquire),
        pmd_client >= 0 ? (unsigned long long)slots[clients[pmd_client].slot].epoch : 0,
        pmd_client >= 0 ? (unsigned long long)clients[pmd_client].slot : 0,
        pmd_client >= 0 ? clients[pmd_client].generation : 0,
        pmd_client >= 0 ? clients[pmd_client].process : 0);
    for (unsigned slot=0;slot<KER_SESSION_SLOTS;slot++) {
        if(slot) putchar(',');
        printf("[%llu,%llu,%u,%u]",(unsigned long long)atomic_load_explicit(&directory->epoch[slot],memory_order_acquire),
            (unsigned long long)slots[slot].epoch,slots[slot].master>=0?(unsigned)clients[slots[slot].master].pid:0,
            users(slot));
    }
    fputs("],\"leases\":[",stdout);
    bool first=true;
    for(unsigned slot=0;slot<KER_SESSION_SLOTS;slot++)for(unsigned generation=0;generation<KER_SESSION_GENERATIONS;generation++)
        for(unsigned process=0;process<KER_SESSION_PROCESSES;process++) {
            if (!first) putchar(',');
            first = false;
            printf("%llu",(unsigned long long)atomic_load_explicit(&directory->lease[slot][generation][process],memory_order_acquire));
        }
    fputs("],\"peers\":[",stdout); first=true;
    for(unsigned slot=0;slot<KER_SESSION_SLOTS;slot++)for(unsigned generation=0;generation<KER_SESSION_GENERATIONS;generation++)
        for(unsigned process=0;process<KER_SESSION_PROCESSES;process++) {
            if (!first) putchar(',');
            first = false;
            printf("[%llu,%llu,%llu,%llu]",
                (unsigned long long)atomic_load_explicit(&directory->peer_version[slot][generation][process],memory_order_acquire),
                (unsigned long long)atomic_load_explicit(&directory->peer_epoch[slot][generation][process],memory_order_acquire),
                (unsigned long long)atomic_load_explicit(&directory->peer_generation[slot][generation][process],memory_order_acquire),
                (unsigned long long)atomic_load_explicit(&directory->peer_draining[slot][generation][process],memory_order_acquire));
        }
    fputs("],\"clients\":[",stdout); first=true;
    for(unsigned i=0;i<CLIENTS;i++)if(clients[i].kind!=UNUSED) {
        if (!first) putchar(',');
        first = false;
        printf("[%u,%ld,%u,%u,%u,%llu]",(unsigned)clients[i].kind,(long)clients[i].pid,
            clients[i].slot,clients[i].generation,clients[i].process,(unsigned long long)clients[i].sequence);
    }
    fputs("]}\n",stdout);fflush(stdout);
}
static int directory_test_corrupt_header(char field)
{
    switch (field) {
    case 'm': directory->magic ^= UINT64_C(1); break;
    case 'v': directory->version ^= UINT64_C(1); break;
    case 'z': directory->size ^= UINT64_C(8); break;
    case 's': directory->session ^= UINT64_C(0x100); break;
    case 'g': directory->generations++; break;
    case 'c': directory->capacity++; break;
    default: return -EINVAL;
    }
    return 0;
}
#endif
static int handle(unsigned i, const struct ker_session_message *request,
    struct ker_session_message *reply)
{
    struct client *client = &clients[i];
    *reply = *request;
    if (!frame_command(request->command)) reply->session = directory->session;
    if (request->magic != KER_SESSION_MAGIC || request->version != KER_SESSION_VERSION ||
        (request->status && request->command != KER_SESSION_PEER_STATUS) ||
        request->status < 0 || request->status > 1 || !request->sequence) return -EPROTO;
    if ((request->tx_lease_id || request->rx_lease_id) &&
        request->command != KER_SESSION_PMD_HANDOFF_PREPARE &&
        request->command != KER_SESSION_PMD_HANDOFF_QUIESCED && !frame_command(request->command)) return -EINVAL;
    if (!frame_command(request->command) &&
        (request->packet_pool_tag || request->packet_object_index || request->packet_port || request->packet_queue))
        return -EINVAL;
    if (client->pmd_parked && request->command!=KER_SESSION_HEARTBEAT && !frame_command(request->command)) return -EPERM;
    if (request->capability && request->command!=KER_SESSION_RESERVE &&
        request->command!=KER_SESSION_ATTACHED && request->command!=KER_SESSION_PEER_RESERVE &&
        request->command!=KER_SESSION_RING_DETACH && request->command!=KER_SESSION_RING_DETACH_ARM &&
        request->command!=KER_SESSION_PMD_HANDOFF_QUIESCED && !frame_command(request->command))
        return -EINVAL;
    if (request->command == KER_SESSION_EPOCH_LIVE && client->kind == UNBOUND) {
        if (request->session || request->token || request->slot || request->generation || request->process || request->capability) return -EINVAL;
        reply->token = 0;
        if (!request->epoch) {
            reply->token = atomic_load_explicit(&directory->state, memory_order_acquire) == KER_SESSION_READY;
        } else for (unsigned s = 1; s < KER_SESSION_SLOTS; s++) {
            if (slots[s].epoch != request->epoch) continue;
            int m = slots[s].master;
            if (m >= 0 && !dead(clients[m].pidfd)) reply->token = 1;
            for (unsigned k = 0; k < CLIENTS; k++)
                if ((clients[k].kind == RESERVED || clients[k].kind == ATTACHED) && clients[k].slot == s &&
                    !dead(clients[k].pidfd)) reply->token = 1;
            if (reply->token) reply->slot = s;
            break;
        }
        return 0;
    }
    if (request->command == KER_SESSION_COORDINATE_QUERY) {
        if (client->kind != ATTACHED || client->peer_only || request->session || request->epoch || request->token ||
            request->slot || request->generation || request->process) {
            *reply = *request;
            return client->kind == ATTACHED ? -EINVAL : -EPERM;
        }
        struct rte_mbuf *leased = client->leased_packet;
        if (!leased || !known_object(leased) || dead(client->pidfd) || client->slot == 0 ||
            client->slot >= KER_SESSION_SLOTS || slots[client->slot].epoch !=
                atomic_load_explicit(&directory->epoch[client->slot], memory_order_acquire) ||
            atomic_load_explicit(&directory->lease[client->slot][client->generation][client->process],
                memory_order_acquire) != (uintptr_t)leased) return -ESTALE;
        reply->session = directory->session;
        reply->epoch = slots[client->slot].epoch;
        reply->slot = client->slot;
        reply->generation = client->generation;
        reply->process = client->process;
        reply->token = 0;
        return 0;
    }
    if (request->command == KER_SESSION_PMD_STATUS && (client->kind == UNBOUND || client->kind == ATTACHED)) {
        if (request->session || request->epoch || request->token || request->slot ||
            request->generation || request->process) return -EINVAL;
        if (!ring_pmd) return -EOPNOTSUPP;
        reply->epoch = reply->slot = reply->generation = reply->process = 0;
        reply->token = atomic_load_explicit(&directory->pmd_owner, memory_order_acquire);
        if ((ring_pmd == 2) != (atomic_load_explicit(&directory->exception_ifindex, memory_order_acquire) != 0)) return -EUCLEAN;
        if (pmd_client >= 0) {
            struct client *owner = &clients[pmd_client];
            reply->epoch = slots[owner->slot].epoch; reply->slot = owner->slot;
            reply->generation = owner->generation; reply->process = owner->process;
        }
        return 0;
    }
    if (request->command == KER_SESSION_STATUS && client->kind == UNBOUND) {
        if (request->session || request->epoch || request->token || request->slot ||
            request->generation || request->process) return -EINVAL;
        reply->epoch = next_epoch;
        reply->generation = message_pool ? rte_mempool_avail_count(message_pool) : 0;
        reply->token = message_pool ? rte_mempool_in_use_count(message_pool) : 0;
        reply->slot = reply->process = 0;
        for (unsigned s = 1; s < KER_SESSION_SLOTS; s++) {
            reply->slot += !!slots[s].epoch;
            reply->process += users(s);
        }
        return 0;
    }
    if (request->command == KER_SESSION_MASTER) {
        if (client->kind != UNBOUND || request->session || request->epoch || request->token ||
            request->slot || request->generation || request->process || request->capability) return -EINVAL;
        if (next_epoch == UINT64_MAX) return -EOVERFLOW;
        for (unsigned s = 1; s < KER_SESSION_SLOTS; s++) if (!slots[s].epoch) {
            uint64_t token;
            int result = random_id(&token);
            if (result) return result;
            slots[s] = (struct slot){.epoch = next_epoch++, .token = token, .master = (int)i,
                .peer_master=-1,.peer_child=-1,.peer_child_pidfd=-1};
            client->kind = MASTER; client->slot = s;
            atomic_store_explicit(&directory->epoch[s], slots[s].epoch, memory_order_release);
            reply->slot = s; reply->epoch = slots[s].epoch; reply->token = token;
            return 0;
        }
        return -ENOSPC;
    }
    if (request->command == KER_SESSION_PEER_RESERVE) {
        if (client->kind!=MASTER || client->slot>=KER_SESSION_SLOTS || client->slot!=request->slot ||
            request->session!=directory->session || request->epoch!=slots[client->slot].epoch ||
            request->token!=slots[client->slot].token || request->generation>=KER_SESSION_GENERATIONS ||
            request->process>=KER_SESSION_PROCESSES || request->capability>(uint64_t)INT_MAX ||
            !request->capability || dead(client->pidfd)) return -EPERM;
        struct slot *owner=&slots[client->slot];
        if (owner->peer_capability) return -EBUSY;
        int child=-1;
        for(unsigned k=0;k<CLIENTS;k++)
            if(clients[k].kind==UNBOUND && clients[k].pid==(pid_t)request->capability &&
                !dead(clients[k].pidfd) && direct_child(clients[k].pid,client->pid)) { child=(int)k; break; }
        if(child<0)return -EAGAIN;
        uint64_t capability;
        int result=random_id(&capability);
        if (result) return result;
        owner->peer_capability=capability; owner->peer_epoch=owner->epoch;
        owner->peer_generation=(unsigned)request->generation; owner->peer_process=(unsigned)request->process;
        owner->peer_master=(int)i; owner->peer_child=child;
        owner->peer_child_pidfd=clients[child].pidfd; owner->peer_child_pid=clients[child].pid;
        reply->capability=capability;
        return 0;
    }
    if (request->command == KER_SESSION_RING_DETACH_ARM) {
        if(client->kind!=MASTER || client->slot!=request->slot || request->session!=directory->session ||
            request->epoch!=slots[client->slot].epoch || request->token!=slots[client->slot].token ||
            request->generation>=KER_SESSION_GENERATIONS || request->process>=KER_SESSION_PROCESSES ||
            request->capability || dead(client->pidfd)) return -EPERM;
        int target=-1;
        for(unsigned k=0;k<CLIENTS;k++)
            if(clients[k].kind==ATTACHED && !clients[k].peer_only && clients[k].slot==client->slot &&
                clients[k].generation==request->generation && clients[k].process==request->process &&
                !dead(clients[k].pidfd) && direct_child(clients[k].pid,client->pid)) { target=(int)k; break; }
        if(target<0 || pmd_client<0 || pmd_client>=(int)CLIENTS || !generation_rings_enabled || !generation_rings ||
            !clients[target].generation_admitted || clients[target].detach_armed) return -ESTALE;
        struct client *source=&clients[target];
        struct client *hardware_owner=&clients[pmd_client];
        if (pmd_client!=target && ring_pmd!=1) return -EOPNOTSUPP;
        if(hardware_owner->kind!=ATTACHED || hardware_owner->peer_only ||
            !hardware_owner->generation_admitted || dead(hardware_owner->pidfd) ||
            hardware_owner->slot!=source->slot || hardware_owner->process!=source->process ||
            slots[hardware_owner->slot].epoch!=slots[source->slot].epoch ||
            !direct_child(hardware_owner->pid,clients[i].pid) ||
            (pmd_client!=target && hardware_owner->generation==source->generation) ||
            !pmd_configured ||
            atomic_load_explicit(&directory->pmd_owner,memory_order_acquire)!=pmd_key(hardware_owner)) return -ESTALE;
        struct ker_generation_identity identity=generation_identity(&clients[target]);
        int ready=ker_generation_orderly_detach_ready(generation_rings,&identity,
            &generation_cleanup_config);
        if(ready)return ready;
        uint64_t capability;
        int result=random_id(&capability);if(result)return result;
        struct client *owner=&clients[target];
        unsigned peer_slot=0; uint64_t peer_epoch=0;
        unsigned peer_client=UINT_MAX;
        int foreign=selected_peer_only((unsigned)target,&peer_slot,&peer_epoch,&peer_client);
        if(foreign<0)return foreign;
        uintptr_t pmd_rx_snapshot=atomic_load_explicit(&directory->pmd_rx_lease,memory_order_acquire);
        if(pmd_rx_snapshot&&!known_object((struct rte_mbuf *)pmd_rx_snapshot))return -EUCLEAN;
        owner->detach_capability=capability;owner->detach_armed=true;owner->detach_done=false;
        owner->detach_sequence=0;
        owner->detach_peer_snapshot=foreign!=0;
        owner->detach_peer_slot=peer_slot;owner->detach_peer_epoch=peer_epoch;
        owner->detach_peer_generation=foreign?clients[peer_client].generation:0;
        owner->detach_peer_process=foreign?clients[peer_client].process:0;
        owner->detach_peer_client=peer_client;
        owner->detach_peer_pid=foreign?clients[peer_client].pid:0;
        owner->detach_peer_pidfd=foreign?clients[peer_client].pidfd:-1;
        owner->detach_pmd_owner=atomic_load_explicit(&directory->pmd_owner,memory_order_acquire);
        owner->detach_pmd_packet=(uintptr_t)pmd_packet;
        owner->detach_pmd_rx_packet=pmd_rx_snapshot;
        owner->detach_pmd_port=pmd_port;
        owner->detach_pmd_configured=pmd_configured;
        owner->detach_owner_client=(unsigned)pmd_client;
        owner->detach_owner_slot=hardware_owner->slot;
        owner->detach_owner_epoch=slots[hardware_owner->slot].epoch;
        owner->detach_owner_generation=hardware_owner->generation;
        owner->detach_owner_process=hardware_owner->process;
        owner->detach_owner_pid=hardware_owner->pid;
        owner->detach_owner_pidfd=hardware_owner->pidfd;
        owner->detach_cleanup=generation_cleanup_config;
        reply->capability=capability;
        return 0;
    }
    if (request->command == KER_SESSION_HEARTBEAT || request->command == KER_SESSION_DRAIN_MODE ||
        request->command == KER_SESSION_PEER_STATUS) {
        if (client->kind != ATTACHED || client->slot != request->slot || request->capability ||
            client->generation != request->generation || client->process != request->process ||
            request->slot >= KER_SESSION_SLOTS || request->epoch != slots[client->slot].epoch ||
            request->session != directory->session || request->token != slots[client->slot].token)
            return -EPERM;
        if (client->peer_only && request->command!=KER_SESSION_HEARTBEAT) return -EPERM;
        unsigned s = client->slot, g = client->generation, p = client->process;
        int master = slots[s].master;
        bool master_alive = master >= 0 && clients[master].kind == MASTER && !dead(clients[master].pidfd);
        if (request->command == KER_SESSION_DRAIN_MODE) {
            if (!master_alive || !direct_child(client->pid, clients[master].pid)) return -ESTALE;
            client->drain_mode = true;
            slots[s].worker_pid[g][p] = client->pid;
            slots[s].worker_drain_mode[g][p] = true;
            return 0;
        }
        if (request->command == KER_SESSION_HEARTBEAT) {
            if (!master_alive && !client->drain_mode) return -ESTALE;
            client->heartbeat_ms = monotonic_ms();
            if (!client->heartbeat_ms) return -EIO;
            slots[s].worker_pid[g][p] = client->pid;
            slots[s].worker_heartbeat_ms[g][p] = client->heartbeat_ms;
            return 0;
        }
        /* Peer selection is per authenticated worker coordinate. The heartbeat
         * belongs to the worker, not its master; only an explicit drain-mode
         * worker may continue refreshing after that master dies. */
        uint64_t now = monotonic_ms(), peer_epoch = slots[s].epoch;
        unsigned peer_generation = g ^ 1U;
        uint64_t newest = 0;
        bool draining = false;
        if (!request->status) {
            for (unsigned candidate_slot = 1; candidate_slot < KER_SESSION_SLOTS; candidate_slot++) {
                if (candidate_slot == s || !slots[candidate_slot].epoch) continue;
                uint64_t stamp = slots[candidate_slot].worker_heartbeat_ms[g][p];
                if (!stamp || now < stamp || now - stamp > KER_SESSION_PEER_STALE_MS) continue;
                int candidate_master = slots[candidate_slot].master;
                bool candidate_master_alive = candidate_master >= 0 &&
                    clients[candidate_master].kind == MASTER && !dead(clients[candidate_master].pidfd);
                if (!candidate_master_alive && !slots[candidate_slot].worker_drain_mode[g][p]) continue;
                if (candidate_master_alive) {
                    bool attached_alive = false;
                    for (unsigned k = 0; k < CLIENTS; k++)
                        if (clients[k].kind == ATTACHED && clients[k].slot == candidate_slot &&
                            clients[k].generation == g && clients[k].process == p &&
                            clients[k].pid == slots[candidate_slot].worker_pid[g][p] && !dead(clients[k].pidfd))
                            attached_alive = true;
                    if (!attached_alive) continue;
                }
                uint64_t epoch = slots[candidate_slot].epoch;
                if (epoch > newest) newest = epoch;
            }
            if (newest) { peer_epoch = newest; draining = true; }
        }
        reply->epoch = peer_epoch;
        reply->generation = peer_generation;
        reply->token = draining;
        _Atomic uint64_t *version = &directory->peer_version[s][g][p];
        ker_session_peer_write_begin(version);
        atomic_store_explicit(&directory->peer_epoch[s][g][p], peer_epoch, memory_order_seq_cst);
        atomic_store_explicit(&directory->peer_generation[s][g][p], peer_generation, memory_order_seq_cst);
        atomic_store_explicit(&directory->peer_draining[s][g][p], draining, memory_order_seq_cst);
        ker_session_peer_write_end(version);
        return 0;
    }
    unsigned s = (unsigned)request->slot;
    /* QUIESCED is authenticated by the one-shot owner key minted by PREPARE,
     * then checked against the private handoff snapshot below. All ordinary
     * commands, including PREPARE itself, continue to require the slot token. */
    if (request->session != directory->session || request->slot >= KER_SESSION_SLOTS || !s ||
        request->epoch != slots[s].epoch || !request->epoch ||
        (request->command != KER_SESSION_PMD_HANDOFF_QUIESCED && request->token != slots[s].token))
        return -ESTALE;
    if (request->generation >= KER_SESSION_GENERATIONS || request->process >= KER_SESSION_PROCESSES)
        return -EINVAL;
    if (frame_command(request->command)) return handle_frame_request(client,request,reply);
    if (request->command == KER_SESSION_RELEASE) {
        if (client->kind != MASTER || client->slot != s) return -EPERM;
        int result = release_slot(s);
        if (!result) client->kind = RELEASED;
        return result;
    }
    if (request->command == KER_SESSION_RESERVE) {
        if (client->kind != UNBOUND) return -EINVAL;
        int m = slots[s].master;
        if (m < 0 || dead(client->pidfd) || dead(clients[m].pidfd) ||
            !direct_child(client->pid, clients[m].pid) || dead(client->pidfd) || dead(clients[m].pidfd))
            return -ESTALE;
        bool peer_only=request->capability!=0;
        if (!peer_only && slots[s].peer_capability &&
            slots[s].peer_generation==request->generation && slots[s].peer_process==request->process)
            return -EBUSY;
        if (peer_only) {
            struct slot *owner=&slots[s];
            if (owner->peer_capability!=request->capability || owner->peer_epoch!=request->epoch ||
                owner->peer_generation!=request->generation || owner->peer_process!=request->process ||
                owner->peer_master!=m || owner->peer_child!=(int)i ||
                owner->peer_child_pidfd!=client->pidfd || owner->peer_child_pid!=client->pid ||
                !direct_child(client->pid,clients[m].pid)) return -EPERM;
        }
        for (unsigned k = 0; k < CLIENTS; k++)
            if ((clients[k].kind == RESERVED || clients[k].kind == ATTACHED) && clients[k].slot == s &&
                clients[k].generation == request->generation && clients[k].process == request->process)
                return -EBUSY;
        uint64_t worker_stamp = slots[s].worker_heartbeat_ms[request->generation][request->process];
        uint64_t now = monotonic_ms();
        if (slots[s].worker_drain_mode[request->generation][request->process] && worker_stamp &&
            now >= worker_stamp && now - worker_stamp <= KER_SESSION_PEER_STALE_MS) return -EBUSY;
        slots[s].worker_pid[request->generation][request->process] = 0;
        slots[s].worker_heartbeat_ms[request->generation][request->process] = 0;
        slots[s].worker_drain_mode[request->generation][request->process] = false;
        _Atomic uintptr_t *lease = &directory->lease[s][request->generation][request->process];
        if (atomic_load_explicit(lease, memory_order_acquire)) return -EUCLEAN;
        struct rte_mbuf *packet = rte_pktmbuf_alloc(message_pool);
        if (!packet) return -ENOMEM;
        client->leased_packet = packet;
        client->kind = RESERVED; client->slot = s;
        client->generation = (unsigned)request->generation; client->process = (unsigned)request->process;
        client->peer_only=peer_only;
        client->peer_capability=peer_only?request->capability:0;
        if (peer_only) {
            slots[s].peer_capability=0; slots[s].peer_epoch=0; slots[s].peer_master=-1;
            slots[s].peer_child=-1; slots[s].peer_child_pidfd=-1; slots[s].peer_child_pid=0;
        }
        atomic_store_explicit(lease, (uintptr_t)packet, memory_order_release);
        return 0;
    }
    if (request->command == KER_SESSION_PMD_HANDOFF_PREPARE) {
        if (ring_pmd != 2) return -EOPNOTSUPP;
        if (!exact_handoff_ring_port()) return -EUCLEAN;
        if (client->slot >= KER_SESSION_SLOTS) return -EPERM;
        if (client->kind != ATTACHED || client->peer_only || !client->generation_admitted ||
            request->session != directory->session || request->epoch != slots[client->slot].epoch ||
            request->slot != client->slot || request->generation != client->generation ||
            request->process != client->process || request->token != slots[client->slot].token || request->capability ||
            client->slot>=KER_SESSION_SLOTS || pmd_client != (int)i || client->pmd_parked ||
            handoff_state != HANDOFF_NONE || !pmd_packet || dead(client->pidfd) ||
            atomic_load_explicit(&directory->pmd_owner, memory_order_acquire) != pmd_key(client) ||
            atomic_load_explicit(&directory->pmd_lease, memory_order_acquire) != (uintptr_t)pmd_packet ||
            atomic_load_explicit(&directory->pmd_rx_lease, memory_order_acquire) != (uintptr_t)pmd_rx_packet ||
            request->tx_lease_id != client->pmd_tx_lease_id ||
            request->rx_lease_id != client->pmd_rx_lease_id ||
            atomic_load_explicit(&directory->pmd_exception_phase,memory_order_acquire)!=0) return -EPERM;
#ifdef KER_SESSION_TEST_HOOKS
        const char *prepare_reject = getenv("KER_SESSION_TEST_HANDOFF_PREPARE_REJECT");
        if (prepare_reject && !strcmp(prepare_reject, "ENOENT")) return -ENOENT;
        if (prepare_reject && !strcmp(prepare_reject, "EBUSY")) return -EBUSY;
        if (prepare_reject && !strcmp(prepare_reject, "EPERM")) return -EPERM;
#endif
        int target = -1;
        for (unsigned k=0;k<CLIENTS;k++) {
            struct client *candidate=&clients[k];
            if (candidate->kind==ATTACHED && !candidate->peer_only && candidate->generation_admitted &&
                candidate->slot==client->slot && candidate->generation==(client->generation^1U) &&
                candidate->process==client->process && !dead(candidate->pidfd) &&
                candidate->pid==(pid_t)slots[candidate->slot].worker_pid[candidate->generation][candidate->process]) {
                if (target>=0) return -EUCLEAN;
                target=(int)k;
            }
        }
        if (target<0 || !atomic_load_explicit(&directory->pmd_tx_lease_id,memory_order_acquire) ||
            (ring_pmd==2 && !atomic_load_explicit(&directory->pmd_rx_lease_id,memory_order_acquire))) return -ENOENT;
        uint64_t capability=0;
        int result=random_id(&capability);
        if (result) return result;
        int peer_pidfd=fcntl(clients[target].pidfd,F_DUPFD_CLOEXEC,3);
        if(peer_pidfd<0)return -errno;
        struct rte_ring *prepare_rx=rte_ring_lookup(KER_SESSION_PACKET_RX);
        struct rte_ring *prepare_tx=rte_ring_lookup(KER_SESSION_PACKET_TX);
        if(!prepare_rx||!prepare_tx||prepare_rx!=packet_rx||prepare_tx!=packet_tx||prepare_rx==prepare_tx||
            !session_exception_keeper.pending ||
            atomic_load_explicit(&directory->pmd_exception_phase,memory_order_acquire)!=0) {
            close(peer_pidfd); return -EBUSY;
        }
        client->handoff_peer=(unsigned)target;
        client->handoff_peer_pidfd=peer_pidfd; client->handoff_peer_client_pidfd=clients[target].pidfd;
        client->handoff_peer_pid=clients[target].pid;
        client->handoff_peer_slot=clients[target].slot; client->handoff_peer_generation=clients[target].generation;
        client->handoff_peer_process=clients[target].process; client->handoff_peer_epoch=slots[clients[target].slot].epoch;
        client->handoff_capability=capability; client->handoff_owner_key=pmd_key(client);
        client->handoff_tx_pointer=(uintptr_t)pmd_packet; client->handoff_rx_pointer=(uintptr_t)pmd_rx_packet;
        client->handoff_tx_lease_id=client->pmd_tx_lease_id; client->handoff_rx_lease_id=client->pmd_rx_lease_id;
        client->handoff_owner_pidfd=client->pidfd; client->handoff_owner_pid=client->pid;
        client->handoff_owner_slot=client->slot; client->handoff_owner_generation=client->generation;
        client->handoff_owner_process=client->process; client->handoff_owner_epoch=slots[client->slot].epoch;
        client->handoff_port=pmd_port;
        client->handoff_pmd_configured=pmd_configured; client->handoff_ring_pmd=ring_pmd;
        client->handoff_rx_queues=pmd_rx_queues; client->handoff_tx_queues=pmd_tx_queues;
        client->handoff_exception_fd=session_exception_keeper.fd;
        client->handoff_exception_ring=(uintptr_t)session_exception_keeper.pending;
        client->handoff_packet_rx_ring=(uintptr_t)prepare_rx;
        client->handoff_packet_tx_ring=(uintptr_t)prepare_tx;
        client->handoff_exception_ifindex=atomic_load_explicit(&directory->exception_ifindex,memory_order_acquire);
        client->handoff_started_ms=monotonic_ms();
        handoff_client=(int)i; handoff_peer=target; handoff_state=HANDOFF_PREPARED;
        handoff_capability=capability; client->handoff_state=HANDOFF_PREPARED;
        reply->token=client->handoff_owner_key; reply->capability=capability;
        reply->tx_lease_id=client->handoff_tx_lease_id; reply->rx_lease_id=client->handoff_rx_lease_id;
        reply->epoch=client->handoff_peer_epoch; reply->slot=client->handoff_peer_slot;
        reply->generation=client->handoff_peer_generation; reply->process=client->handoff_peer_process;
        return 0;
    }
    if (request->command == KER_SESSION_PMD_HANDOFF_QUIESCED) {
        if (client->kind!=ATTACHED || client->peer_only || handoff_state!=HANDOFF_PREPARED ||
            handoff_client!=(int)i || handoff_peer<0) return -EPERM;
        if (ring_pmd != 2 || !exact_handoff_ring_port() || request->session!=directory->session ||
            request->epoch!=slots[client->slot].epoch || request->slot!=client->slot ||
            request->generation!=client->generation || request->process!=client->process ||
            request->token!=client->handoff_owner_key || request->capability!=client->handoff_capability ||
            request->tx_lease_id!=client->handoff_tx_lease_id || request->rx_lease_id!=client->handoff_rx_lease_id ||
            dead(client->pidfd) || dead(clients[handoff_peer].pidfd) || pmd_client!=(int)i || !pmd_packet ||
            !pmd_rx_packet ||
            atomic_load_explicit(&directory->pmd_owner,memory_order_acquire)!=client->handoff_owner_key ||
            atomic_load_explicit(&directory->pmd_lease,memory_order_acquire)!=(uintptr_t)pmd_packet ||
            atomic_load_explicit(&directory->pmd_rx_lease,memory_order_acquire)!=(uintptr_t)pmd_rx_packet ||
            atomic_load_explicit(&directory->pmd_tx_lease_id,memory_order_acquire)!=client->handoff_tx_lease_id ||
            atomic_load_explicit(&directory->pmd_rx_lease_id,memory_order_acquire)!=client->handoff_rx_lease_id ||
            atomic_load_explicit(&directory->pmd_exception_phase,memory_order_acquire)!=0) _Exit(125);
        if (monotonic_ms()-client->handoff_started_ms>KER_SESSION_HANDOFF_TIMEOUT_MS) _Exit(125);
        struct client *target=&clients[handoff_peer];
        if (target->kind!=ATTACHED || target->peer_only || !target->generation_admitted ||
            target->slot!=client->handoff_peer_slot || target->generation!=client->handoff_peer_generation ||
            target->process!=client->handoff_peer_process || target->pid!=client->handoff_peer_pid ||
            target->pidfd!=client->handoff_peer_client_pidfd || slots[target->slot].epoch!=client->handoff_peer_epoch ||
            dead(target->pidfd) || dead(client->handoff_peer_pidfd) ||
            target->pid!=(pid_t)slots[target->slot].worker_pid[target->generation][target->process]) _Exit(125);
        /* All authority-bearing checks precede the irreversible lease release. */
        if (client->handoff_owner_pidfd!=client->pidfd || client->handoff_owner_pid!=client->pid ||
            client->handoff_owner_slot!=client->slot || client->handoff_owner_generation!=client->generation ||
            client->handoff_owner_process!=client->process || client->handoff_owner_epoch!=slots[client->slot].epoch ||
            client->handoff_tx_pointer!=(uintptr_t)pmd_packet ||
            client->handoff_rx_pointer!=(uintptr_t)pmd_rx_packet || client->handoff_port!=pmd_port ||
            client->handoff_pmd_configured!=pmd_configured || client->handoff_ring_pmd!=ring_pmd ||
            client->handoff_rx_queues!=pmd_rx_queues || client->handoff_tx_queues!=pmd_tx_queues ||
            client->handoff_exception_fd!=session_exception_keeper.fd ||
            client->handoff_exception_ring!=(uintptr_t)session_exception_keeper.pending ||
            client->handoff_exception_ifindex!=atomic_load_explicit(&directory->exception_ifindex,memory_order_acquire) ||
            !known_object(pmd_packet) || pmd_packet->pool!=message_pool || pmd_packet->nb_segs!=1 ||
            rte_mbuf_refcnt_read(pmd_packet)!=1 || (pmd_packet->ol_flags&RTE_MBUF_F_EXTERNAL)) _Exit(125);
        if (!known_object(pmd_rx_packet) || pmd_rx_packet==pmd_packet ||
            pmd_rx_packet->pool!=message_pool || pmd_rx_packet->nb_segs!=1 ||
            rte_mbuf_refcnt_read(pmd_rx_packet)!=1 || (pmd_rx_packet->ol_flags&RTE_MBUF_F_EXTERNAL) ||
            atomic_load_explicit(&directory->pmd_rx_lease,memory_order_acquire)!=(uintptr_t)pmd_rx_packet ||
            atomic_load_explicit(&directory->pmd_exception_phase,memory_order_acquire)!=0 ||
            !session_exception_keeper.pending || !rte_ring_empty(session_exception_keeper.pending)) _Exit(125);
        struct rte_ring *handoff_rx=rte_ring_lookup(KER_SESSION_PACKET_RX);
        struct rte_ring *handoff_tx=rte_ring_lookup(KER_SESSION_PACKET_TX);
        if (!handoff_rx || !handoff_tx || handoff_rx!=packet_rx || handoff_tx!=packet_tx || handoff_rx==handoff_tx ||
            (uintptr_t)handoff_rx!=client->handoff_packet_rx_ring ||
            (uintptr_t)handoff_tx!=client->handoff_packet_tx_ring ||
            !rte_ring_empty(handoff_rx) || !rte_ring_empty(handoff_tx)) _Exit(125);
        if (ring_pmd==2) {
            atomic_store_explicit(&directory->pmd_rx_lease,0,memory_order_release);
            atomic_store_explicit(&directory->pmd_rx_lease_id,0,memory_order_release);
            rte_pktmbuf_reset(pmd_rx_packet); rte_pktmbuf_free(pmd_rx_packet); pmd_rx_packet=NULL;
        }
        atomic_store_explicit(&directory->pmd_lease,0,memory_order_release);
        atomic_store_explicit(&directory->pmd_tx_lease_id,0,memory_order_release);
        rte_pktmbuf_reset(pmd_packet); rte_pktmbuf_free(pmd_packet); pmd_packet=NULL; pmd_client=-1;
        atomic_store_explicit(&directory->pmd_owner,0,memory_order_release);
        handoff_state=HANDOFF_PARKED; client->handoff_state=HANDOFF_PARKED; client->pmd_parked=true;
        reply->token=client->handoff_owner_key; reply->capability=client->handoff_capability;
        reply->tx_lease_id=client->handoff_tx_lease_id; reply->rx_lease_id=client->handoff_rx_lease_id;
        reply->epoch=client->handoff_peer_epoch; reply->slot=client->handoff_peer_slot;
        reply->generation=client->handoff_peer_generation; reply->process=client->handoff_peer_process;
        return 0;
    }
    if (request->command == KER_SESSION_PMD_ACQUIRE) {
        if (!ring_pmd) return -EOPNOTSUPP;
        if (client->kind != ATTACHED || client->peer_only || client->pmd_parked || client->slot != s || client->generation != request->generation ||
            client->process != request->process) return -EPERM;
        if (handoff_state==HANDOFF_PREPARED) return -EBUSY;
        if (handoff_state==HANDOFF_PARKED) {
            if ((int)i!=handoff_peer || handoff_client<0 || dead(clients[handoff_client].pidfd) ||
                handoff_peer!= (int)i || clients[i].pid!=clients[handoff_client].handoff_peer_pid ||
                clients[i].pidfd!=clients[handoff_client].handoff_peer_client_pidfd ||
                clients[i].slot!=clients[handoff_client].handoff_peer_slot ||
                clients[i].generation!=clients[handoff_client].handoff_peer_generation ||
                clients[i].process!=clients[handoff_client].handoff_peer_process ||
                clients[i].slot>=KER_SESSION_SLOTS ||
                slots[clients[i].slot].epoch!=clients[handoff_client].handoff_peer_epoch ||
                dead(clients[handoff_client].handoff_peer_pidfd)) return -EPERM;
        }
        if (pmd_client >= 0) return -EBUSY;
        struct rte_mbuf *packet = rte_pktmbuf_alloc(message_pool);
        if (!packet) return -ENOMEM;
        struct rte_mbuf *rx = ring_pmd == 2 ? rte_pktmbuf_alloc(message_pool) : NULL;
        if (ring_pmd == 2 && !rx) { rte_pktmbuf_free(packet); return -ENOMEM; }
        /* Both original objects are privately journaled before the grant ACK. */
        pmd_client = (int)i; pmd_packet = packet; pmd_rx_packet = rx;
        uint64_t tx_id=next_pmd_lease_id++,rx_id=ring_pmd==2?next_pmd_lease_id++:0;
        if (!tx_id || (ring_pmd==2&&!rx_id) || !next_pmd_lease_id) _Exit(125);
        atomic_store_explicit(&directory->pmd_rx_lease_id,rx_id,memory_order_release);
        atomic_store_explicit(&directory->pmd_tx_lease_id,tx_id,memory_order_release);
        atomic_store_explicit(&directory->pmd_rx_lease, (uintptr_t)rx, memory_order_release);
        atomic_store_explicit(&directory->pmd_lease, (uintptr_t)packet, memory_order_release);
        atomic_store_explicit(&directory->pmd_owner, pmd_key(client), memory_order_release);
        client->pmd_tx_lease_id=tx_id; client->pmd_rx_lease_id=rx_id;
        reply->tx_lease_id=tx_id; reply->rx_lease_id=rx_id;
        if (handoff_state==HANDOFF_PARKED) {
            if (handoff_client<0 || (int)i!=handoff_peer || dead(clients[handoff_client].pidfd)) _Exit(125);
            /* Keep the parked owner's duplicated exact peer pidfd until the
             * parked client is reaped; frame leases bind this immutable peer. */
            handoff_state=HANDOFF_NONE; handoff_client=handoff_peer=-1; handoff_capability=0;
        }
        return 0;
    }
    if (request->command == KER_SESSION_ATTACHED) {
        if (client->kind != RESERVED || client->slot != s || client->generation != request->generation ||
            client->process != request->process) return -EPERM;
        if ((client->peer_only && (!generation_rings_enabled || !request->capability ||
                request->capability!=client->peer_capability)) ||
            (!client->peer_only && request->capability)) return -EPROTO;
        if (generation_rings_enabled && !client->peer_only) {
            if (!generation_rings || client->process != 0) return -EOPNOTSUPP;
            struct ker_generation_identity identity=generation_identity(client);
            int result=ker_generation_admit(generation_rings,&identity,client->pidfd);
            if(result)return result;
            client->generation_admitted=true;
        }
        client->kind = ATTACHED;
        client->peer_capability=0;
        reply->capability=0;
        return 0;
    }
    if (request->command == KER_SESSION_RING_DETACH) {
        if (client->kind!=ATTACHED || client->peer_only || !generation_rings_enabled ||
            !client->generation_admitted || !generation_rings || client->slot!=s ||
            client->generation!=request->generation || client->process!=request->process ||
            !request->capability || request->capability!=client->detach_capability ||
            (!client->detach_armed&&!client->detach_done) ||
            dead(client->pidfd) || pmd_client<0 ||
            !pmd_packet || !known_object(pmd_packet) ||
            atomic_load_explicit(&directory->pmd_lease,memory_order_acquire)!=(uintptr_t)pmd_packet)
            return -EPERM;
        if (client->detach_done) {
            if(request->sequence!=client->detach_sequence)return -EPERM;
            reply->token=client->detach_foreign;
            reply->capability=((uint64_t)client->detach_rx_count<<32)|client->detach_tx_count;
            return 0;
        }
        unsigned peer_slot=0; uint64_t peer_epoch=0;
        unsigned peer_client=UINT_MAX;
        int foreign=selected_peer_only(i,&peer_slot,&peer_epoch,&peer_client);
        if (foreign<0) return foreign;
        if ((foreign!=0)!=client->detach_peer_snapshot || peer_slot!=client->detach_peer_slot ||
            peer_epoch!=client->detach_peer_epoch ||
            (foreign && (peer_client!=client->detach_peer_client ||
                clients[peer_client].generation!=client->detach_peer_generation ||
                clients[peer_client].process!=client->detach_peer_process ||
                clients[peer_client].pid!=client->detach_peer_pid ||
                clients[peer_client].pidfd!=client->detach_peer_pidfd)) ||
            pmd_client!=(int)client->detach_owner_client ||
            clients[pmd_client].kind!=ATTACHED || clients[pmd_client].peer_only ||
            !clients[pmd_client].generation_admitted || dead(clients[pmd_client].pidfd) ||
            clients[pmd_client].slot!=client->detach_owner_slot ||
            slots[client->detach_owner_slot].epoch!=client->detach_owner_epoch ||
            clients[pmd_client].generation!=client->detach_owner_generation ||
            clients[pmd_client].process!=client->detach_owner_process ||
            clients[pmd_client].pid!=client->detach_owner_pid ||
            clients[pmd_client].pidfd!=client->detach_owner_pidfd ||
            !pmd_configured || !client->detach_pmd_configured ||
            pmd_port!=client->detach_pmd_port ||
            atomic_load_explicit(&directory->pmd_rx_lease,memory_order_acquire)!=client->detach_pmd_rx_packet ||
            (client->detach_pmd_rx_packet &&
                !known_object((struct rte_mbuf *)client->detach_pmd_rx_packet)) ||
            atomic_load_explicit(&directory->pmd_owner,memory_order_acquire)!=client->detach_pmd_owner ||
            atomic_load_explicit(&directory->pmd_owner,memory_order_acquire)!=pmd_key(&clients[pmd_client]) ||
            (uintptr_t)pmd_packet!=client->detach_pmd_packet ||
            !generation_cleanup_equal(&client->detach_cleanup,&generation_cleanup_config)) {
            client->detach_armed=false; client->detach_capability=0;
            client->detach_peer_snapshot=false; client->detach_peer_slot=0; client->detach_peer_epoch=0;
            client->detach_peer_generation=0;client->detach_peer_process=0;
            client->detach_peer_client=UINT_MAX;client->detach_peer_pid=0;client->detach_peer_pidfd=-1;
            client->detach_pmd_owner=0;client->detach_pmd_packet=0;client->detach_pmd_rx_packet=0;
            client->detach_pmd_port=0;client->detach_pmd_configured=false;
            memset(&client->detach_cleanup,0,sizeof(client->detach_cleanup));
            return -ESTALE;
        }
        struct ker_generation_identity identity=generation_identity(client);
        unsigned rx_count=0,tx_count=0;
        int drain_tx=!foreign && clients[pmd_client].generation==client->generation;
#ifdef KER_SESSION_TEST_HOOKS
        if (generation_test_corrupt_after_collection) {
            generation_test_corrupt_after_collection=false;
            ker_generation_test_corrupt_next_detach();
        }
#endif
        int result=ker_generation_orderly_detach(generation_rings,&identity,
            &generation_cleanup_config,drain_tx,&rx_count,&tx_count);
        if (result) { fprintf(stderr,"ker session: orderly generation detach failed %d\n",result); _Exit(125); }
        result=ker_generation_admit(generation_rings,&identity,client->pidfd);
        if (result) { fprintf(stderr,"ker session: detached generation could not be readmitted %d\n",result); _Exit(125); }
        client->generation_admitted=true; client->detach_done=true;
        client->detach_armed=false;
        client->detach_sequence=request->sequence;
        client->detach_foreign=foreign!=0; client->detach_peer_slot=peer_slot;
        client->detach_peer_epoch=peer_epoch; client->detach_rx_count=rx_count; client->detach_tx_count=tx_count;
        reply->token=client->detach_foreign;
        reply->capability=((uint64_t)rx_count<<32)|tx_count;
        printf("KER_SESSION_RING_DETACH {\"source_slot\":%u,\"source_epoch\":%llu,\"source_generation\":%u,\"owner_slot\":%u,\"owner_epoch\":%llu,\"owner_generation\":%u,\"owner_process\":%u,\"owner_pid\":%ld,\"owner_client\":%u,\"foreign_peer\":%s,\"peer_slot\":%u,\"peer_epoch\":%llu,\"peer_client\":%u,\"rx_reclaimed\":%u,\"tx_reclaimed\":%u}\n",
            client->slot,(unsigned long long)slots[client->slot].epoch,client->generation,
            clients[pmd_client].slot,(unsigned long long)slots[clients[pmd_client].slot].epoch,
            clients[pmd_client].generation,clients[pmd_client].process,(long)clients[pmd_client].pid,(unsigned)pmd_client,
            foreign?"true":"false",peer_slot,(unsigned long long)peer_epoch,
            foreign?peer_client:UINT_MAX,rx_count,tx_count);fflush(stdout);
        return 0;
    }
    return -EOPNOTSUPP;
}
static void receive_request(unsigned i)
{
    struct client *client = &clients[i];
    struct ker_session_message request, reply;
    ssize_t n = recv(client->fd, &request, sizeof(request), MSG_DONTWAIT | MSG_TRUNC);
    if (n < 0 && (errno == EAGAIN || errno == EINTR)) return;
    if (n != sizeof(request)) {
        disconnect_client(i);
        return;
    }
    if (request.sequence == client->sequence && client->sequence &&
        !memcmp(&request, &client->request, sizeof(request))) reply = client->reply;
    else if (request.sequence <= client->sequence) {
        reply = request; reply.status = -EPROTO;
    } else {
        int result = handle(i, &request, &reply);
        reply.status = result;
        client->sequence = request.sequence; client->request = request; client->reply = reply;
    }
#ifdef KER_SESSION_TEST_HOOKS
    if (request.command==KER_SESSION_PMD_HANDOFF_PREPARE &&
        request.tx_lease_id==client->pmd_tx_lease_id && request.rx_lease_id==client->pmd_rx_lease_id) {
        const char *mode=getenv("KER_SESSION_TEST_HANDOFF_MODE");
        if (mode && !strncmp(mode,"bad-prepare-error",17) && reply.status) {
            const char *field=getenv("KER_SESSION_TEST_HANDOFF_BAD_ERROR_FIELD");
            if(!field || !strcmp(field,"generation")) { reply.generation^=1U; field="generation"; }
            else if(!strcmp(field,"token")) reply.token^=UINT64_C(1);
            else if(!strcmp(field,"capability")) reply.capability^=UINT64_C(1);
            else if(!strcmp(field,"tx-lease")) reply.tx_lease_id^=UINT64_C(1);
            else if(!strcmp(field,"rx-lease")) reply.rx_lease_id^=UINT64_C(1);
            else if(!strcmp(field,"sequence")) reply.sequence^=UINT64_C(1);
            else field="unsupported";
            printf("KER_SESSION_TEST_HANDOFF_REPLY_CORRUPTED {\"kind\":\"error\",\"field\":\"%s\"}\n",field); fflush(stdout);
        } else if (mode && !strcmp(mode,"bad-prepare-success") && !reply.status) {
            reply.token^=UINT64_C(1);
            printf("KER_SESSION_TEST_HANDOFF_REPLY_CORRUPTED {\"kind\":\"success\",\"field\":\"token\"}\n"); fflush(stdout);
        }
    }
#endif
    ssize_t sent;
    if (!reply.status && request.command == KER_SESSION_PMD_ACQUIRE && ring_pmd == 2) {
        char control[CMSG_SPACE(sizeof(int))] = {0};
        struct iovec iov = {.iov_base=&reply,.iov_len=sizeof(reply)};
        struct msghdr message = {.msg_iov=&iov,.msg_iovlen=1,.msg_control=control,.msg_controllen=sizeof(control)};
        struct cmsghdr *cmsg = CMSG_FIRSTHDR(&message);
        cmsg->cmsg_level = SOL_SOCKET; cmsg->cmsg_type = SCM_RIGHTS; cmsg->cmsg_len = CMSG_LEN(sizeof(int));
        memcpy(CMSG_DATA(cmsg), &session_exception_keeper.fd, sizeof(int));
        sent = sendmsg(client->fd, &message, MSG_DONTWAIT | MSG_NOSIGNAL);
    } else sent = send(client->fd, &reply, sizeof(reply), MSG_DONTWAIT | MSG_NOSIGNAL);
    if (sent != sizeof(reply)) disconnect_client(i);
}
static int accept_client(int listener)
{
    int fd = accept4(listener, NULL, NULL, SOCK_NONBLOCK | SOCK_CLOEXEC);
    if (fd < 0) return errno == EAGAIN || errno == EINTR ? 0 : -errno;
    struct ucred credential;
    socklen_t size = sizeof(credential);
    int pidfd = -1;
    if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &credential, &size) ||
        size != sizeof(credential) || credential.uid != geteuid()) { close(fd); return 0; }
    size = sizeof(pidfd);
    if (getsockopt(fd, SOL_SOCKET, SO_PEERPIDFD, &pidfd, &size) || size != sizeof(pidfd)) {
        if (pidfd >= 0) close(pidfd);
        close(fd); return -EOPNOTSUPP;
    }
    for (unsigned i = 0; i < CLIENTS; i++) if (clients[i].kind == UNUSED) {
        clients[i] = (struct client){.fd = fd, .pidfd = pidfd, .pid = credential.pid, .kind = UNBOUND,
            .frame_consumer_pidfd = -1, .frame_producer_pidfd = -1,
            .frame_consumer_client = UINT_MAX};
        return 0;
    }
    close(pidfd); close(fd); return 0;
}
static int all_eal_users(void)
{
    for (unsigned i = 0; i < CLIENTS; i++)
        if ((clients[i].kind == RESERVED || clients[i].kind == ATTACHED) && !dead(clients[i].pidfd)) return 1;
    return 0;
}
static int primary(const char *path, int control)
{
    int result = 1, listener = -1;
    struct ker_generation_ring_stats generation_stats={0};
#ifdef KER_SESSION_TEST_HOOKS
    tc3_probe_gate = getenv("KER_SESSION_TEST_PROBE_GATE") != NULL;
    directory_test_hooks = getenv("KER_SESSION_TEST_DIRECTORY_HOOKS") != NULL;
#endif
    struct stat socket_identity = {0};
    bool bound = false;
    for (unsigned i = 0; i < CLIENTS; i++) clients[i] = (struct client){.fd = -1, .pidfd = -1,
        .frame_consumer_pidfd = -1, .frame_producer_pidfd = -1,
        .frame_consumer_client = UINT_MAX};
    for (unsigned i = 0; i < KER_SESSION_SLOTS; i++) slots[i].master = -1;
    zone = rte_memzone_reserve(KER_SESSION_ZONE, sizeof(*directory), SOCKET_ID_ANY, 0);
    if (!zone) goto cleanup;
    directory = zone->addr;
    memset(directory, 0, sizeof(*directory));
    directory->magic = KER_SESSION_MAGIC; directory->version = KER_SESSION_VERSION;
    directory->size = sizeof(*directory); directory->primary_pid = (uint32_t)getpid();
    directory->slots = KER_SESSION_SLOTS; directory->generations = KER_SESSION_GENERATIONS;
    directory->processes = KER_SESSION_PROCESSES; directory->channels = KER_SESSION_CHANNELS;
    directory->capacity = KER_SESSION_CAPACITY;
    atomic_init(&directory->state, KER_SESSION_PREPARING);
    directory->ring_pmd = ring_pmd;
    atomic_init(&directory->pmd_owner, 0);
    atomic_init(&directory->exception_ifindex, 0);
    atomic_init(&directory->pmd_lease, 0);
    atomic_init(&directory->pmd_rx_lease, 0);
    atomic_init(&directory->pmd_tx_lease_id, 0);
    atomic_init(&directory->pmd_rx_lease_id, 0);
    atomic_init(&directory->pmd_exception_phase, 0);
    atomic_init(&directory->pmd_exception_discarded, 0);
    for (unsigned s = 0; s < KER_SESSION_SLOTS; s++) {
        atomic_init(&directory->epoch[s], 0);
        for (unsigned g = 0; g < KER_SESSION_GENERATIONS; g++)
            for (unsigned p = 0; p < KER_SESSION_PROCESSES; p++) {
                atomic_init(&directory->lease[s][g][p], 0);
                atomic_init(&directory->peer_version[s][g][p], 0);
                atomic_init(&directory->peer_epoch[s][g][p], 0);
                atomic_init(&directory->peer_generation[s][g][p], 0);
                atomic_init(&directory->peer_draining[s][g][p], 0);
            }
    }
    if (!atomic_is_lock_free(&directory->pmd_owner) || !atomic_is_lock_free(&directory->exception_ifindex) || !atomic_is_lock_free(&directory->pmd_lease) ||
        !atomic_is_lock_free(&directory->pmd_rx_lease) || !atomic_is_lock_free(&directory->pmd_tx_lease_id) ||
        !atomic_is_lock_free(&directory->pmd_rx_lease_id) || !atomic_is_lock_free(&directory->pmd_exception_phase) || !atomic_is_lock_free(&directory->pmd_exception_discarded) ||
        !atomic_is_lock_free(&directory->epoch[0]) ||
        !atomic_is_lock_free(&directory->peer_version[1][0][0]) ||
        !atomic_is_lock_free(&directory->peer_epoch[1][0][0]) ||
        !atomic_is_lock_free(&directory->peer_generation[1][0][0]) ||
        !atomic_is_lock_free(&directory->peer_draining[1][0][0]) ||
        !atomic_is_lock_free(&directory->lease[0][0][0]) || random_id(&directory->session)) goto cleanup;
#ifdef KER_SESSION_TEST_HOOKS
    if (directory_test_hooks) directory_test_save_header();
#endif
    for (unsigned s = 0; s < KER_SESSION_SLOTS; s++)
        for (unsigned g = 0; g < KER_SESSION_GENERATIONS; g++)
            for (unsigned p = 0; p < KER_SESSION_PROCESSES; p++)
                for (unsigned c = 0; c < KER_SESSION_CHANNELS; c++) {
                    char name[RTE_RING_NAMESIZE];
                    if (ring_name(name, sizeof(name), s, g, p, c)) goto cleanup;
                    rings[ring_index(s, g, p, c)] = rte_ring_create(name, KER_SESSION_CAPACITY,
                        SOCKET_ID_ANY, RING_F_EXACT_SZ | RING_F_SP_ENQ | RING_F_SC_DEQ);
                    if (!rings[ring_index(s, g, p, c)]) goto cleanup;
                }
    message_pool = rte_pktmbuf_pool_create(KER_SESSION_POOL, KER_SESSION_OBJECTS, 0, 0,
        RTE_MBUF_DEFAULT_BUF_SIZE, SOCKET_ID_ANY);
    if (!message_pool) { fprintf(stderr, "ker session message pool: %s\n", rte_strerror(rte_errno)); goto cleanup; }
    if (rte_mempool_obj_iter(message_pool, remember_object, NULL) != KER_SESSION_OBJECTS) goto cleanup;
    if (generation_rings_enabled && ker_generation_rings_create(directory->session,1,2,message_pool,&generation_rings)) {
        fprintf(stderr,"ker session: generation packet-ring creation failed\n");goto cleanup;
    }
    if (ring_pmd) {
        struct rte_eth_conf config = {0};
        if (ring_pmd == 2) {
            if (rte_eth_dev_count_avail()) goto cleanup;
            int created = ker_session_packet_create(&packet_rx, &packet_tx);
            if (created < 0) goto cleanup;
        }
        if (rte_eth_dev_get_port_by_name(ring_pmd == 2 ? KER_SESSION_PACKET_PORT : "net_ring_ker", &pmd_port) || rte_eth_dev_count_avail() != 1 ||
            rte_eth_dev_configure(pmd_port, 1, 1, &config)) goto cleanup;
        pmd_rx_queues = 1; pmd_tx_queues = 1; pmd_configured = true;
        if (rte_eth_rx_queue_setup(pmd_port, 0, 128, SOCKET_ID_ANY, NULL, message_pool) ||
            rte_eth_tx_queue_setup(pmd_port, 0, 128, SOCKET_ID_ANY, NULL) || rte_eth_dev_start(pmd_port)) goto cleanup;
        if (ring_pmd == 2) {
            struct rte_ether_addr mac = {.addr_bytes = {0x02, 0x4b, 0x45,
                (uint8_t)(directory->session >> 16), (uint8_t)(directory->session >> 8), (uint8_t)directory->session}};
            snprintf(session_exception_iface, sizeof(session_exception_iface), "kex%08x", (unsigned)directory->session);
            snprintf(session_exception_ring, sizeof(session_exception_ring), "ker_se_%08x", (unsigned)directory->session);
            unsigned ifindex = 0;
            int endpoint_result = ker_worker_exception_open_session(
                &session_exception_keeper, session_exception_iface, session_exception_ring,
                message_pool, &mac, 1500, 64, &directory->pmd_exception_phase, &ifindex);
            if (endpoint_result || !ifindex) {
                fprintf(stderr, "ker session: exception endpoint setup failed: %d\n", endpoint_result ? endpoint_result : -ENODEV);
                goto cleanup;
            }
            directory->exception_ifindex = ifindex;
        }
    }
    int precreated = validate_shared_rings();
    if (precreated != (int)QUEUES) goto cleanup;
    struct sockaddr_un address = {.sun_family = AF_UNIX};
    if (strlen(path) >= sizeof(address.sun_path)) goto cleanup;
    strcpy(address.sun_path, path);
    char parent[sizeof(address.sun_path)]; strcpy(parent, path);
    char *slash = strrchr(parent, '/');
    if (!slash || slash == parent) goto cleanup;
    *slash = 0;
    struct stat info;
    if (stat(parent, &info) || !S_ISDIR(info.st_mode) || info.st_uid != geteuid() || (info.st_mode & 077)) {
        fprintf(stderr, "ker session: socket parent must be an owned private directory\n"); goto cleanup;
    }
    listener = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (listener < 0) goto cleanup;
    mode_t previous = umask(077);
    int status = bind(listener, (void *)&address, sizeof(address));
    umask(previous);
    if (status) goto cleanup; /* Never unlink somebody else's existing socket. */
    bound = true;
    if (lstat(path, &socket_identity) || listen(listener, 16)) goto cleanup;
    atomic_store_explicit(&directory->state, KER_SESSION_READY, memory_order_release);
    printf("KER_SESSION_READY {\"stage\":\"shared-control\",\"session\":%llu,\"rings\":%u,\"slots\":%u,\"ring_pmd\":%s,\"ports\":%u,\"epoch\":%llu,\"slot\":0,\"exception_endpoint_name\":\"%s\",\"exception_endpoint_ifindex\":%u}\n",
        (unsigned long long)directory->session, (unsigned)precreated, KER_SESSION_SLOTS, ring_pmd ? "true" : "false",
        (unsigned)rte_eth_dev_count_avail(), (unsigned long long)atomic_load_explicit(&directory->epoch[0], memory_order_acquire), ring_pmd == 2 ? session_exception_iface : "", atomic_load_explicit(&directory->exception_ifindex, memory_order_acquire)); fflush(stdout);
    result = 0;
    while (!stopping) {
        reap_clients();
        if (handoff_state!=HANDOFF_NONE && handoff_client>=0 &&
            monotonic_ms()-clients[handoff_client].handoff_started_ms>KER_SESSION_HANDOFF_TIMEOUT_MS) _Exit(125);
#ifdef KER_SESSION_TEST_HOOKS
        if (tc3_probe_gate && tc3_drain_requested) {
            int verified = verify_tc3_probe_barrier();
            if (!verified) {
                tc3_probe_gate = false;
                serve_probes();
            } else if (verified != -EAGAIN) {
                fprintf(stderr, "ker session: TC-3 pending-token barrier failed: %d\n", verified);
                result = 1; break;
            }
        }
#endif
        serve_probes();
        struct pollfd fds[CLIENTS + 2];
        fds[0] = (struct pollfd){.fd = control, .events = POLLIN};
        fds[1] = (struct pollfd){.fd = listener, .events = POLLIN};
        for (unsigned i = 0; i < CLIENTS; i++) fds[i + 2] = (struct pollfd){.fd = clients[i].fd, .events = POLLIN};
        int ready = poll(fds, CLIENTS + 2, 50);
        if (ready < 0) { if (errno == EINTR) continue; result = 1; break; }
        if (fds[0].revents) {
#ifdef KER_SESSION_TEST_HOOKS
            if (fds[0].revents & POLLIN) {
                char command;
                if (read(control, &command, 1) == 1) {
                    if (tc3_probe_gate && command == 'D') {
                        tc3_drain_requested = true;
                        continue;
                    }
                    if (directory_test_hooks && command == 'M') {
                        char field;
                        if (read(control, &field, 1) == 1 && !directory_test_corrupt_header(field)) {
                            printf("KER_SESSION_TEST_DIRECTORY_MUTATED {\"field\":\"%c\"}\n", field); fflush(stdout);
                            continue;
                        }
                    }
                    if (directory_test_hooks && command == 'R') {
                        directory_test_restore_header();
                        printf("KER_SESSION_TEST_DIRECTORY_RESTORED\n"); fflush(stdout);
                        continue;
                    }
                    if (directory_test_hooks && command == 'S') {
                        directory_test_snapshot();
                        continue;
                    }
                    if (directory_test_hooks && command == 'G') {
                        int saved_errno = rte_errno;
                        int generation_present = ker_generation_rings_test_directory_present();
                        const struct rte_memzone *control_zone = rte_memzone_lookup(KER_SESSION_ZONE);
                        int session_present = control_zone != NULL;
                        int session_matches = control_zone == zone;
                        rte_errno = saved_errno;
                        printf("KER_SESSION_TEST_DIRECTORY_STATE {\"generation_present\":%s,\"session_present\":%s,\"session_matches\":%s,\"session\":%llu}\n",
                            generation_present ? "true" : "false", session_present ? "true" : "false",
                            session_matches ? "true" : "false", (unsigned long long)directory->session);
                        fflush(stdout);
                        continue;
                    }
                }
            }
#endif
            break;
        }
        if (fds[1].revents & POLLIN) if (accept_client(listener)) { result = 1; break; }
        for (unsigned i = 0; i < CLIENTS; i++) {
            if (clients[i].fd < 0) continue;
            if (fds[i + 2].revents & POLLIN) receive_request(i);
            if (clients[i].fd >= 0 && (fds[i + 2].revents & (POLLHUP | POLLERR | POLLNVAL))) {
                disconnect_client(i);
            }
        }
    }
cleanup:
    if (directory) atomic_store_explicit(&directory->state, KER_SESSION_STOPPING, memory_order_release);
    if (listener >= 0) close(listener);
    for (unsigned i = 0; i < CLIENTS; i++) if (clients[i].fd >= 0) {
        close(clients[i].fd); clients[i].fd = -1;
    }
    /* Control EOF requests quiescence; only exact process death proves all
     * EAL borrowers are gone. Never free live secondary references on timeout. */
    for (unsigned i = 0; all_eal_users() && i < 100; i++) poll(NULL, 0, 50);
    if (all_eal_users()) { fprintf(stderr, "ker session: live EAL users prevent cleanup\n"); _Exit(125); }
    for (unsigned i = 0; i < CLIENTS; i++) {
        if (clients[i].kind == RESERVED || clients[i].kind == ATTACHED) reclaim_control(i);
        drop_client(i);
    }
    if (session_exception_keeper.pending && ker_worker_exception_close(&session_exception_keeper)) result = 1;
    if (pmd_configured) {
        if (rte_eth_dev_stop(pmd_port) || rte_eth_dev_close(pmd_port)) result = 1;
    }
    if (generation_rings) {
        if (ker_generation_rings_stats(generation_rings,&generation_stats)) {
            fprintf(stderr,"ker session: generation ring telemetry was not quiescent at shutdown\n");_Exit(125);
        }
        if (ker_generation_rings_destroy(generation_rings)) {
            fprintf(stderr,"ker session: generation packet rings are not quiescent\n");_Exit(125);
        }
        generation_rings=NULL;
    }
    if (packet_rx) { if (!rte_ring_empty(packet_rx)) _Exit(125); rte_ring_free(packet_rx); }
    if (packet_tx) { if (!rte_ring_empty(packet_tx)) _Exit(125); rte_ring_free(packet_tx); }
    if (message_pool) {
        if (rte_mempool_in_use_count(message_pool)) {
            fprintf(stderr, "ker session: outstanding shared control objects prevent cleanup\n"); _Exit(125);
        }
        printf("KER_SESSION_DRAINED {\"outstanding\":0,\"objects\":%u,\"exception_lease_discarded\":%llu,\"generation_rings\":{\"rx_full\":%llu,\"tx_full\":%llu,\"tx_drop\":%llu,\"rx_peak\":%u,\"tx_peak\":%u,\"rx_capacity\":%u,\"tx_capacity\":%u,\"rx_rings\":%u,\"tx_rings\":%u}}\n",
            KER_SESSION_OBJECTS, (unsigned long long)atomic_load_explicit(&directory->pmd_exception_discarded, memory_order_acquire),
            (unsigned long long)generation_stats.rx_full,(unsigned long long)generation_stats.tx_full,
            (unsigned long long)generation_stats.tx_drop,generation_stats.rx_peak,generation_stats.tx_peak,
            generation_stats.rx_capacity,generation_stats.tx_capacity,generation_stats.rx_rings,generation_stats.tx_rings); fflush(stdout);
        rte_mempool_free(message_pool);
    }
    for (unsigned i = 0; i < QUEUES; i++) if (rings[i]) {
        if (!rte_ring_empty(rings[i])) { fprintf(stderr, "ker session: nonempty ring prevents cleanup\n"); _Exit(125); }
        rte_ring_free(rings[i]);
    }
    if (zone && rte_memzone_free(zone)) result = 1;
    if (bound) {
        struct stat current;
        if (!lstat(path, &current) && current.st_dev == socket_identity.st_dev && current.st_ino == socket_identity.st_ino)
            if (unlink(path)) result = 1;
    }
    if (rte_eal_cleanup()) result = 1;
    return result;
}
static int receive_exact(int fd, void *data, size_t length)
{
    size_t offset = 0;
    while (offset < length) {
        ssize_t n = read(fd, (char *)data + offset, length - offset);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return -EIO;
        offset += (size_t)n;
    }
    return 0;
}
static void require_resident_alive(int resident);
static bool message_equal_except_status(const struct ker_session_message *a,const struct ker_session_message *b)
{
    struct ker_session_message left=*a,right=*b; left.status=right.status=0;
    return !memcmp(&left,&right,sizeof(left));
}
static int exchange(int fd, struct ker_session_message *message, int resident)
{
    struct ker_session_message response, expected=*message;
    require_resident_alive(resident);
    if (send(fd, message, sizeof(*message), MSG_NOSIGNAL) != sizeof(*message)) return -EIO;
    require_resident_alive(resident);
    if (recv(fd, &response, sizeof(response), MSG_TRUNC) != sizeof(response)) return -EIO;
    require_resident_alive(resident);
    if (expected.command==KER_SESSION_ATTACHED) expected.capability=0;
    if (response.status > 0 || response.status < -4095) return -EPROTO;
    if (expected.command==KER_SESSION_PMD_ACQUIRE && !response.status) {
        if (!response.tx_lease_id || (ring_pmd==2 ? !response.rx_lease_id : response.rx_lease_id!=0)) return -EPROTO;
        expected.tx_lease_id=response.tx_lease_id; expected.rx_lease_id=response.rx_lease_id;
    }
    if (!message_equal_except_status(&response,&expected)) return -EPROTO;
    *message=response;
    return (int)response.status;
}
static int exchange_exception_fd(int fd, struct ker_session_message *message, int resident, int *received_fd)
{
    struct ker_session_message response;
    char control[CMSG_SPACE(sizeof(int) * 2)] = {0};
    struct iovec iov = {.iov_base=&response,.iov_len=sizeof(response)};
    struct msghdr header = {.msg_iov=&iov,.msg_iovlen=1,.msg_control=control,.msg_controllen=sizeof(control)};
    *received_fd = -1;
    require_resident_alive(resident);
    if (send(fd, message, sizeof(*message), MSG_NOSIGNAL) != sizeof(*message)) return -EIO;
    require_resident_alive(resident);
    ssize_t received = recvmsg(fd, &header, MSG_CMSG_CLOEXEC | MSG_TRUNC);
    require_resident_alive(resident);
    if (received < 0) return -EIO;
    unsigned descriptors = 0;
    bool ancillary_invalid = false;
    for (struct cmsghdr *cmsg=CMSG_FIRSTHDR(&header); cmsg; cmsg=CMSG_NXTHDR(&header,cmsg)) {
        if (cmsg->cmsg_level != SOL_SOCKET || cmsg->cmsg_type != SCM_RIGHTS ||
            cmsg->cmsg_len < CMSG_LEN(sizeof(int)) ||
            (cmsg->cmsg_len - CMSG_LEN(0)) % sizeof(int)) {
            ancillary_invalid = true;
            continue;
        }
        size_t count=(cmsg->cmsg_len-CMSG_LEN(0))/sizeof(int);
        int *fds=(int *)CMSG_DATA(cmsg);
        for (size_t i=0;i<count;i++) { if (!descriptors++) *received_fd=fds[i]; else close(fds[i]); }
    }
    bool identity_bad=false;
    if (response.status>=-4095 && response.status<=0 && message->command==KER_SESSION_PMD_ACQUIRE && !response.status) {
        struct ker_session_message expected=*message;
        if(!response.tx_lease_id || !response.rx_lease_id) identity_bad=true;
        expected.tx_lease_id=response.tx_lease_id; expected.rx_lease_id=response.rx_lease_id;
        identity_bad|=!message_equal_except_status(&response,&expected);
    } else identity_bad=!message_equal_except_status(&response,message);
    if (received != sizeof(response) || header.msg_flags & (MSG_TRUNC | MSG_CTRUNC) || ancillary_invalid ||
        identity_bad || response.status > 0 || response.status < -4095) {
        if (*received_fd >= 0) { close(*received_fd); *received_fd=-1; }
        return -EPROTO;
    }
    *message=response;
    if (response.status) {
        if (*received_fd>=0) { close(*received_fd); *received_fd=-1; }
        return (int)response.status;
    }
    if (descriptors != 1) { if (*received_fd>=0) close(*received_fd); *received_fd=-1; return -EPROTO; }
    return 0;
}
static int coordinate_query(int fd, uint64_t sequence, struct ker_session_message *reply)
{
    struct ker_session_message request = {.magic = KER_SESSION_MAGIC,
        .version = KER_SESSION_VERSION, .command = KER_SESSION_COORDINATE_QUERY,
        .sequence = sequence};
    struct ker_session_message response;
    if (send(fd, &request, sizeof(request), MSG_NOSIGNAL) != sizeof(request) ||
        recv(fd, &response, sizeof(response), MSG_TRUNC) != sizeof(response)) return -EIO;
    if (response.magic != KER_SESSION_MAGIC || response.version != KER_SESSION_VERSION ||
        response.command != request.command || response.sequence != request.sequence ||
        response.status > 0 || response.status < -4095) return -EPROTO;
    if (response.status) return (int)response.status;
    if (!response.session || !response.epoch || !response.slot || response.slot >= KER_SESSION_SLOTS ||
        response.generation >= KER_SESSION_GENERATIONS || response.process >= KER_SESSION_PROCESSES ||
        response.token) return -EPROTO;
    *reply = response;
    return 0;
}
static int worker_request(int fd, const struct ker_session_message *identity,
    uint64_t *sequence, uint64_t command, int reload_active, int resident,
    struct ker_session_message *response)
{
    require_resident_alive(resident);
    struct ker_session_message request = *identity;
    request.command = command;
    request.sequence = ++*sequence;
    request.status = command == KER_SESSION_PEER_STATUS ? reload_active : 0;
    if (send(fd, &request, sizeof(request), MSG_NOSIGNAL) != sizeof(request)) return -EIO;
    require_resident_alive(resident);
    if (recv(fd, response, sizeof(*response), MSG_TRUNC) != sizeof(*response)) return -EIO;
    require_resident_alive(resident);
    if (response->magic != request.magic || response->version != request.version ||
        response->command != request.command || response->sequence != request.sequence ||
        response->session != request.session || response->slot != request.slot ||
        response->process != request.process || response->status > 0 || response->status < -4095)
        return -EPROTO;
    if (response->status) return (int)response->status;
    if (command != KER_SESSION_PEER_STATUS && command != KER_SESSION_RING_DETACH &&
        !message_equal_except_status(response,&request)) return -EPROTO;
    if (command == KER_SESSION_PEER_STATUS &&
        (!response->epoch || response->generation >= KER_SESSION_GENERATIONS || response->token > 1)) return -EPROTO;
    if (command == KER_SESSION_RING_DETACH && (response->token>1 ||
        (response->token && (!response->epoch || !response->generation)) ||
        (!response->token && (response->epoch || response->generation)))) return -EPROTO;
    return 0;
}
static int worker_handoff_request(int fd,const struct ker_session_message *identity,
    uint64_t *sequence,int resident,uint64_t command,uint64_t owner_key,uint64_t capability,
    uint64_t tx_lease_id,uint64_t rx_lease_id,struct ker_session_message *response)
{
    struct ker_session_message request=*identity;
    request.command=command; request.sequence=++*sequence; request.status=0;
    request.token=command==KER_SESSION_PMD_HANDOFF_PREPARE?identity->token:owner_key;
    request.capability=capability; request.tx_lease_id=tx_lease_id; request.rx_lease_id=rx_lease_id;
#ifdef KER_SESSION_TEST_HOOKS
    const char *handoff_mode=getenv("KER_SESSION_TEST_HANDOFF_MODE");
    if(command==KER_SESSION_PMD_HANDOFF_QUIESCED && handoff_mode) {
        if(!strcmp(handoff_mode,"bad-capability"))request.capability^=UINT64_C(1);
        else if(!strcmp(handoff_mode,"bad-tx-lease"))request.tx_lease_id^=UINT64_C(1);
        else if(!strcmp(handoff_mode,"bad-rx-lease"))request.rx_lease_id^=UINT64_C(1);
    }
#endif
    require_resident_alive(resident);
    if(send(fd,&request,sizeof(request),MSG_NOSIGNAL)!=sizeof(request))return -EIO;
#ifdef KER_SESSION_TEST_HOOKS
    if(command==KER_SESSION_PMD_HANDOFF_QUIESCED && getenv("KER_SESSION_TEST_HANDOFF_MODE")) {
        printf("KER_SESSION_TEST_HANDOFF_QUIESCED_SENT {\"mode\":\"%s\"}\n",
            getenv("KER_SESSION_TEST_HANDOFF_MODE")); fflush(stdout);
    }
#endif
    require_resident_alive(resident);
    if(recv(fd,response,sizeof(*response),MSG_TRUNC)!=sizeof(*response))return -EIO;
    require_resident_alive(resident);
    if(response->magic!=request.magic || response->version!=request.version ||
        response->command!=request.command || response->sequence!=request.sequence ||
        response->status > 0 || response->status < -4095) return -EPROTO;
    if(response->status) {
        /* Rejections echo the exact request identity and authority. Accepting
         * the successor identity on an error can hide a malformed or stale
         * reply and incorrectly convert a recoverable rejection to success. */
        if(!message_equal_except_status(response,&request)) return -EPROTO;
        return (int)response->status;
    }
    struct ker_session_message expected=request;
    expected.generation=identity->generation^1U;
    expected.token=owner_key;
    if(command==KER_SESSION_PMD_HANDOFF_PREPARE) {
        if(!response->capability) return -EPROTO;
        expected.capability=response->capability;
    } else expected.capability=capability;
    if(!message_equal_except_status(response,&expected) ||
        response->tx_lease_id!=tx_lease_id || response->rx_lease_id!=rx_lease_id) return -EPROTO;
#ifdef KER_SESSION_TEST_HOOKS
    if(command==KER_SESSION_PMD_HANDOFF_PREPARE && getenv("KER_SESSION_TEST_HANDOFF_REPLAY_PREPARE")) {
        struct ker_session_message replay;
        if(send(fd,&request,sizeof(request),MSG_NOSIGNAL)!=sizeof(request))return -EIO;
        require_resident_alive(resident);
        if(recv(fd,&replay,sizeof(replay),MSG_TRUNC)!=sizeof(replay))return -EIO;
        require_resident_alive(resident);
        if(memcmp(response,&replay,sizeof(replay)))return -EPROTO;
        printf("KER_SESSION_TEST_HANDOFF_PREPARE_REPLAY {\"same_response\":true}\n"); fflush(stdout);
    }
#endif
    return 0;
}
#ifdef KER_SESSION_TEST_HOOKS
static int worker_handoff_expect_prepare_rejected(int fd,const struct ker_session_message *identity,
    uint64_t *sequence,int resident,uint64_t tx_lease_id,uint64_t rx_lease_id)
{
    struct ker_session_message request=*identity,response,expected;
    request.command=KER_SESSION_PMD_HANDOFF_PREPARE; request.sequence=++*sequence; request.status=0;
    request.token=identity->token; request.capability=0; request.tx_lease_id=tx_lease_id^UINT64_C(1);
    request.rx_lease_id=rx_lease_id;
    require_resident_alive(resident);
    if(send(fd,&request,sizeof(request),MSG_NOSIGNAL)!=sizeof(request))return -EIO;
    require_resident_alive(resident);
    if(recv(fd,&response,sizeof(response),MSG_TRUNC)!=sizeof(response))return -EIO;
    require_resident_alive(resident);
    expected=request; expected.session=directory->session; expected.status=-EPERM;
    if(memcmp(&response,&expected,sizeof(response)))return -EPROTO;
    if(send(fd,&request,sizeof(request),MSG_NOSIGNAL)!=sizeof(request))return -EIO;
    require_resident_alive(resident);
    struct ker_session_message replay;
    if(recv(fd,&replay,sizeof(replay),MSG_TRUNC)!=sizeof(replay))return -EIO;
    require_resident_alive(resident);
    if(memcmp(&response,&replay,sizeof(response)))return -EPROTO;
    printf("KER_SESSION_TEST_HANDOFF_PREPARE_REJECTED {\"status\":%d,\"same_replay\":true}\n",-EPERM);
    fflush(stdout);
    return 0;
}
#endif
struct worker_heartbeat {
    bool pending, frame_reply_valid;
    struct ker_session_message request, frame_reply;
    uint64_t sent_ms, last_ack_ms;
};
static int pump_worker_heartbeat(int fd, struct worker_heartbeat *heartbeat, int resident);
static int heartbeat_tick(int fd, const struct ker_session_message *identity,
    uint64_t *sequence, int resident, struct worker_heartbeat *heartbeat);
static int drain_worker_heartbeat_after_command(int fd, struct worker_heartbeat *heartbeat,
    int resident, int control);
static int worker_frame_request(int fd,const struct ker_session_message *identity,uint64_t *sequence,
    int resident,uint64_t capability,uint64_t command,uint64_t tag,uint32_t index,
    uint16_t port,uint16_t queue,uint64_t lease,struct worker_heartbeat *heartbeat,
    struct ker_session_message *response);
static int parked_frame_datagram(int packet_fd,int fd,int resident,int control,
    const struct ker_session_message *identity,uint64_t *sequence,uint64_t capability,
    struct worker_heartbeat *heartbeat,struct ker_generation_rings *rings);
static int parked_owner_wait(int control,int packet_fd,int fd,int resident,
    const struct ker_session_message *identity,uint64_t *sequence,uint64_t capability,
    struct worker_heartbeat *heartbeat,struct ker_generation_rings *rings)
{
    printf("KER_SESSION_PMD_PARKED {\"pid\":%ld,\"owner_key\":%llu}\n",
        (long)getpid(),(unsigned long long)atomic_load_explicit(&directory->pmd_owner,memory_order_acquire)); fflush(stdout);
    while(!stopping) {
        require_resident_alive(resident);
        int tick=heartbeat_tick(fd,identity,sequence,resident,heartbeat);
        if(tick<0)return tick;
        if(dead(resident))_Exit(125);
        struct pollfd waiters[]={{.fd=control,.events=POLLIN},{.fd=fd,.events=POLLIN},
            {.fd=resident,.events=POLLIN},{.fd=packet_fd,.events=POLLIN}};
        int ready=poll(waiters,4,100);
        if(ready<0){if(errno==EINTR)continue;return -errno;}
        if(waiters[2].revents)_Exit(125);
        if(waiters[1].revents) {
            int ack;
            if(heartbeat->pending) {
                ack=pump_worker_heartbeat(fd,heartbeat,resident);
                if(ack<0)return ack;
                if(!ack||heartbeat->pending)continue; /* exact stale frame replay or no complete ACK yet */
            } else {
                struct ker_session_message replay;
                ssize_t n=recv(fd,&replay,sizeof(replay),MSG_DONTWAIT|MSG_TRUNC);
                if(n==sizeof(replay)&&heartbeat->frame_reply_valid&&
                    !memcmp(&replay,&heartbeat->frame_reply,sizeof(replay))) continue;
                return -EPROTO; /* unsolicited non-frame data */
            }
        }
        if(waiters[0].revents) {
            if(waiters[0].revents&(POLLHUP|POLLERR|POLLNVAL))return 0;
            if(waiters[0].revents&POLLIN) {
                char command; ssize_t count=read(control,&command,1);
                if(count==0)return 0;
                if(count<0&&errno==EINTR)continue;
                return -EPROTO; /* Parked workers accept no device/control commands. */
            }
        }
        if (waiters[3].revents & (POLLERR|POLLHUP|POLLNVAL)) return -EPIPE;
        if (waiters[3].revents & POLLIN) {
            int frame=parked_frame_datagram(packet_fd,fd,resident,control,identity,sequence,
                capability,heartbeat,rings);
            if (frame<0) return frame;
        }
    }
    return 0;
}
#ifdef KER_SESSION_TEST_HOOKS
static int worker_detach_request(int fd,const struct ker_session_message *identity,
    uint64_t *sequence,uint64_t capability,int resident,struct ker_session_message *response)
{
    struct ker_session_message request=*identity, replay;
    request.command=KER_SESSION_RING_DETACH;request.sequence=++*sequence;request.status=0;request.capability=capability;
    require_resident_alive(resident);
    if(send(fd,&request,sizeof(request),MSG_NOSIGNAL)!=sizeof(request))return -EIO;
    require_resident_alive(resident);
    if(recv(fd,response,sizeof(*response),MSG_TRUNC)!=sizeof(*response))return -EIO;
    require_resident_alive(resident);
    if(response->magic!=request.magic||response->version!=request.version||
        response->command!=request.command||response->sequence!=request.sequence||
        response->session!=request.session||response->epoch!=request.epoch||response->slot!=request.slot||
        response->generation!=request.generation||response->process!=request.process||
        response->status||response->token>1)return -EPROTO;
    /* Immediate exact retransmission must return the resident's cached result. */
    if(send(fd,&request,sizeof(request),MSG_NOSIGNAL)!=sizeof(request))return -EIO;
    require_resident_alive(resident);
    if(recv(fd,&replay,sizeof(replay),MSG_TRUNC)!=sizeof(replay))return -EIO;
    require_resident_alive(resident);
    return memcmp(response,&replay,sizeof(replay))?-EPROTO:0;
}
static int worker_detach_expect_status(int fd,const struct ker_session_message *identity,
    uint64_t *sequence,uint64_t capability,int resident,int expected)
{
    struct ker_session_message request=*identity,response;
    request.command=KER_SESSION_RING_DETACH;request.sequence=++*sequence;request.status=0;request.capability=capability;
    require_resident_alive(resident);
    if(send(fd,&request,sizeof(request),MSG_NOSIGNAL)!=sizeof(request))return -EIO;
    require_resident_alive(resident);
    if(recv(fd,&response,sizeof(response),MSG_TRUNC)!=sizeof(response))return -EIO;
    require_resident_alive(resident);
    if(response.magic!=request.magic||response.version!=request.version||
        response.command!=request.command||response.sequence!=request.sequence||
        response.session!=request.session||response.epoch!=request.epoch||
        response.slot!=request.slot||response.generation!=request.generation||
        response.process!=request.process) {
        fprintf(stderr,"ker session detach identity mismatch expected{cmd=%u seq=%llu slot=%llu epoch=%llu gen=%u proc=%u} actual{cmd=%u seq=%llu slot=%llu epoch=%llu gen=%u proc=%u status=%d}\n",
            (unsigned)request.command,(unsigned long long)request.sequence,(unsigned long long)request.slot,
            (unsigned long long)request.epoch,(unsigned)request.generation,(unsigned)request.process,
            (unsigned)response.command,(unsigned long long)response.sequence,(unsigned long long)response.slot,
            (unsigned long long)response.epoch,(unsigned)response.generation,(unsigned)response.process,(int)response.status);
        return -EPROTO;
    }
    if(response.status!=expected) {
        fprintf(stderr,"ker session detach status mismatch expected{cmd=%u seq=%llu status=%d} actual{cmd=%u seq=%llu status=%d}\n",
            (unsigned)request.command,(unsigned long long)request.sequence,expected,
            (unsigned)response.command,(unsigned long long)response.sequence,(int)response.status);
        return -EPROTO;
    }
    return 0;
}
#endif
static uint64_t monotonic_ms(void)
{
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now)) return 0;
    return (uint64_t)now.tv_sec * 1000 + (uint64_t)now.tv_nsec / 1000000;
}
static void require_resident_alive(int resident)
{
    if (dead(resident)) { fprintf(stderr, "ker session: primary process exited\n"); _Exit(125); }
}
/* Observe cancellation commands while preserving queued probe requests. */
static int probe_control(int control, unsigned *deferred_probes)
{
    if (stopping) return -ECANCELED;
    struct pollfd event = {.fd = control, .events = POLLIN};
    int ready;
    do ready = poll(&event, 1, 0); while (ready < 0 && errno == EINTR && !stopping);
    if (stopping) return -ECANCELED;
    if (ready < 0) return -errno;
    if (!ready) return 0;
    if (event.revents & (POLLERR | POLLNVAL)) return -ECANCELED;
    if (event.revents & POLLIN) {
        char command;
        ssize_t count;
        do count = read(control, &command, 1); while (count < 0 && errno == EINTR && !stopping);
        if (stopping || count == 0) return -ECANCELED;
        if (count < 0) return errno == EAGAIN || errno == EWOULDBLOCK ? 0 : -errno;
        if (command != 'P') return -ECANCELED;
        if (*deferred_probes == UINT_MAX) return -EOVERFLOW;
        (*deferred_probes)++;
    }
    if (event.revents & POLLHUP) return -ECANCELED;
    return 0;
}
static int pump_worker_heartbeat(int fd, struct worker_heartbeat *heartbeat, int resident)
{
    if (!heartbeat->pending) return 0;
    require_resident_alive(resident);
    struct ker_session_message reply;
    ssize_t n = recv(fd, &reply, sizeof(reply), MSG_DONTWAIT | MSG_TRUNC);
    if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) return 0;
    require_resident_alive(resident);
    if(n==sizeof(reply)&&heartbeat->frame_reply_valid&&
        !memcmp(&reply,&heartbeat->frame_reply,sizeof(reply))) return 0;
    if (n != sizeof(reply) || reply.status ||
        !message_equal_except_status(&reply,&heartbeat->request)) return -EPROTO;
    heartbeat->pending = false;
    heartbeat->last_ack_ms = monotonic_ms();
    return 1;
}
static int heartbeat_tick(int fd, const struct ker_session_message *identity,
    uint64_t *sequence, int resident, struct worker_heartbeat *heartbeat)
{
    require_resident_alive(resident);
    bool acknowledged = false;
    if (heartbeat->pending) {
        int result = pump_worker_heartbeat(fd, heartbeat, resident);
        if (result < 0) return result;
        acknowledged = result > 0;
        if (heartbeat->pending) return acknowledged ? 1 : 0;
    }
    uint64_t now = monotonic_ms();
    if (now < heartbeat->last_ack_ms || now - heartbeat->last_ack_ms < 250) return acknowledged ? 1 : 0;
    if (*sequence == UINT64_MAX) return -EOVERFLOW;
    struct ker_session_message request = *identity;
    request.command = KER_SESSION_HEARTBEAT;
    request.sequence = *sequence + 1;
    request.status = 0;
    ssize_t n = send(fd, &request, sizeof(request), MSG_DONTWAIT | MSG_NOSIGNAL);
    if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) return 0;
    if (n != sizeof(request)) return -EIO;
    *sequence = request.sequence;
    heartbeat->request = request;
    heartbeat->sent_ms = now;
    heartbeat->pending = true;
    require_resident_alive(resident);
    return acknowledged ? 1 : 0;
}
#ifdef KER_SESSION_TEST_HOOKS
static int worker_test_handoff_prepared(int control,int fd,int resident,
    const struct ker_session_message *identity,uint64_t *sequence,
    struct worker_heartbeat *heartbeat,const char *mode)
{
    printf("KER_SESSION_TEST_HANDOFF_PREPARED {\"mode\":\"%s\"}\n",mode); fflush(stdout);
    if(strcmp(mode,"peer-death")&&strcmp(mode,"timeout"))return 0;
    uint64_t start=monotonic_ms();
    uint64_t deadline=start+(strcmp(mode,"timeout")?10000U:KER_SESSION_HANDOFF_TIMEOUT_MS+1000U);
    for(;;) {
        if(stopping)return -EINTR;
        if(dead(resident))return -ECONNRESET;
        int tick=heartbeat_tick(fd,identity,sequence,resident,heartbeat);
        if(tick<0)return tick;
        uint64_t now=monotonic_ms();
        if(now>=deadline)return -ETIMEDOUT;
        struct pollfd waiters[]={{.fd=control,.events=POLLIN},{.fd=resident,.events=POLLIN}};
        int timeout=(int)(deadline-now); if(timeout>50)timeout=50;
        int ready=poll(waiters,2,timeout);
        if(ready<0) { if(errno==EINTR)continue; return -errno; }
        if(waiters[1].revents)_Exit(125);
        if(waiters[0].revents&(POLLERR|POLLHUP|POLLNVAL))return -ECANCELED;
        if(waiters[0].revents&POLLIN) {
            char command=0; ssize_t count=read(control,&command,1);
            if(count!=1||command!='D')return -EPROTO;
            return 0;
        }
    }
}
#endif
static int drain_worker_heartbeat(int fd, struct worker_heartbeat *heartbeat,
    int resident, int control)
{
    uint64_t deadline = monotonic_ms() + 1000;
    while (heartbeat->pending) {
        require_resident_alive(resident);
        int result = pump_worker_heartbeat(fd, heartbeat, resident);
        if (result < 0 || !heartbeat->pending) return result < 0 ? result : 0;
        if (stopping) return -EINTR;
        uint64_t now = monotonic_ms();
        if (now >= deadline) return -ETIMEDOUT;
        struct pollfd waiters[] = {{.fd = fd, .events = POLLIN},
            {.fd = resident, .events = POLLIN}, {.fd = control, .events = POLLIN}};
        int timeout = (int)(deadline - now);
        if (timeout > 50) timeout = 50;
        int ready = poll(waiters, control >= 0 ? 3 : 2, timeout);
        if (ready < 0 && errno == EINTR) continue;
        if (ready < 0) return -errno;
        if (waiters[1].revents) return -ECONNRESET;
        if (control >= 0 && (waiters[2].revents & (POLLHUP | POLLERR | POLLNVAL))) return -ECANCELED;
        if (control >= 0 && (waiters[2].revents & POLLIN)) return -EINTR;
    }
    return 0;
}
static int report_handoff_control_result(int result)
{
#ifdef KER_SESSION_TEST_HOOKS
    if (result == -ECANCELED && getenv("KER_SESSION_TEST_HANDOFF_CONTROL_HUP")) {
        printf("KER_SESSION_TEST_HANDOFF_CONTROL_HUP {\"prepare_authorized\":false}\n"); fflush(stdout);
    }
#endif
    return result;
}
/* Finish the response for a control byte that the worker has already read.
 * A later byte may be queued while its heartbeat ACK is still pending. The
 * control-aware drain reports that as EINTR without consuming the byte; drain
 * only the ACK, then let the main loop process the queued command in order. */
static int drain_worker_heartbeat_after_command(int fd, struct worker_heartbeat *heartbeat,
    int resident, int control)
{
    if (stopping) return -EINTR;
    int result = drain_worker_heartbeat(fd, heartbeat, resident, control);
#ifdef KER_SESSION_TEST_HOOKS
    if (result == -ECANCELED && getenv("KER_SESSION_TEST_DQ_PENDING_HB")) {
        fprintf(stderr, "KER_SESSION_TEST_DQ_CONTROL_HUP {\"authorized\":false}\n");
        fflush(stderr);
    }
#endif
    if (result == -EINTR && !stopping) {
#ifdef KER_SESSION_TEST_HOOKS
        if (getenv("KER_SESSION_TEST_DQ_PENDING_HB")) {
            fprintf(stderr, "KER_SESSION_TEST_DQ_HEARTBEAT_DEFERRED {\"queued_control\":true}\n");
            fflush(stderr);
        }
        if (getenv("KER_SESSION_TEST_HANDOFF_PENDING_HB")) {
            printf("KER_SESSION_TEST_HANDOFF_HEARTBEAT_DEFERRED {\"queued_control\":true}\n");
            fflush(stdout);
        }
#endif
        result = drain_worker_heartbeat(fd, heartbeat, resident, -1);
    }
    if (result) return report_handoff_control_result(result);
    if (stopping) return -EINTR;
    if (control >= 0) {
        struct pollfd state = {.fd=control, .events=POLLIN};
        int ready;
        do ready = poll(&state, 1, 0); while (ready < 0 && errno == EINTR && !stopping);
        if (ready < 0) return -errno;
        if (state.revents & (POLLHUP | POLLERR | POLLNVAL))
            return report_handoff_control_result(-ECANCELED);
    }
    if (stopping) return -EINTR;
    return 0;
}
static int worker_frame_request(int fd,const struct ker_session_message *identity,uint64_t *sequence,
    int resident,uint64_t capability,uint64_t command,uint64_t tag,uint32_t index,
    uint16_t port,uint16_t queue,uint64_t lease,struct worker_heartbeat *heartbeat,
    struct ker_session_message *response)
{
    struct ker_session_message request=*identity,expected;
    request.command=command; request.sequence=++*sequence; request.status=0;
    request.token=identity->token; request.capability=capability;
    request.tx_lease_id=lease; request.rx_lease_id=0;
    request.packet_pool_tag=tag; request.packet_object_index=index;
    request.packet_port=port; request.packet_queue=queue;
    require_resident_alive(resident);
    if(send(fd,&request,sizeof(request),MSG_NOSIGNAL)!=sizeof(request))return -EIO;
#ifdef KER_SESSION_TEST_HOOKS
    bool replay_test=getenv("KER_SESSION_TEST_FRAME_REPLAY")!=NULL;
    if(replay_test&&send(fd,&request,sizeof(request),MSG_NOSIGNAL)!=sizeof(request))return -EIO;
#else
    bool replay_test=false;
#endif
    require_resident_alive(resident);
    ssize_t n;
    do n=recv(fd,response,sizeof(*response),MSG_TRUNC); while(n<0&&errno==EINTR&&!dead(resident));
    require_resident_alive(resident);
    if(n<0)return -errno;
    if(n!=sizeof(*response))return -EPROTO;
    if(replay_test) {
        struct ker_session_message replay;
        do n=recv(fd,&replay,sizeof(replay),MSG_TRUNC); while(n<0&&errno==EINTR&&!dead(resident));
        require_resident_alive(resident);
        if(n!=(ssize_t)sizeof(replay)||memcmp(response,&replay,sizeof(replay)))return -EPROTO;
    }
        if(response->magic!=request.magic||response->version!=request.version||
            response->command!=request.command||response->sequence!=request.sequence||
            response->status>0||response->status < -4095)return -EPROTO;
        expected=request;
        if(response->status) {
            expected.status=response->status;
            if(memcmp(response,&expected,sizeof(expected)))return -EPROTO;
            if(heartbeat){heartbeat->frame_reply=*response;heartbeat->frame_reply_valid=true;}
            return (int)response->status;
        }
        if(command==KER_SESSION_FRAME_PREPARE) {
            if(response->packet_pool_tag!=tag||response->packet_port!=port||response->packet_queue!=queue||
                response->packet_object_index==UINT32_MAX||!response->tx_lease_id||response->rx_lease_id)
                return -EPROTO;
            expected.packet_object_index=response->packet_object_index;
            expected.tx_lease_id=response->tx_lease_id;
        }
        if(!message_equal_except_status(response,&expected))return -EPROTO;
        if(heartbeat){heartbeat->frame_reply=*response;heartbeat->frame_reply_valid=true;}
        return 0;
}
static int parked_frame_cancel(int fd,int resident,const struct ker_session_message *identity,
    uint64_t *sequence,uint64_t capability,struct worker_heartbeat *heartbeat,
    const struct ker_session_message *prepared)
{
    struct ker_session_message reply;
    int result=worker_frame_request(fd,identity,sequence,resident,capability,
        KER_SESSION_FRAME_CANCEL,prepared->packet_pool_tag,prepared->packet_object_index,
        prepared->packet_port,prepared->packet_queue,prepared->tx_lease_id,heartbeat,&reply);
    return result;
}
#ifdef KER_SESSION_TEST_HOOKS
static int frame_negative_prepare(int fd,int resident,const struct ker_session_message *identity,
    uint64_t *sequence,uint64_t capability,uint64_t tag,unsigned variant)
{
    struct ker_session_message request=*identity,response,expected;
    request.command=KER_SESSION_FRAME_PREPARE;request.sequence=++*sequence;request.status=0;
    request.capability=capability;request.token=identity->token;request.packet_pool_tag=tag;
    request.packet_object_index=UINT32_MAX;request.packet_port=0;request.packet_queue=0;
    request.tx_lease_id=0;request.rx_lease_id=0;
    int expected_status=-EPERM;
    switch(variant){
    case 0: request.capability^=1; break;
    case 1: request.token^=1;expected_status=-ESTALE;break;
    case 2: request.session^=1;expected_status=-ESTALE;break;
    case 3: request.epoch^=1;expected_status=-ESTALE;break;
    case 4: request.slot^=1;expected_status=-ESTALE;break;
    case 5: request.generation^=1;break;
    case 6: request.process^=1;break;
    case 7: request.packet_pool_tag^=1;expected_status=-EOPNOTSUPP;break;
    case 8: request.packet_object_index=0;expected_status=-EBUSY;break;
    case 9: request.packet_queue=2;expected_status=-EOPNOTSUPP;break;
    case 10: request.tx_lease_id=1;expected_status=-EBUSY;break;
    case 11: request.version--;expected_status=-EPROTO;break;
    default:return -EINVAL;
    }
    require_resident_alive(resident);
    if(send(fd,&request,sizeof(request),MSG_NOSIGNAL)!=(ssize_t)sizeof(request))return -EIO;
    ssize_t n;
    do n=recv(fd,&response,sizeof(response),MSG_TRUNC);while(n<0&&errno==EINTR&&!dead(resident));
    require_resident_alive(resident);
    if(n!=(ssize_t)sizeof(response))return n<0?-errno:-EPROTO;
    expected=request;expected.status=expected_status;
    if(memcmp(&response,&expected,sizeof(expected)))return -EPROTO;
    return 0;
}
static int frame_negative_pending_request(int fd,int resident,
    const struct ker_session_message *identity,uint64_t *sequence,uint64_t capability,
    const struct ker_session_message *prepared,uint64_t command,unsigned variant)
{
    struct ker_session_message request=*identity,response,expected;
    request.command=command;request.sequence=++*sequence;request.status=0;
    request.capability=capability;request.packet_pool_tag=prepared->packet_pool_tag;
    request.packet_object_index=prepared->packet_object_index;request.packet_port=prepared->packet_port;
    request.packet_queue=prepared->packet_queue;request.tx_lease_id=prepared->tx_lease_id;
    request.rx_lease_id=0;
    int status;
    if(variant==0){request.capability^=1;status=-EPERM;}
    else {request.tx_lease_id^=1;status=-ESTALE;}
    require_resident_alive(resident);
    if(send(fd,&request,sizeof(request),MSG_NOSIGNAL)!=(ssize_t)sizeof(request))return -EIO;
    ssize_t n;
    do n=recv(fd,&response,sizeof(response),MSG_TRUNC);while(n<0&&errno==EINTR&&!dead(resident));
    require_resident_alive(resident);
    if(n!=(ssize_t)sizeof(response))return n<0?-errno:-EPROTO;
    expected=request;expected.status=status;
    return memcmp(&response,&expected,sizeof(expected))?-EPROTO:0;
}
static int frame_negative_prepares_leave_datagram(int packet_fd,int fd,int resident,
    const struct ker_session_message *identity,uint64_t *sequence,uint64_t capability,
    struct ker_generation_rings *rings,const uint8_t *peek_bytes,size_t peek_length)
{
    uint64_t tag=ker_generation_packet_pool_tag(rings);
    uint32_t ring_before,pool_before,ring_after,pool_after;
    if(ker_generation_test_tx_snapshot(rings,0,0,0,&ring_before,&pool_before)||ring_before)return -EUCLEAN;
    for(unsigned variant=0;variant<12;variant++) {
        int result=frame_negative_prepare(fd,resident,identity,sequence,capability,tag,variant);
        if(result)return result;
        if(ker_generation_test_tx_snapshot(rings,0,0,0,&ring_after,&pool_after)||
            ring_after!=ring_before||pool_after!=pool_before)return -EUCLEAN;
        uint8_t observed[sizeof(struct ker_packet_header)+1518];
        struct iovec iov={.iov_base=observed,.iov_len=sizeof(observed)};
        struct msghdr msg={.msg_iov=&iov,.msg_iovlen=1};
        ssize_t n=recvmsg(packet_fd,&msg,MSG_PEEK|MSG_TRUNC|MSG_DONTWAIT);
        if(n!=(ssize_t)peek_length||memcmp(observed,peek_bytes,peek_length))return -EUCLEAN;
    }
    printf("KER_SESSION_FRAME_NEGATIVE_PREPARES_PASS {\"variants\":12,\"datagram_queued\":true,\"ring_unchanged\":true,\"pool_unchanged\":true}\n");
    fflush(stdout);return 0;
}
static int frame_prepare_cancel_replay(int packet_fd,int fd,int resident,
    const struct ker_session_message *identity,uint64_t *sequence,uint64_t capability,
    struct worker_heartbeat *heartbeat,struct ker_generation_rings *rings,
    const uint8_t *peek_bytes,size_t peek_length,uint64_t tag)
{
    uint32_t ring_before,pool_before,ring_after,pool_after;
    if(ker_generation_test_tx_snapshot(rings,0,0,0,&ring_before,&pool_before)||ring_before)return -EUCLEAN;
    struct ker_session_message prepared,cancelled;
    int result=worker_frame_request(fd,identity,sequence,resident,capability,
        KER_SESSION_FRAME_PREPARE,tag,UINT32_MAX,0,0,0,heartbeat,&prepared);
    if(result)return result;
    if(frame_negative_pending_request(fd,resident,identity,sequence,capability,&prepared,
        KER_SESSION_FRAME_COMMIT,0)||
        frame_negative_pending_request(fd,resident,identity,sequence,capability,&prepared,
        KER_SESSION_FRAME_CANCEL,1))return -EPROTO;
    if(ker_generation_test_tx_snapshot(rings,0,0,0,&ring_after,&pool_after)||
        ring_after!=ring_before||pool_after!=pool_before+1)return -EUCLEAN;
    result=worker_frame_request(fd,identity,sequence,resident,capability,
        KER_SESSION_FRAME_CANCEL,prepared.packet_pool_tag,prepared.packet_object_index,
        prepared.packet_port,prepared.packet_queue,prepared.tx_lease_id,heartbeat,&cancelled);
    if(result)return result;
    if(ker_generation_test_tx_snapshot(rings,0,0,0,&ring_after,&pool_after)||ring_after!=ring_before||
        pool_after!=pool_before)return -EUCLEAN;
    uint8_t observed[sizeof(struct ker_packet_header)+1518];
    struct iovec iov={.iov_base=observed,.iov_len=sizeof(observed)};
    struct msghdr msg={.msg_iov=&iov,.msg_iovlen=1};
    ssize_t n=recvmsg(packet_fd,&msg,MSG_PEEK|MSG_TRUNC|MSG_DONTWAIT);
    if(n!=(ssize_t)peek_length||memcmp(observed,peek_bytes,peek_length))return -EUCLEAN;
    printf("KER_SESSION_FRAME_CANCEL_REPLAY_PASS {\"prepared_replay\":true,\"bad_commit_denied\":true,\"bad_cancel_denied\":true,\"cancel_replay\":true,\"datagram_queued\":true,\"pool_restored\":true}\n");
    fflush(stdout);return 0;
}
#endif
static int parked_frame_datagram(int packet_fd,int fd,int resident,int control,
    const struct ker_session_message *identity,uint64_t *sequence,uint64_t capability,
    struct worker_heartbeat *heartbeat,struct ker_generation_rings *rings)
{
    if(!rings||!generation_rings_enabled||!identity||!capability)return -EOPNOTSUPP;
    uint8_t peek_bytes[sizeof(struct ker_packet_header)+1518];
    struct iovec peek_iov={.iov_base=peek_bytes,.iov_len=sizeof(peek_bytes)};
    struct msghdr peek_msg={.msg_iov=&peek_iov,.msg_iovlen=1};
    ssize_t peek=recvmsg(packet_fd,&peek_msg,MSG_PEEK|MSG_TRUNC|MSG_DONTWAIT);
    if(peek<0)return (errno==EAGAIN||errno==EWOULDBLOCK||errno==EINTR)?0:-errno;
    if(peek<(ssize_t)(sizeof(struct ker_packet_header)+14)||
        peek>(ssize_t)sizeof(peek_bytes)||(peek_msg.msg_flags&MSG_TRUNC))return -EMSGSIZE;
    struct ker_packet_header peek_header; memcpy(&peek_header,peek_bytes,sizeof(peek_header));
    if(peek_header.flags||peek_header.gso_type||peek_header.header_length||peek_header.gso_size||
        peek_header.checksum_start||peek_header.checksum_offset||peek_header.buffers)return -EOPNOTSUPP;
    int drained=drain_worker_heartbeat_after_command(fd,heartbeat,resident,control);
    if(drained)return drained;
    uint64_t tag=ker_generation_packet_pool_tag(rings);
    if(!tag)return -EUCLEAN;
#ifdef KER_SESSION_TEST_HOOKS
    if(getenv("KER_SESSION_TEST_FRAME_NEGATIVES")) {
        int negatives=frame_negative_prepares_leave_datagram(packet_fd,fd,resident,identity,sequence,
            capability,rings,peek_bytes,(size_t)peek);
        if(negatives)return negatives;
        int canceled=frame_prepare_cancel_replay(packet_fd,fd,resident,identity,sequence,
            capability,heartbeat,rings,peek_bytes,(size_t)peek,tag);
        if(canceled)return canceled;
    }
#endif
    struct ker_session_message prepared;
    int result=worker_frame_request(fd,identity,sequence,resident,capability,
        KER_SESSION_FRAME_PREPARE,tag,UINT32_MAX,0,0,0,heartbeat,&prepared);
    if(result) {
        if(result==-EBUSY||result==-ENOMEM||result==-ENOBUFS)return 0; /* Datagram remains queued. */
        return result;
    }
    struct ker_generation_identity source={.session=identity->session,.epoch=identity->epoch,
        .slot=(uint32_t)identity->slot,.generation=(uint32_t)identity->generation,
        .process=(uint32_t)identity->process,.pid=(uint32_t)getpid()};
    if(prepared.packet_pool_tag!=tag) { if(parked_frame_cancel(fd,resident,identity,sequence,capability,heartbeat,&prepared))_Exit(125); return -EPROTO; }
    struct rte_mbuf *packet=ker_generation_packet_resolve(rings,&source,
        prepared.packet_object_index,prepared.tx_lease_id);
    if(!packet) { if(parked_frame_cancel(fd,resident,identity,sequence,capability,heartbeat,&prepared))_Exit(125); return -ESTALE; }
    uint16_t frame_length=(uint16_t)(peek-sizeof(struct ker_packet_header));
    void *frame=rte_pktmbuf_append(packet,frame_length);
    if(!frame) {
        int complete=ker_generation_packet_write_complete(rings,&source,
            prepared.packet_object_index,prepared.tx_lease_id);
        if(complete!=-EMSGSIZE&&complete)_Exit(125);
        if(parked_frame_cancel(fd,resident,identity,sequence,capability,heartbeat,&prepared))_Exit(125);
        return -ENOSPC;
    }
    struct ker_packet_header received_header={0};
    struct iovec receive_iov[2]={{.iov_base=&received_header,.iov_len=sizeof(received_header)},
        {.iov_base=frame,.iov_len=frame_length}};
    struct msghdr receive_msg={.msg_iov=receive_iov,.msg_iovlen=2};
    ssize_t consumed=recvmsg(packet_fd,&receive_msg,MSG_DONTWAIT|MSG_TRUNC);
    int receive_errno=consumed<0?errno:0;
    int complete=ker_generation_packet_write_complete(rings,&source,
        prepared.packet_object_index,prepared.tx_lease_id);
    if(complete==-EUCLEAN||complete==-ESTALE)_Exit(125);
    bool input_bad=consumed!=(ssize_t)peek||(receive_msg.msg_flags&MSG_TRUNC)||
        memcmp(&received_header,&peek_header,sizeof(received_header));
    if(consumed<0||input_bad||complete) {
        if(parked_frame_cancel(fd,resident,identity,sequence,capability,heartbeat,&prepared))_Exit(125);
        return consumed<0?-receive_errno:(complete?complete:-EIO);
    }
    struct ker_session_message committed;
    result=worker_frame_request(fd,identity,sequence,resident,capability,
        KER_SESSION_FRAME_COMMIT,prepared.packet_pool_tag,prepared.packet_object_index,
        prepared.packet_port,prepared.packet_queue,prepared.tx_lease_id,heartbeat,&committed);
    if(result)return result;
    char frame_hex[1518*2+1];
    static const char hex[]="0123456789abcdef";
    const uint8_t *committed_bytes=rte_pktmbuf_mtod(packet,const uint8_t *);
    for(unsigned i=0;i<frame_length;i++){
        frame_hex[i*2]=hex[committed_bytes[i]>>4];frame_hex[i*2+1]=hex[committed_bytes[i]&15];
    }
    frame_hex[frame_length*2]='\0';
    printf("KER_SESSION_FRAME_COMMITTED {\"port\":%u,\"queue\":%u,\"generation\":%llu,\"length\":%u,\"object_index\":%u,\"pool_tag\":%llu,\"packet_pointer\":\"%p\",\"frame_hex\":\"%s\"}\n",
        prepared.packet_port,prepared.packet_queue,(unsigned long long)identity->generation,frame_length,
        prepared.packet_object_index,(unsigned long long)tag,(void *)packet,frame_hex); fflush(stdout);
    return 1;
}

static int shared_probe(struct rte_ring *input, struct rte_ring *output,
    struct rte_mbuf *packet, const struct ker_session_message *identity, int control,
    unsigned *deferred_probes, unsigned count, uint64_t *next_sequence, int resident,
    int fd, uint64_t *control_sequence, struct worker_heartbeat *heartbeat)
{
    for (unsigned sequence = 1; sequence <= count; sequence++) {
        require_resident_alive(resident);
        if (heartbeat_tick(fd, identity, control_sequence, resident, heartbeat) < 0) return -EIO;
        int cancelled = probe_control(control, deferred_probes);
        if (cancelled) { require_resident_alive(resident); return cancelled; }
        rte_pktmbuf_reset(packet);
        struct ker_session_probe expected = {.identity = *identity};
        if (*next_sequence == UINT64_MAX) return -EOVERFLOW;
        expected.identity.command = KER_SESSION_PROBE; expected.identity.sequence = ++*next_sequence;
        expected.identity.token = 0; expected.identity.status = -EINPROGRESS;
        for (unsigned b = 0; b < sizeof(expected.payload); b++)
            expected.payload[b] = (uint8_t)(identity->epoch + identity->generation * 17 + identity->process * 31 + sequence + b);
        void *data = rte_pktmbuf_append(packet, sizeof(expected));
        if (!data) return -EMSGSIZE;
        memcpy(data, &expected, sizeof(expected));
        require_resident_alive(resident);
        cancelled = probe_control(control, deferred_probes);
        if (cancelled) { require_resident_alive(resident); return cancelled; }
        if (rte_ring_enqueue(input, packet)) return -ENOBUFS;
        /* After publication, cancellation leaves the leased mbuf in its ring.
         * The resident reclaims it only after this exact borrower dies. */
        uint64_t deadline = monotonic_ms() + 5000;
        struct rte_mbuf *reply;
        for (;;) {
            require_resident_alive(resident);
            if (heartbeat_tick(fd, identity, control_sequence, resident, heartbeat) < 0) return -EIO;
            cancelled = probe_control(control, deferred_probes);
            if (cancelled) { require_resident_alive(resident); return cancelled; }
            if (!rte_ring_dequeue(output, (void **)&reply)) break;
            if (monotonic_ms() >= deadline) return -ETIMEDOUT;
            poll(NULL, 0, 1);
        }
        if (reply != packet || reply->nb_segs != 1 || reply->data_len != sizeof(expected)) return -EPROTO;
        struct ker_session_probe *actual = rte_pktmbuf_mtod(reply, struct ker_session_probe *);
        expected.identity.status = 0; expected.responder = (uint64_t)directory->primary_pid;
        int result = memcmp(actual, &expected, sizeof(expected)) ? -EPROTO : 0;
        if (result) return result;
    }
    return 0;
}
static int pmd_roundtrips(struct rte_mbuf *packet, const struct ker_session_message *identity,
    unsigned count, uint64_t *sequence, int peer, int control, unsigned *deferred_probes,
    int fd, uint64_t *control_sequence, struct worker_heartbeat *heartbeat)
{
    uint64_t key = 1 + (identity->slot * KER_SESSION_GENERATIONS + identity->generation) * KER_SESSION_PROCESSES + identity->process;
    struct rte_eth_stats before, after;
    if (rte_eth_stats_get(pmd_port, &before)) return -EIO;
    for (unsigned i = 0; i < count; i++) {
        require_resident_alive(peer);
        if (heartbeat_tick(fd, identity, control_sequence, peer, heartbeat) < 0) return -EIO;
        int cancelled = probe_control(control, deferred_probes);
        if (cancelled) { require_resident_alive(peer); return cancelled; }
        if (atomic_load_explicit(&directory->pmd_owner, memory_order_acquire) != key ||
            atomic_load_explicit(&directory->epoch[identity->slot], memory_order_acquire) != identity->epoch) return -ESTALE;
        /* Ethernet test frame, not an IP/protocol implementation. Original
         * net_ring loopback carries these exact bytes through TX/RX bursts. */
        uint8_t expected[14 + sizeof(struct ker_session_probe)] = {0x02,0,0,0,0,1,0x02,0,0,0,0,2,0x88,0xb5};
        struct ker_session_probe probe = {.identity = *identity};
        if (*sequence == UINT64_MAX) return -EOVERFLOW;
        probe.identity.sequence = ++*sequence;
        probe.identity.command = KER_SESSION_PROBE;
        probe.identity.token = 0; probe.identity.status = 0;
        for (unsigned n = 0; n < sizeof(probe.payload); n++) probe.payload[n] = (uint8_t)(n + *sequence + identity->epoch);
        memcpy(expected + 14, &probe, sizeof(probe));
        rte_pktmbuf_reset(packet);
        void *data = rte_pktmbuf_append(packet, sizeof(expected));
        if (!data) return -ENOSPC;
        memcpy(data, expected, sizeof(expected));
        require_resident_alive(peer);
        cancelled = probe_control(control, deferred_probes);
        if (cancelled) { require_resident_alive(peer); return cancelled; }
        if (rte_eth_tx_burst(pmd_port, 0, &packet, 1) != 1) return -ENOBUFS;
        struct rte_mbuf *received = NULL;
        for (unsigned attempt = 0; attempt < 5000; attempt++) {
            require_resident_alive(peer);
            if (heartbeat_tick(fd, identity, control_sequence, peer, heartbeat) < 0) return -EIO;
            cancelled = probe_control(control, deferred_probes);
            if (cancelled) { require_resident_alive(peer); return cancelled; }
            if (rte_eth_rx_burst(pmd_port, 0, &received, 1)) break;
            poll(NULL, 0, 1);
        }
        if (!received) return -ETIMEDOUT;
        if (received != packet || received->nb_segs != 1 || received->pkt_len != sizeof(expected) ||
            received->data_len != sizeof(expected) || memcmp(rte_pktmbuf_mtod(received, void *), expected, sizeof(expected))) return -EBADMSG;
    }
    require_resident_alive(peer);
    int cancelled = probe_control(control, deferred_probes);
    if (cancelled) { require_resident_alive(peer); return cancelled; }
    if (rte_eth_stats_get(pmd_port, &after) || after.ipackets - before.ipackets != count ||
        after.opackets - before.opackets != count) return -EIO;
    return 0;
}
static int acquire_pmd(int fd, struct ker_session_message *identity, int resident,
    struct rte_mempool *pool, struct rte_mbuf *control_packet, struct rte_mbuf **packet,
    int *exception_fd, uint64_t *tx_lease_id, uint64_t *rx_lease_id)
{
    struct ker_session_message request=*identity;
    request.command = KER_SESSION_PMD_ACQUIRE; request.sequence=identity->sequence+1; request.status = 0;
    request.tx_lease_id=request.rx_lease_id=0;
    int result;
    *exception_fd = -1; *tx_lease_id=*rx_lease_id=0;
    if (ring_pmd == 2) result = exchange_exception_fd(fd, &request, resident, exception_fd);
    else result = exchange(fd, &request, resident);
    identity->sequence=request.sequence;
    if (result) return result;
    *tx_lease_id=request.tx_lease_id; *rx_lease_id=request.rx_lease_id;
    identity->tx_lease_id=identity->rx_lease_id=0;
    *packet = (struct rte_mbuf *)atomic_load_explicit(&directory->pmd_lease, memory_order_acquire);
    uint64_t key = 1 + (identity->slot * KER_SESSION_GENERATIONS + identity->generation) * KER_SESSION_PROCESSES + identity->process;
    return !known_object(*packet) || (*packet)->pool != pool || *packet == control_packet ||
        atomic_load_explicit(&directory->pmd_owner, memory_order_acquire) != key ||
        *tx_lease_id!=atomic_load_explicit(&directory->pmd_tx_lease_id,memory_order_acquire) ||
        *rx_lease_id!=atomic_load_explicit(&directory->pmd_rx_lease_id,memory_order_acquire) ||
        ((ring_pmd == 2) != (atomic_load_explicit(&directory->exception_ifindex, memory_order_acquire) != 0)) ? -EUCLEAN : 0;
}
/* Use the resident's serialized snapshot; separately reading the owner key and
 * a recycled slot epoch could combine two different grants. */
static int observe_pmd(int fd, struct ker_session_message *identity, int resident, struct ker_session_message *owner)
{
    struct ker_session_message request = {.magic = KER_SESSION_MAGIC, .version = KER_SESSION_VERSION,
        .command = KER_SESSION_PMD_STATUS, .sequence = ++identity->sequence};
    require_resident_alive(resident);
    if (send(fd, &request, sizeof(request), MSG_NOSIGNAL) != sizeof(request)) return -EIO;
    require_resident_alive(resident);
    if (recv(fd, owner, sizeof(*owner), MSG_TRUNC) != sizeof(*owner)) return -EIO;
    require_resident_alive(resident);
    if (owner->magic != request.magic || owner->version != request.version || owner->command != request.command ||
        owner->sequence != request.sequence || owner->session != identity->session || owner->status) return -EPROTO;
    if (!owner->token) return owner->epoch || owner->slot || owner->generation || owner->process ? -EPROTO : 0;
    if (!owner->epoch || !owner->slot || owner->slot >= KER_SESSION_SLOTS ||
        owner->generation >= KER_SESSION_GENERATIONS || owner->process >= KER_SESSION_PROCESSES) return -EPROTO;
    uint64_t key = 1 + (owner->slot * KER_SESSION_GENERATIONS + owner->generation) * KER_SESSION_PROCESSES + owner->process;
    return key == owner->token && ((ring_pmd == 2) ==
        (atomic_load_explicit(&directory->exception_ifindex, memory_order_acquire) != 0)) ? 0 : -EPROTO;
}
struct worker_heartbeat_context {
    int fd, resident;
    const struct ker_session_message *identity;
    uint64_t *sequence;
    struct worker_heartbeat *heartbeat;
};
static int service_worker_heartbeat(void *opaque)
{
    struct worker_heartbeat_context *context = opaque;
#ifdef KER_SESSION_TEST_HOOKS
    static bool handoff_pending_reported;
    if(context->heartbeat->pending && getenv("KER_SESSION_TEST_HANDOFF_PENDING_HB")) {
        if(!handoff_pending_reported) {
            handoff_pending_reported=true;
            printf("KER_SESSION_TEST_HANDOFF_HEARTBEAT_PENDING {\"pending\":true}\n"); fflush(stdout);
        }
        return 0;
    }
#endif
    int result=heartbeat_tick(context->fd, context->identity, context->sequence,
        context->resident, context->heartbeat);
#ifdef KER_SESSION_TEST_HOOKS
    if(result>=0 && context->heartbeat->pending && !handoff_pending_reported &&
        getenv("KER_SESSION_TEST_HANDOFF_PENDING_HB")) {
        handoff_pending_reported=true;
        printf("KER_SESSION_TEST_HANDOFF_HEARTBEAT_PENDING {\"pending\":true}\n"); fflush(stdout);
    }
#endif
    return result;
}
static int pump_worker_heartbeat_context(void *opaque)
{
    struct worker_heartbeat_context *context = opaque;
#ifdef KER_SESSION_TEST_HOOKS
    if(context->heartbeat->pending && getenv("KER_SESSION_TEST_HANDOFF_PENDING_HB")) return 0;
#endif
    return pump_worker_heartbeat(context->fd, context->heartbeat, context->resident);
}
#ifdef KER_SESSION_TEST_HOOKS
static int tc3_observer_loop(int control, int fd, int peer, struct rte_ring **channels,
    struct rte_mbuf *leased_packet, struct ker_session_message *identity,
    unsigned generation, unsigned process, struct rte_mbuf *device_packet, int exception_fd,
    uint64_t *control_sequence, struct worker_heartbeat *heartbeat)
{
    unsigned samples = 0, deferred = 0;
    uint64_t sequence = 0;
    struct ker_session_message owner;
    bool owns = device_packet != NULL;
    if (drain_worker_heartbeat(fd, heartbeat, peer, control) || observe_pmd(fd, identity, peer, &owner)) return 1;
    uint64_t key = 1 + (identity->slot * KER_SESSION_GENERATIONS + generation) * KER_SESSION_PROCESSES + process;
    if ((owner.token == key) != owns || (ring_pmd == 2 && owns != (exception_fd >= 0))) return 1;
    printf("KER_SESSION_TC3_OBSERVER_READY {\"pid\":%ld,\"epoch\":%llu,\"slot\":%llu,\"generation\":%u,\"process\":%u,\"owns_device\":%s,\"owner_epoch\":%llu,\"owner_generation\":%llu,\"owner_slot\":%llu,\"owner_process\":%llu,\"queue_owner_key\":%llu,\"exception_endpoint_owner_key\":%llu,\"exception_endpoint_fd\":%s,\"exception_ifindex\":%u}\n",
        (long)getpid(), (unsigned long long)identity->epoch, (unsigned long long)identity->slot, generation, process,
        owns ? "true" : "false", (unsigned long long)owner.epoch, (unsigned long long)owner.generation,
        (unsigned long long)owner.slot, (unsigned long long)owner.process, (unsigned long long)owner.token,
        (unsigned long long)(owner.token && ring_pmd == 2 ? owner.token : 0), exception_fd >= 0 ? "true" : "false",
        atomic_load_explicit(&directory->exception_ifindex, memory_order_acquire)); fflush(stdout);
    while (!stopping) {
        struct pollfd waiters[] = {{.fd=control,.events=POLLIN},{.fd=fd,.events=POLLIN},{.fd=peer,.events=POLLIN}};
        int ready = poll(waiters, 3, 100);
        if (ready < 0) { if (errno == EINTR) continue; return 1; }
        if (waiters[2].revents || dead(peer)) _Exit(125);
        if (waiters[1].revents) {
            int heartbeat_result = heartbeat->pending ? pump_worker_heartbeat(fd, heartbeat, peer) : -EPROTO;
            if (heartbeat_result <= 0 || heartbeat->pending) return 1;
        }
        if (heartbeat_tick(fd, identity, control_sequence, peer, heartbeat) < 0) return 1;
        if (!(waiters[0].revents & POLLIN)) continue;
        char command;
        if (read(control, &command, 1) != 1) return 1;
        if (command == 'Q') return 0;
        if (command == 'S') {
            if (samples >= 2 || drain_worker_heartbeat_after_command(fd, heartbeat, peer, control) ||
                observe_pmd(fd, identity, peer, &owner)) return 1;
            bool current_owner = owner.token == key;
            printf("KER_SESSION_TC3_SAMPLE {\"pid\":%ld,\"sample\":%u,\"epoch\":%llu,\"slot\":%llu,\"generation\":%u,\"process\":%u,\"nohw\":%u,\"owner_epoch\":%llu,\"owner_generation\":%llu,\"owner_slot\":%llu,\"owner_process\":%llu,\"queue_owner_key\":%llu,\"exception_endpoint_owner_key\":%llu,\"exception_endpoint_fd\":%s,\"exception_ifindex\":%u}\n",
                (long)getpid(), samples, (unsigned long long)identity->epoch, (unsigned long long)identity->slot,
                generation, process, current_owner ? 0u : 1u, (unsigned long long)owner.epoch,
                (unsigned long long)owner.generation, (unsigned long long)owner.slot,
                (unsigned long long)owner.process, (unsigned long long)owner.token,
                (unsigned long long)(owner.token && ring_pmd == 2 ? owner.token : 0),
                exception_fd >= 0 ? "true" : "false", atomic_load_explicit(&directory->exception_ifindex, memory_order_acquire)); fflush(stdout);
            samples++;
        } else if (command == 'P') {
            if (samples != 2) return 1;
            int status = drain_worker_heartbeat_after_command(fd, heartbeat, peer, control) ? -EIO :
                shared_probe(channels[0], channels[3], leased_packet, identity,
                    control, &deferred, 1, &sequence, peer, fd, control_sequence, heartbeat);
            if (status) return 1;
            printf("KER_SESSION_TC3_PROBE_DONE {\"pid\":%ld,\"epoch\":%llu,\"slot\":%llu,\"generation\":%u,\"process\":%u,\"count\":1,\"sequence\":%llu,\"primary_pid\":%u}\n",
                (long)getpid(), (unsigned long long)identity->epoch, (unsigned long long)identity->slot,
                generation, process, (unsigned long long)sequence, directory->primary_pid); fflush(stdout);
        } else return 1;
    }
    return 0;
}
#endif
static int secondary(const char *path, int control, int ticket, unsigned generation,
    unsigned process, unsigned probe_count, bool probe_only, bool standby,
#ifdef KER_SESSION_TEST_HOOKS
    bool generation_test, bool generation_detach_test, bool generation_tx_full_test,
    int directory_test_gate_fd, bool directory_test_replay_attached,
    bool generation_rings_test_replay,
#endif
    bool coordinate_probe, int packet_fd, int wire_fd, int mtu_fd, int argc, char **argv)
{
    int result = 1, fd = -1, peer = -1, exception_fd = -1;
#ifdef KER_SESSION_TEST_HOOKS
    bool detach_foreign_result=false;
    bool detach_nonowner_result=false;
#endif
    struct ker_worker_exception exception_bridge = {.fd=-1};
    bool initialized = false;
    struct ker_session_message message;
    uint64_t device_tx_lease_id=0, device_rx_lease_id=0;
    struct sockaddr_un address = {.sun_family = AF_UNIX};
    if (strlen(path) >= sizeof(address.sun_path)) { close(ticket); return 1; }
    strcpy(address.sun_path, path);
    fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
    if (fd < 0 || connect(fd, (void *)&address, sizeof(address))) goto cleanup;
    struct timeval timeout = {.tv_sec = 5};
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) ||
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout))) goto cleanup;
    socklen_t size = sizeof(peer);
    if (getsockopt(fd, SOL_SOCKET, SO_PEERPIDFD, &peer, &size) || size != sizeof(peer)) goto cleanup;
    struct ucred credential;
    size = sizeof(credential);
    if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &credential, &size) || size != sizeof(credential) || credential.uid != geteuid()) goto cleanup;
    /* Connect and publish this exact pidfd before reading the master ticket.
     * PEER_RESERVE can then bind its one-shot role to this child, rather than
     * treating the capability as a bearer token. */
    if (receive_exact(ticket, &message, sizeof(message))) goto cleanup;
    close(ticket); ticket=-1;
    if (message.magic != KER_SESSION_MAGIC || message.version != KER_SESSION_VERSION || message.status ||
        message.command != KER_SESSION_MASTER || !message.session || !message.epoch || !message.token ||
        !message.slot || message.slot >= KER_SESSION_SLOTS) goto cleanup;
    message.command = KER_SESSION_RESERVE; message.sequence = 1;
    message.generation = generation; message.process = process;
    int status = exchange(fd, &message, peer);
    if (status) { fprintf(stderr, "ker session reserve: %d\n", status); goto cleanup; }
#ifdef KER_SESSION_TEST_HOOKS
    if (directory_test_gate_fd >= 0) {
        char release;
        printf("KER_SESSION_TEST_RESERVED\n"); fflush(stdout);
        if (receive_exact(directory_test_gate_fd, &release, 1) || release != 'G') goto cleanup;
        close(directory_test_gate_fd); directory_test_gate_fd = -1;
    }
#endif
    /* Register the process lifetime before EAL starts borrowing shared data. */
    if (rte_eal_init(argc, argv) < 0) goto cleanup;
    initialized = true;
    if (rte_eal_process_type() != RTE_PROC_SECONDARY) goto cleanup;
    const struct ker_session_directory *d = NULL;
    if (session_directory_lookup_validate(&message, (uint32_t)credential.pid, &d)) {
        fprintf(stderr, "ker session: shared directory lookup/validation failed\n");
        goto cleanup;
    }
    directory = (struct ker_session_directory *)d;
    if (d->ring_pmd != ring_pmd) goto cleanup;
    if (ring_pmd && (rte_eth_dev_get_port_by_name(ring_pmd == 2 ? KER_SESSION_PACKET_PORT : "net_ring_ker", &pmd_port) || rte_eth_dev_count_avail() != 1)) goto cleanup;
    struct rte_mempool *pool = rte_mempool_lookup(KER_SESSION_POOL);
    if (!pool || pool->size != KER_SESSION_OBJECTS || pool->cache_size) goto cleanup;
    if (rte_mempool_obj_iter(pool, remember_object, NULL) != KER_SESSION_OBJECTS) goto cleanup;
    bool peer_only=message.capability!=0;
    if (peer_only && (!generation_rings_enabled
#ifdef KER_SESSION_TEST_HOOKS
        || generation_test
#endif
        )) goto cleanup;
    if (generation_rings_enabled && !peer_only && ker_generation_rings_attach(d->session,1,2,pool,&generation_rings)) goto cleanup;
#ifdef KER_SESSION_TEST_HOOKS
    if (generation_rings_test_replay) {
        if (!generation_rings || peer_only || ker_generation_rings_test_replay(generation_rings)) goto cleanup;
        printf("KER_SESSION_TEST_GENERATION_REPLAY {\"directory_same\":true,\"rings_same\":true,\"session\":%llu,\"ports\":1,\"queues\":2}\n",
            (unsigned long long)message.session); fflush(stdout);
    }
#endif
    struct rte_mbuf *leased_packet = (struct rte_mbuf *)atomic_load_explicit(
        &d->lease[message.slot][generation][process], memory_order_acquire);
    if (!known_object(leased_packet) || leased_packet->pool != pool) goto cleanup;
    int validated_rings = validate_shared_rings();
    if (validated_rings != (int)QUEUES) goto cleanup;
    char names[KER_SESSION_CHANNELS][RTE_RING_NAMESIZE];
    struct rte_ring *channels[KER_SESSION_CHANNELS];
    for (unsigned c = 0; c < KER_SESSION_CHANNELS; c++) {
        if (ring_name(names[c], sizeof(names[c]), (unsigned)message.slot, generation, process, c)) goto cleanup;
        struct rte_ring *ring = rte_ring_lookup(names[c]);
        if (!ring || rte_ring_get_capacity(ring) != KER_SESSION_CAPACITY) goto cleanup;
        channels[c] = ring;
    }
    message.command = KER_SESSION_ATTACHED; message.sequence++;
    if (exchange(fd, &message, peer)) goto cleanup;
#ifdef KER_SESSION_TEST_HOOKS
    if (directory_test_replay_attached) {
        if (exchange(fd, &message, peer)) goto cleanup;
        printf("KER_SESSION_TEST_ATTACHED_REPLAY {\"sequence\":%llu,\"slot\":%llu,\"epoch\":%llu}\n",
            (unsigned long long)message.sequence,(unsigned long long)message.slot,(unsigned long long)message.epoch); fflush(stdout);
    }
#endif
    printf("KER_SESSION_ATTACHED {\"stage\":\"shared-control\",\"pid\":%ld,\"master\":%ld,\"epoch\":%llu,\"slot\":%llu,\"generation\":%u,\"process\":%u,\"peer_only\":%s,\"validated_rings\":%u,\"rings\":[\"%s\",\"%s\",\"%s\",\"%s\"]}\n",
        (long)getpid(), (long)getppid(), (unsigned long long)message.epoch,
        (unsigned long long)message.slot, generation, process, peer_only?"true":"false",
        peer_only?0U:(unsigned)validated_rings, names[0], names[1], names[2], names[3]); fflush(stdout);
    if (coordinate_probe) {
        struct ker_session_message resolved;
        char target[RTE_RING_NAMESIZE], slot_zero[RTE_RING_NAMESIZE];
        if (coordinate_query(fd, message.sequence + 1, &resolved) ||
            resolved.session != message.session || resolved.epoch != message.epoch ||
            resolved.slot != message.slot || resolved.generation != generation ||
            resolved.process != process || resolved.generation != 0 ||
            ring_name(target, sizeof(target), (unsigned)resolved.slot,
                (unsigned)resolved.generation, 1, 0) ||
            ring_name(slot_zero, sizeof(slot_zero), 0, (unsigned)resolved.generation, 1, 0) ||
            !rte_ring_lookup(target) || !strcmp(target, slot_zero)) goto cleanup;
        printf("KER_SESSION_COORDINATE {\"query_sent\":true,\"query_completed\":true,\"session\":%llu,\"epoch\":%llu,\"slot\":%llu,\"generation\":%u,\"process\":%u,\"target_ring\":\"%s\",\"target_found\":true,\"slot_zero_ring\":\"%s\"}\n",
            (unsigned long long)resolved.session, (unsigned long long)resolved.epoch,
            (unsigned long long)resolved.slot, generation, process, target, slot_zero);
        fflush(stdout);
        /* Keep the exact attached EAL worker alive until the test owner closes
         * its relay input, allowing the harness to open and observe its pidfd. */
        char release;
        ssize_t released;
        do released = read(control, &release, 1); while (released < 0 && errno == EINTR && !stopping);
        if (released != 0) goto cleanup;
        result = 0;
        goto cleanup;
    }
    bool drain_authorized = false, control_open = true, reload_active = false;
    struct worker_heartbeat heartbeat = {0};
    if (worker_request(fd, &message, &message.sequence, KER_SESSION_HEARTBEAT, 0, peer, &message)) goto cleanup;
    heartbeat.last_ack_ms = monotonic_ms();
#ifdef KER_SESSION_TEST_HOOKS
    if (getenv("KER_SESSION_TEST_DQ_PENDING_HB")) {
        fprintf(stderr, "KER_SESSION_TEST_DQ_INITIAL_HEARTBEAT_ACKED {\"acked\":true}\n");
        fflush(stderr);
    }
#endif
    struct worker_heartbeat_context heartbeat_context = {.fd=fd,.resident=peer,
        .identity=&message,.sequence=&message.sequence,.heartbeat=&heartbeat};
    struct rte_mbuf *device_packet = NULL;
    if (ring_pmd&&!peer_only) {
        int acquired = acquire_pmd(fd, &message, peer, pool, leased_packet, &device_packet, &exception_fd,
            &device_tx_lease_id,&device_rx_lease_id);
        if (acquired && (!standby || acquired != -EBUSY)) {
            fprintf(stderr, "ker session: PMD consumer grant rejected %d\n", acquired); goto cleanup;
        }
        uint64_t key = acquired ? 0 : 1 + (message.slot * KER_SESSION_GENERATIONS + generation) * KER_SESSION_PROCESSES + process;
        printf("%s {\"pid\":%ld,\"epoch\":%llu,\"slot\":%llu,\"generation\":%u,\"process\":%u,\"queue_owner_key\":%llu,\"exception_endpoint_owner_key\":%llu,\"exception_endpoint_ifindex\":%u,\"exception_endpoint_fd\":%s}\n",
            acquired ? "KER_SESSION_PMD_STANDBY" : "KER_SESSION_PMD_GRANTED",
            (long)getpid(), (unsigned long long)message.epoch, (unsigned long long)message.slot, generation, process,
            (unsigned long long)key, (unsigned long long)(ring_pmd == 2 ? key : 0),
            atomic_load_explicit(&directory->exception_ifindex, memory_order_acquire), exception_fd >= 0 ? "true" : "false"); fflush(stdout);
    }
#ifdef KER_SESSION_TEST_HOOKS
    if (ring_pmd == 2 && tc3_observer) {
        bool endpoint_granted = exception_fd >= 0;
        if (device_packet) {
            char exception_iface[IFNAMSIZ], exception_ring[RTE_RING_NAMESIZE];
            snprintf(exception_iface, sizeof(exception_iface), "kex%08x", (unsigned)directory->session);
            snprintf(exception_ring, sizeof(exception_ring), "ker_se_%08x", (unsigned)directory->session);
            if (ker_worker_exception_attach_session(&exception_bridge, exception_fd, exception_iface, exception_ring,
                    pool, atomic_load_explicit(&directory->exception_ifindex, memory_order_acquire),
                    (struct rte_mbuf *)atomic_load_explicit(&directory->pmd_rx_lease, memory_order_acquire),
                    &directory->pmd_exception_phase)) goto cleanup;
            exception_fd = -1;
            struct rte_mbuf *rx = (struct rte_mbuf *)atomic_load_explicit(&directory->pmd_rx_lease, memory_order_acquire);
            if (!known_object(rx) || rx == device_packet || rx == leased_packet || rx->pool != pool) goto cleanup;
        }
        result = tc3_observer_loop(control, fd, peer, channels, leased_packet, &message,
            generation, process, device_packet, endpoint_granted ? 1 : -1,
            &message.sequence, &heartbeat);
        goto cleanup;
    }
#endif
    if (ring_pmd == 2&&!peer_only) {
        /* A paired standby owns only its coordinate control lease. Do not
         * inspect data leases or touch either device queue before admission.
         * One P request receives exactly one outcome, so the supervisor never
         * leaves a retry byte pending when the packet loop takes control. */
#ifdef KER_SESSION_TEST_HOOKS
        bool test_pending_heartbeat_done = false;
        bool test_pending_heartbeat_reported = false;
#endif
        while (!device_packet && !stopping) {
            if (heartbeat_tick(fd, &message, &message.sequence, peer, &heartbeat) < 0) goto cleanup;
            struct pollfd waiters[] = {{.fd = control, .events = POLLIN},
                {.fd = fd, .events = POLLIN}, {.fd = peer, .events = POLLIN}};
            int ready = poll(waiters, 3, 100);
            if (ready < 0) { if (errno == EINTR) continue; goto cleanup; }
            if (waiters[2].revents || dead(peer)) {
                fprintf(stderr, "ker session: primary process exited\n"); _Exit(125);
            }
            if (waiters[1].revents) {
                int heartbeat_result = heartbeat.pending ? pump_worker_heartbeat(fd, &heartbeat, peer) : -EPROTO;
                if (heartbeat_result <= 0 || heartbeat.pending) goto cleanup;
            }
            if (!waiters[0].revents) continue;
            char command;
            if (!(waiters[0].revents & POLLIN) || read(control, &command, 1) != 1 || command != 'P') {
                result = 0; goto cleanup;
            }
#ifdef KER_SESSION_TEST_HOOKS
            /* Deterministically leave a real heartbeat ACK queued at the
             * PMD exchange boundary. Without the drain below, acquire_pmd()
             * would consume this ACK as its own response. */
            if (!test_pending_heartbeat_done && getenv("KER_SESSION_TEST_PENDING_HB_BEFORE_PMD")) {
                test_pending_heartbeat_done = true;
                if (!heartbeat.pending) {
                    heartbeat.last_ack_ms = 0;
                    if (heartbeat_tick(fd, &message, &message.sequence, peer, &heartbeat) < 0 ||
                        !heartbeat.pending) goto cleanup;
                }
                struct pollfd ack = {.fd = fd, .events = POLLIN};
                int ack_ready;
                do ack_ready = poll(&ack, 1, 1000); while (ack_ready < 0 && errno == EINTR);
                if (ack_ready != 1 || !(ack.revents & POLLIN)) goto cleanup;
                fprintf(stderr, "KER_SESSION_TEST_PENDING_HB_QUEUED\n");
            }
#endif
            if (drain_worker_heartbeat_after_command(fd, &heartbeat, peer, control)) goto cleanup;
#ifdef KER_SESSION_TEST_HOOKS
            if (test_pending_heartbeat_done && !test_pending_heartbeat_reported) {
                test_pending_heartbeat_reported = true;
                fprintf(stderr, "KER_SESSION_TEST_PENDING_HB_DRAINED\n");
            }
#endif
            int acquired = acquire_pmd(fd, &message, peer, pool, leased_packet, &device_packet, &exception_fd,
                &device_tx_lease_id,&device_rx_lease_id);
            if (acquired && acquired != -EBUSY) {
                fprintf(stderr, "ker session: standby PMD acquisition failed %d\n", acquired); goto cleanup;
            }
            uint64_t owner_key = acquired ? 0 : 1 + (message.slot * KER_SESSION_GENERATIONS + generation) * KER_SESSION_PROCESSES + process;
            printf("%s {\"pid\":%ld,\"epoch\":%llu,\"slot\":%llu,\"generation\":%u,\"process\":%u,\"queue_owner_key\":%llu,\"exception_endpoint_owner_key\":%llu,\"exception_endpoint_ifindex\":%u,\"exception_endpoint_fd\":%s}\n",
                acquired ? "KER_SESSION_PMD_STANDBY" : "KER_SESSION_PMD_GRANTED",
                (long)getpid(), (unsigned long long)message.epoch, (unsigned long long)message.slot,
                generation, process, (unsigned long long)owner_key, (unsigned long long)(owner_key && ring_pmd == 2 ? owner_key : 0),
                atomic_load_explicit(&directory->exception_ifindex, memory_order_acquire), exception_fd >= 0 ? "true" : "false"); fflush(stdout);
        }
        if (!device_packet) { result = 0; goto cleanup; }
        char exception_iface[IFNAMSIZ], exception_ring[RTE_RING_NAMESIZE];
        snprintf(exception_iface, sizeof(exception_iface), "kex%08x", (unsigned)directory->session);
        snprintf(exception_ring, sizeof(exception_ring), "ker_se_%08x", (unsigned)directory->session);
        if (ker_worker_exception_attach_session(&exception_bridge, exception_fd, exception_iface,
                exception_ring, pool, atomic_load_explicit(&directory->exception_ifindex, memory_order_acquire),
                (struct rte_mbuf *)atomic_load_explicit(&directory->pmd_rx_lease, memory_order_acquire), &directory->pmd_exception_phase)) goto cleanup;
        exception_fd=-1; /* bridge owns the received CLOEXEC descriptor */
        struct rte_mbuf *rx_packet = (struct rte_mbuf *)atomic_load_explicit(&directory->pmd_rx_lease, memory_order_acquire);
        if (!known_object(rx_packet) || rx_packet == device_packet || rx_packet == leased_packet || rx_packet->pool != pool) goto cleanup;
        uint64_t key = 1 + (message.slot * KER_SESSION_GENERATIONS + generation) * KER_SESSION_PROCESSES + process;
        struct ker_session_packet_stats packet_stats={0};
#ifdef KER_SESSION_TEST_HOOKS
        struct generation_frame_drain_context frame_drain_context={.rings=generation_rings,
            .identity={.session=message.session,.epoch=message.epoch,.slot=(uint32_t)message.slot,
                .generation=generation,.process=process,.pid=(uint32_t)getpid()}};
#endif
        int packet_result=ker_session_packet_loop(pmd_port,packet_fd,wire_fd,mtu_fd,control,fd,peer,
            &directory->pmd_owner,key,device_packet,rx_packet,&exception_bridge,&stopping,
            service_worker_heartbeat,pump_worker_heartbeat_context,&heartbeat_context,
#ifdef KER_SESSION_TEST_HOOKS
            generation_frame_drain_test?generation_frame_drain_control:NULL,
            generation_frame_drain_test?&frame_drain_context:NULL,
#endif
            &packet_stats);
        if(packet_result<0){result=1;goto cleanup;}
        while(packet_result==1) {
            uint64_t tx_id=device_tx_lease_id;
            uint64_t rx_id=device_rx_lease_id;
            /* The packet loop's final nonblocking ACK pump can leave a real
             * heartbeat outstanding. Finish it before PREPARE so that its
             * reply cannot be mistaken for the synchronous handoff response. */
#ifdef KER_SESSION_TEST_HOOKS
            bool pending_handoff_heartbeat=heartbeat.pending;
#endif
            if(drain_worker_heartbeat_after_command(fd,&heartbeat,peer,control_open?control:-1))goto cleanup;
#ifdef KER_SESSION_TEST_HOOKS
            if(pending_handoff_heartbeat && getenv("KER_SESSION_TEST_HANDOFF_PENDING_HB")) {
                printf("KER_SESSION_TEST_HANDOFF_HEARTBEAT_DRAINED {\"pending\":false}\n"); fflush(stdout);
            }
#endif
#ifdef KER_SESSION_TEST_HOOKS
            if(getenv("KER_SESSION_TEST_HANDOFF_REPLAY_PREPARE") &&
                worker_handoff_expect_prepare_rejected(fd,&message,&message.sequence,peer,tx_id,rx_id)) _Exit(125);
#endif
            struct ker_session_message prepared;
            int handoff=worker_handoff_request(fd,&message,&message.sequence,peer,
                KER_SESSION_PMD_HANDOFF_PREPARE,key,0,tx_id,rx_id,&prepared);
            if(handoff){
                if(handoff==-EBUSY||handoff==-ENOENT||handoff==-EPERM){
#ifdef KER_SESSION_TEST_HOOKS
                    if(getenv("KER_SESSION_TEST_HANDOFF_PREPARE_REJECT")) {
                        printf("KER_SESSION_TEST_HANDOFF_PREPARE_RESUMED {\"status\":%d}\n",handoff); fflush(stdout);
                    }
#endif
                    struct ker_session_packet_stats resumed_stats={0};
                    int resumed=ker_session_packet_loop(pmd_port,packet_fd,wire_fd,mtu_fd,control,fd,peer,
                        &directory->pmd_owner,key,device_packet,rx_packet,&exception_bridge,&stopping,
                        service_worker_heartbeat,pump_worker_heartbeat_context,&heartbeat_context,
#ifdef KER_SESSION_TEST_HOOKS
                        generation_frame_drain_test?generation_frame_drain_control:NULL,
                        generation_frame_drain_test?&frame_drain_context:NULL,
#endif
                        &resumed_stats);
                    if(resumed<0){result=1;goto cleanup;}
                    if(merge_packet_stats(&packet_stats,&resumed_stats))_Exit(125);
                    if(resumed==1) continue; /* A queued H is a distinct caller handoff request. */
                    printf("KER_SESSION_PACKET_DONE {\"tx\":%llu,\"rx\":%llu,\"to_wire\":%llu,\"from_wire\":%llu,\"exception_to_wire\":%llu,\"exception_from_wire\":%llu,\"exception_to_native\":%llu,\"fragment_to_native\":%llu,\"exception_endpoint_owner_key\":%llu,\"retained\":%u,\"status\":0}\n",
                        (unsigned long long)packet_stats.tx,(unsigned long long)packet_stats.rx,
                        (unsigned long long)packet_stats.to_wire,(unsigned long long)packet_stats.from_wire,
                        (unsigned long long)packet_stats.exception_to_wire,(unsigned long long)packet_stats.exception_from_wire,
                        (unsigned long long)packet_stats.exception_to_native,(unsigned long long)packet_stats.fragment_to_native,
                        (unsigned long long)key,packet_stats.retained); fflush(stdout);
                    result=0;goto cleanup;
                }
                _Exit(125);
            }
            uint64_t owner_key=prepared.token,capability=prepared.capability;
            unsigned successor_slot=(unsigned)prepared.slot,successor_generation=(unsigned)prepared.generation;
            tx_id=prepared.tx_lease_id; rx_id=prepared.rx_lease_id;
#ifdef KER_SESSION_TEST_HOOKS
            const char *handoff_mode=getenv("KER_SESSION_TEST_HANDOFF_MODE");
            if(handoff_mode && worker_test_handoff_prepared(control,fd,peer,&message,&message.sequence,
                    &heartbeat,handoff_mode))_Exit(125);
#endif
            if(owner_key!=key||!capability||!tx_id||(ring_pmd==2&&!rx_id)||
                atomic_load_explicit(&directory->pmd_lease,memory_order_acquire)!=(uintptr_t)device_packet||
                (ring_pmd==2&&atomic_load_explicit(&directory->pmd_rx_lease,memory_order_acquire)!=(uintptr_t)rx_packet))_Exit(125);
            if(exception_bridge.session_busy||exception_bridge.session_tx_pending||
                exception_bridge.session_native_pending||exception_bridge.session_to_native||
                atomic_load_explicit(&directory->pmd_exception_phase,memory_order_acquire)!=0||
                !exception_bridge.pending||!rte_ring_empty(exception_bridge.pending))_Exit(125);
            if(ker_worker_exception_close(&exception_bridge))_Exit(125);
            close(wire_fd); close(mtu_fd); wire_fd=mtu_fd=-1;
            device_packet=NULL; rx_packet=NULL; exception_fd=-1;
#ifdef KER_SESSION_TEST_HOOKS
            if(getenv("KER_SESSION_TEST_HANDOFF_MODE")) {
                printf("KER_SESSION_TEST_HANDOFF_FDS_CLOSED {\"mode\":\"%s\"}\n",
                    getenv("KER_SESSION_TEST_HANDOFF_MODE")); fflush(stdout);
            }
#endif
            struct ker_session_message quiesced;
            if(worker_handoff_request(fd,&message,&message.sequence,peer,
                KER_SESSION_PMD_HANDOFF_QUIESCED,owner_key,capability,tx_id,rx_id,&quiesced) ||
                quiesced.slot!=successor_slot || quiesced.generation!=successor_generation ||
                quiesced.process!=message.process || quiesced.epoch!=message.epoch)_Exit(125);
            /* The resident's successful QUIESCED reply is the serialized
             * commit proof. Do not sample the shared owner/lease atomics here:
             * the successor may already be publishing its replacement grant. */
            device_tx_lease_id=device_rx_lease_id=0;
            printf("KER_SESSION_PMD_PARKED {\"pid\":%ld,\"old_owner_key\":%llu,\"successor_slot\":%u,\"successor_generation\":%u,\"commit\":\"resident-quiesced\"}\n",
                (long)getpid(),(unsigned long long)key,successor_slot,successor_generation); fflush(stdout);
            if(parked_owner_wait(control,packet_fd,fd,peer,&message,&message.sequence,
                    capability,&heartbeat,generation_rings))_Exit(125);
            printf("KER_SESSION_PACKET_DONE {\"tx\":%llu,\"rx\":%llu,\"to_wire\":%llu,\"from_wire\":%llu,\"exception_to_wire\":%llu,\"exception_from_wire\":%llu,\"exception_to_native\":%llu,\"fragment_to_native\":%llu,\"exception_endpoint_owner_key\":%llu,\"retained\":0,\"status\":0}\n",
                (unsigned long long)packet_stats.tx,(unsigned long long)packet_stats.rx,
                (unsigned long long)packet_stats.to_wire,(unsigned long long)packet_stats.from_wire,
                (unsigned long long)packet_stats.exception_to_wire,(unsigned long long)packet_stats.exception_from_wire,
                (unsigned long long)packet_stats.exception_to_native,(unsigned long long)packet_stats.fragment_to_native,
                (unsigned long long)key); fflush(stdout);
            result=0; goto cleanup;
        }
        result=0; goto cleanup;
    }
    uint64_t device_sequence = 0;
    uint64_t probe_sequence = 0;
    unsigned deferred_probes = 0;
#ifdef KER_SESSION_TEST_HOOKS
    unsigned generation_test_step_index=generation_detach_test?3U:0U;
#endif
    bool probe_pending = probe_only;
    /* Only a consumed P owns a response that must finish before a queued
     * control byte. Startup --probe-only work remains cancellable. */
    bool probe_from_consumed_command = false;
#ifdef KER_SESSION_TEST_HOOKS
    bool test_dq_pending_reported = false;
    bool test_probe_only_started = false;
#endif
    while (!stopping) {
        if (heartbeat_tick(fd, &message, &message.sequence, peer, &heartbeat) < 0) {
            fprintf(stderr, "ker session: worker heartbeat failed\n"); goto cleanup;
        }
#ifdef KER_SESSION_TEST_HOOKS
        if (!test_dq_pending_reported && heartbeat.pending && getenv("KER_SESSION_TEST_DQ_PENDING_HB")) {
            test_dq_pending_reported = true;
            fprintf(stderr, "KER_SESSION_TEST_DQ_HEARTBEAT_PENDING {\"pending\":true}\n");
            fflush(stderr);
        }
#endif
        if (probe_pending) {
            bool consumed_probe = probe_from_consumed_command;
#ifdef KER_SESSION_TEST_HOOKS
            if (probe_only && getenv("KER_SESSION_TEST_PROBE_ONLY_CANCEL") && !test_probe_only_started) {
                test_probe_only_started = true;
                fprintf(stderr, "KER_SESSION_TEST_PROBE_ONLY_STARTED {\"automatic\":true}\n");
                fflush(stderr);
            }
#endif
            int probe_result = shared_probe(channels[0], channels[3], leased_packet, &message,
                control, &deferred_probes, probe_count, &probe_sequence, peer, fd,
                &message.sequence, &heartbeat);
#ifdef KER_SESSION_TEST_HOOKS
            if (probe_result == -ECANCELED && probe_only && getenv("KER_SESSION_TEST_PROBE_ONLY_CANCEL")) {
                fprintf(stderr, "KER_SESSION_TEST_PROBE_ONLY_CANCELLED {\"status\":0}\n");
                fflush(stderr);
            }
#endif
            if (probe_result == -ECANCELED) { result = 0; goto cleanup; }
            if (probe_result) { fprintf(stderr, "ker session: shared probe failed %d\n", probe_result); goto cleanup; }
            printf("KER_SESSION_PROBED {\"epoch\":%llu,\"slot\":%llu,\"generation\":%u,\"process\":%u,\"count\":%u,\"sequence\":%llu,\"primary_pid\":%u,\"payload_bytes\":%u}\n",
                (unsigned long long)message.epoch, (unsigned long long)message.slot,
                generation, process, probe_count, (unsigned long long)probe_sequence,
                directory->primary_pid, KER_SESSION_PROBE_PAYLOAD); fflush(stdout);
            if (ring_pmd && standby && !peer_only) {
                if (!device_packet) {
                    int heartbeat_result = consumed_probe ?
                        drain_worker_heartbeat_after_command(fd, &heartbeat, peer, control_open ? control : -1) :
                        drain_worker_heartbeat(fd, &heartbeat, peer, control_open ? control : -1);
                    if (heartbeat_result) goto cleanup;
#ifdef KER_SESSION_TEST_HOOKS
                    if (getenv("KER_SESSION_TEST_DQ_PENDING_HB")) {
                        fprintf(stderr, "KER_SESSION_TEST_DQ_PROBE_PMD_ACQUIRE {\"consumed_p\":%s}\n",
                            consumed_probe ? "true" : "false");
                        fflush(stderr);
                    }
#endif
                    int acquired = acquire_pmd(fd, &message, peer, pool, leased_packet, &device_packet, &exception_fd,
                        &device_tx_lease_id,&device_rx_lease_id);
                    if (acquired && acquired != -EBUSY) {
                        fprintf(stderr, "ker session: standby PMD acquisition failed %d\n", acquired); goto cleanup;
                    }
                }
                struct ker_session_message owner;
                int heartbeat_result = consumed_probe ?
                    drain_worker_heartbeat_after_command(fd, &heartbeat, peer, control_open ? control : -1) :
                    drain_worker_heartbeat(fd, &heartbeat, peer, control_open ? control : -1);
                if (heartbeat_result || observe_pmd(fd, &message, peer, &owner)) goto cleanup;
                bool owns = owner.epoch == message.epoch && owner.slot == message.slot &&
                    owner.generation == message.generation && owner.process == message.process;
                if (owns != (device_packet != NULL)) goto cleanup;
                printf("KER_SESSION_PMD_SAMPLED {\"pid\":%ld,\"epoch\":%llu,\"slot\":%llu,\"owns_device\":%s,\"owner_epoch\":%llu,\"owner_generation\":%llu,\"owner_slot\":%llu,\"owner_process\":%llu,\"queue_owner_key\":%llu,\"exception_endpoint_owner_key\":%llu,\"exception_endpoint_ifindex\":%u,\"sequence\":%llu}\n",
                    (long)getpid(), (unsigned long long)message.epoch, (unsigned long long)message.slot,
                    owns ? "true" : "false", (unsigned long long)owner.epoch, (unsigned long long)owner.generation,
                    (unsigned long long)owner.slot, (unsigned long long)owner.process,
                    (unsigned long long)owner.token, (unsigned long long)(ring_pmd == 2 ? owner.token : 0),
                    atomic_load_explicit(&directory->exception_ifindex, memory_order_acquire),
                    (unsigned long long)probe_sequence); fflush(stdout);
            }
            if (ring_pmd && device_packet && probe_count) {
                int status = pmd_roundtrips(device_packet, &message, probe_count, &device_sequence,
                    peer, control, &deferred_probes, fd, &message.sequence, &heartbeat);
                if (status == -ECANCELED) { result = 0; goto cleanup; }
                if (status) { fprintf(stderr, "ker session: PMD roundtrip failed %d\n", status); goto cleanup; }
                printf("KER_SESSION_PMD_PROBED {\"pid\":%ld,\"sequence\":%llu,\"count\":%u,\"frame_bytes\":%zu}\n",
                    (long)getpid(), (unsigned long long)device_sequence, probe_count, 14 + sizeof(struct ker_session_probe)); fflush(stdout);
            }
            probe_pending = false;
            probe_from_consumed_command = false;
            if (probe_only) break;
            if (deferred_probes) {
                deferred_probes--;
                probe_pending = true;
                probe_from_consumed_command = true;
                continue;
            }
        }
        struct pollfd fds[] = {{.fd = control_open ? control : -1, .events = POLLIN},
            {.fd = fd, .events = POLLIN}, {.fd = peer, .events = POLLIN}};
        int ready = poll(fds, 3, 100);
        if (ready < 0) { if (errno == EINTR) continue; goto cleanup; }
        if (fds[2].revents) { fprintf(stderr, "ker session: primary process exited\n"); _Exit(125); }
        if (fds[1].revents) {
            require_resident_alive(peer);
            int heartbeat_result = heartbeat.pending ? pump_worker_heartbeat(fd, &heartbeat, peer) : -EPROTO;
            if (heartbeat_result <= 0 || heartbeat.pending) {
                fprintf(stderr, "ker session: unexpected resident data\n"); goto cleanup;
            }
        }
        if (fds[0].revents) {
            /* A control event must not hide a concurrent resident death. */
            if (dead(peer)) { fprintf(stderr, "ker session: primary process exited\n"); _Exit(125); }
            char command;
            ssize_t count = (fds[0].revents & POLLIN) ? read(control, &command, 1) : 0;
            if (count == 0 || (fds[0].revents & (POLLHUP | POLLERR | POLLNVAL))) {
                control_open = false;
                if (!drain_authorized) break;
            } else if (count == 1 && command == 'D') {
#ifdef KER_SESSION_TEST_HOOKS
                if (getenv("KER_SESSION_TEST_DQ_PENDING_HB")) {
                    fprintf(stderr, "KER_SESSION_TEST_DQ_D_CONSUMED {\"command\":\"D\"}\n");
                    fflush(stderr);
                }
#endif
                if (drain_worker_heartbeat_after_command(fd, &heartbeat, peer, control_open ? control : -1)) goto cleanup;
                if (!drain_authorized && worker_request(fd, &message, &message.sequence,
                        KER_SESSION_DRAIN_MODE, 0, peer, &message)) goto cleanup;
                drain_authorized = true;
                printf("KER_SESSION_DRAIN_MODE {\"epoch\":%llu,\"slot\":%llu,\"generation\":%u,\"process\":%u}\n",
                    (unsigned long long)message.epoch, (unsigned long long)message.slot,
                    generation, process); fflush(stdout);
            } else if (count == 1 && command == 'R') {
                reload_active = !reload_active;
                printf("KER_SESSION_RELOAD_ACTIVE {\"value\":%s}\n", reload_active ? "true" : "false"); fflush(stdout);
            } else if (count == 1 && command == 'Q') {
                struct ker_session_message peer_status;
                if (drain_worker_heartbeat_after_command(fd, &heartbeat, peer, control_open ? control : -1) ||
                    worker_request(fd, &message, &message.sequence, KER_SESSION_PEER_STATUS,
                        reload_active, peer, &peer_status)) goto cleanup;
                uint64_t mirror_epoch, mirror_generation, mirror_draining;
                if (ker_session_peer_read(&directory->peer_version[message.slot][generation][process],
                    &directory->peer_epoch[message.slot][generation][process],
                    &directory->peer_generation[message.slot][generation][process],
                    &directory->peer_draining[message.slot][generation][process],
                    &mirror_epoch, &mirror_generation, &mirror_draining)) goto cleanup;
                printf("KER_SESSION_PEER {\"epoch\":%llu,\"generation\":%llu,\"draining\":%s,\"mirror_epoch\":%llu,\"mirror_generation\":%llu,\"mirror_draining\":%s}\n",
                    (unsigned long long)peer_status.epoch, (unsigned long long)peer_status.generation,
                    peer_status.token ? "true" : "false", (unsigned long long)mirror_epoch,
                    (unsigned long long)mirror_generation, mirror_draining ? "true" : "false"); fflush(stdout);
            } else if (count == 1 && command == 'P' && (probe_count || standby)) {
                probe_pending = true;
                probe_from_consumed_command = true;
#ifdef KER_SESSION_TEST_HOOKS
                if (getenv("KER_SESSION_TEST_DQ_PENDING_HB")) {
                    fprintf(stderr, "KER_SESSION_TEST_DQ_P_CONSUMED {\"command\":\"P\"}\n");
                    fflush(stderr);
                }
#endif
            }
#ifdef KER_SESSION_TEST_HOOKS
            else if (count == 1 && command == 'h' && getenv("KER_SESSION_TEST_DQ_PENDING_HB")) {
                heartbeat.last_ack_ms = 0;
                fprintf(stderr, "KER_SESSION_TEST_DQ_HEARTBEAT_REQUESTED {\"real_tick\":true}\n");
                fflush(stderr);
            }
            else if (count == 1 && command == 'G' && (generation_test||generation_detach_test||generation_tx_full_test)) {
                struct ker_generation_identity identity = {.session=message.session,.epoch=message.epoch,
                    .slot=(uint32_t)message.slot,.generation=generation,.process=process,.pid=(uint32_t)getpid()};
                if(peer_only||!generation_rings)goto cleanup;
                int status = generation_test_step(generation_rings,&identity,pool,generation_test_step_index,
                    generation_detach_test,detach_foreign_result,detach_nonowner_result,generation_empty_cleanup_test,
                    generation_tx_full_test);
                if (status) { fprintf(stderr,"ker session: generation adapter probe failed step=%u status=%d\n",generation_test_step_index,status); result=1; goto cleanup; }
                printf("KER_GENERATION_PROBED {\"generation\":%u,\"step\":%u}\n",generation,generation_test_step_index++); fflush(stdout);
                if(generation_empty_cleanup_test&&generation_test_step_index==6) {
                    printf("KER_GENERATION_EMPTY_CLEANUP_RELEASED {\"generation\":%u}\n",generation); fflush(stdout);
                    generation_test_step_index=0;
                }
            } else if (count == 1 && command == 'd' && generation_detach_test && !peer_only) {
                struct ker_session_message detached,identity=message;
                uint64_t capability=0;
                if(receive_exact(control,&capability,sizeof(capability)))goto cleanup;
                if(drain_worker_heartbeat(fd,&heartbeat,peer,-1))goto cleanup;
                int status=worker_detach_request(fd,&identity,&message.sequence,capability,peer,&detached);
                if(status){fprintf(stderr,"ker session detach failed %d\n",status);goto cleanup;}
                detach_foreign_result=detached.token!=0;
                unsigned rx_count=(unsigned)(detached.capability>>32),tx_count=(unsigned)detached.capability;
                detach_nonowner_result=tx_count==0&&!detach_foreign_result;
                if(generation_detach_post_matrix(tx_count,detach_foreign_result,detach_nonowner_result,
                        generation_empty_cleanup_test,identity.generation,
                        generation_test_original,generation_test_original_packet))goto cleanup;
                struct ker_generation_rings *reopened=NULL;
                if(ker_generation_rings_attach(message.session,1,2,pool,&reopened))goto cleanup;
                int stable=generation_detach_post_matrix(tx_count,detach_foreign_result,detach_nonowner_result,
                    generation_empty_cleanup_test,identity.generation,generation_test_original,generation_test_original_packet);
                if(ker_generation_rings_detach(reopened)||stable){
                    fprintf(stderr,"generation detach matrix failed after readmit generation=%llu status=%d\n",
                        (unsigned long long)identity.generation,stable);
                    result=1;goto cleanup;
                }
                printf("KER_SESSION_RING_DETACHED {\"foreign_peer\":%s,\"rx_reclaimed\":%u,\"tx_reclaimed\":%u}\n",
                    detach_foreign_result?"true":"false",rx_count,tx_count);fflush(stdout);
            } else if (count == 1 && command == 'a' && generation_detach_test && !peer_only) {
                uint64_t capability=0;
                if(receive_exact(control,&capability,sizeof(capability)))goto cleanup;
                if(drain_worker_heartbeat(fd,&heartbeat,peer,-1))goto cleanup;
                int status=worker_detach_expect_status(fd,&message,&message.sequence,capability,peer,-ESTALE);
                if(status)goto cleanup;
                printf("KER_SESSION_RING_DETACH_SNAPSHOT_REJECTED {\"status\":%d}\n",-ESTALE);fflush(stdout);
            } else if (count == 1 && command == 'b' && generation_detach_test && !peer_only) {
                uint64_t capability=0;
                if(receive_exact(control,&capability,sizeof(capability)))goto cleanup;
                if(drain_worker_heartbeat(fd,&heartbeat,peer,-1))goto cleanup;
                int status=worker_detach_expect_status(fd,&message,&message.sequence,capability,peer,-EPERM);
                if(status)goto cleanup;
                printf("KER_SESSION_RING_DETACH_OLD_CAP_REJECTED {\"status\":%d}\n",-EPERM);fflush(stdout);
            } else if (count == 1 && command == 'X' && generation_detach_test) {
                if(drain_worker_heartbeat(fd,&heartbeat,peer,-1))goto cleanup;
                if(peer_only){
                    if(generation_rings)goto cleanup;
                    struct ker_session_message denied;
                    int pmd_status=worker_request(fd,&message,&message.sequence,KER_SESSION_PMD_ACQUIRE,0,peer,&denied);
                    int detach_status=worker_request(fd,&message,&message.sequence,KER_SESSION_RING_DETACH,0,peer,&denied);
                    if(pmd_status!=-EPERM||detach_status!=-EPERM)goto cleanup;
                    printf("KER_SESSION_PEER_ONLY_DENIED {\"generation_ring_handle\":false,\"pmd_status\":%d,\"detach_status\":%d}\n",pmd_status,detach_status);fflush(stdout);
                } else {
                    struct ker_session_message forged=message,denied;
                    forged.capability=1;
                    int status=worker_request(fd,&forged,&message.sequence,KER_SESSION_HEARTBEAT,0,peer,&denied);
                    if(status!=-EINVAL)goto cleanup;
                    printf("KER_SESSION_CAPABILITY_DENIED {\"status\":%d}\n",status);fflush(stdout);
                }
            } else if (count == 1 && command == 'V' && generation_detach_test && generation_empty_cleanup_test) {
                struct ker_generation_identity identity={.session=message.session,.epoch=message.epoch,
                    .slot=(uint32_t)message.slot,.generation=generation,.process=process,.pid=(uint32_t)getpid()};
                int status=generation_detach_post_matrix(0,detach_foreign_result,detach_nonowner_result,true,
                    identity.generation,generation_test_original,generation_test_original_packet);
                if(status){fprintf(stderr,"generation empty retained barrier failed generation=%u status=%d\n",generation,status);result=1;goto cleanup;}
                printf("KER_GENERATION_EMPTY_CLEANUP_RETAINED {\"generation\":%u,\"rings\":8,\"owned_rings\":4,\"same_objects\":true}\n",
                    identity.generation);fflush(stdout);
            } else if (count == 1 && command == 'F' && generation_detach_test) detach_foreign_result=true;
            else if (count == 1 && command == 'N' && generation_detach_test) detach_foreign_result=false;
            else if (count == 1 && command == 'M' && generation_detach_test && !peer_only) detach_nonowner_result=true;
            else if (count == 1 && command == 'T' && generation_detach_test && !peer_only) generation_test_step_index=3;
            else if (count == 1 && command == 'H' && generation_detach_test && !peer_only &&
                generation==0 && !generation_test_hold_started) {
                generation_test_hold_context.rings=generation_rings;
                generation_test_hold_context.identity=(struct ker_generation_identity){
                    .session=message.session,.epoch=message.epoch,.slot=(uint32_t)message.slot,
                    .generation=generation,.process=process,.pid=(uint32_t)getpid()};
                ker_generation_test_hold_next_dequeue();
                if(pthread_create(&generation_test_hold_thread,NULL,generation_test_hold_rx_dequeue,NULL))goto cleanup;
                generation_test_hold_started=true;
            }
#endif
            else if (count < 0 && errno == EINTR) continue;
            else break;
        }
    }
    result = 0;
cleanup:
    if(ticket>=0)close(ticket);
    if (exception_bridge.pending && ker_worker_exception_close(&exception_bridge)) result = 1;
    if (exception_fd >= 0) close(exception_fd);
    if (initialized && rte_eal_cleanup()) result = 1;
    if (fd >= 0) close(fd);
    if (peer >= 0) close(peer);
#ifdef KER_SESSION_TEST_HOOKS
    if (directory_test_gate_fd >= 0) close(directory_test_gate_fd);
#endif
    return result;
}
static int queue_mask_number(const char *s, uint64_t *value)
{
    char *end;
    if (!s || !*s || *s=='-' || *s=='+') return -1;
    errno=0;
    unsigned long long parsed=strtoull(s,&end,0);
    if (errno || end==s || *end) return -1;
    *value=(uint64_t)parsed;
    return 0;
}
static int number(const char *s)
{
    char *end;
    errno = 0;
    long value = strtol(s, &end, 10);
    return errno || !*s || *end || value < 0 || value > INT_MAX ? -1 : (int)value;
}
int main(int argc, char **argv)
{
    const char *path = NULL, *role = NULL;
    int control = -1, ticket = -1, generation = 0, process = 0, split = -1, probe_count = 0;
    bool probe_only = false, standby = false;
#ifdef KER_SESSION_TEST_HOOKS
    bool generation_test = false, generation_detach_test=false, generation_tx_full_test=false, empty_cleanup_test=false;
    int directory_test_gate_fd = -1;
    bool generation_rings_test_replay = false;
#endif
    bool generation_rings = false, coordinate_probe = false;
    bool cleanup_rx_set=false, cleanup_tx_set=false;
    uint64_t cleanup_rx_mask=0, cleanup_tx_mask=0;
#ifdef KER_SESSION_TEST_HOOKS
    bool tc3_observer_arg = false;
#endif
    int packet_fd = -1, wire_fd = -1, mtu_fd = -1;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--")) { split = i; break; }
        if (!strcmp(argv[i], "--standby")) { standby = true; continue; }
        if (!strcmp(argv[i], "--generation-rings")) { generation_rings = true; continue; }
        if (!strcmp(argv[i], "--generation-cleanup-rx-mask")) {
            if (i+1>=argc || cleanup_rx_set || queue_mask_number(argv[++i],&cleanup_rx_mask)) return 2;
            cleanup_rx_set=true; continue;
        }
        if (!strcmp(argv[i], "--generation-cleanup-tx-mask")) {
            if (i+1>=argc || cleanup_tx_set || queue_mask_number(argv[++i],&cleanup_tx_mask)) return 2;
            cleanup_tx_set=true; continue;
        }
#ifdef KER_SESSION_TEST_HOOKS
        if (!strcmp(argv[i], "--generation-rings-test")) { generation_test = true; continue; }
        if (!strcmp(argv[i], "--test-generation-frame-drain")) { generation_frame_drain_test = true; continue; }
        if (!strcmp(argv[i], "--generation-detach-test")) { generation_detach_test=true; continue; }
        if (!strcmp(argv[i], "--generation-tx-full-test")) { generation_tx_full_test=true; continue; }
        if (!strcmp(argv[i], "--generation-empty-cleanup-test")) { empty_cleanup_test=true; continue; }
        if (!strcmp(argv[i], "--generation-test-corrupt-after-collection")) { generation_test_corrupt_after_collection=true; continue; }
#endif
        if (!strcmp(argv[i], "--ring-pmd")) { if (ring_pmd) return 2; ring_pmd = 1; continue; }
        if (!strcmp(argv[i], "--paired-pmd")) { if (ring_pmd) return 2; ring_pmd = 2; continue; }
        if (!strcmp(argv[i], "--probe-only")) { probe_only = true; continue; }
#ifdef KER_SESSION_TEST_HOOKS
        if (!strcmp(argv[i], "--tc3-observer")) { tc3_observer_arg = true; continue; }
        if (!strcmp(argv[i], "--directory-test-gate-fd") && i + 1 < argc) {
            directory_test_gate_fd = number(argv[++i]); continue;
        }
        if (!strcmp(argv[i], "--directory-test-replay-attached")) {
            directory_test_replay_attached = true; continue;
        }
        if (!strcmp(argv[i], "--generation-rings-test-replay")) {
            generation_rings_test_replay = true; continue;
        }
#endif
        if (!strcmp(argv[i], "--coordinate-probe")) { coordinate_probe = true; continue; }
        if (i + 1 >= argc) break;
        if (!strcmp(argv[i], "--socket")) path = argv[++i];
        else if (!strcmp(argv[i], "--role")) role = argv[++i];
        else if (!strcmp(argv[i], "--control-fd")) control = number(argv[++i]);
        else if (!strcmp(argv[i], "--ticket-fd")) ticket = number(argv[++i]);
        else if (!strcmp(argv[i], "--generation")) generation = number(argv[++i]);
        else if (!strcmp(argv[i], "--process")) process = number(argv[++i]);
        else if (!strcmp(argv[i], "--packet-fd")) packet_fd = number(argv[++i]);
        else if (!strcmp(argv[i], "--wire-fd")) wire_fd = number(argv[++i]);
        else if (!strcmp(argv[i], "--mtu-fd")) mtu_fd = number(argv[++i]);
        else if (!strcmp(argv[i], "--probe-count")) probe_count = number(argv[++i]);
        else break;
    }
#ifdef KER_SESSION_TEST_HOOKS
    if (role && !strcmp(role, "test-eal-primary")) {
        if (control < 0 || split < 0) return 2;
        argv[split] = argv[0];
        if (rte_eal_init(argc - split, argv + split) < 0) return 1;
        if (rte_eal_process_type() != RTE_PROC_PRIMARY) { rte_eal_cleanup(); return 1; }
        printf("KER_SESSION_TEST_EAL_PRIMARY_READY\n"); fflush(stdout);
        char discard[64];
        while (read(control, discard, sizeof(discard)) > 0) { }
        return rte_eal_cleanup() ? 1 : 0;
    }
#endif
    if ((standby && (!ring_pmd || probe_only || !role || strcmp(role, "secondary"))) ||
        (coordinate_probe && (!role || strcmp(role, "secondary") || ring_pmd || standby || probe_only || probe_count || generation || process)) ||
        probe_count < 0 || probe_count > 4096 || (probe_only && !probe_count)) return 2;
    if (!path || !role || control < 0 || split < 0 || generation < 0 || process < 0 ||
        generation >= (int)KER_SESSION_GENERATIONS || process >= (int)KER_SESSION_PROCESSES ||
        (strcmp(role, "primary") && strcmp(role, "secondary")) || (!strcmp(role, "secondary") && ticket < 0)) {
        fprintf(stderr, "usage: ker-io-session --role primary|secondary --socket PATH --control-fd N [--ticket-fd N --generation 0..1 --process 0..3] -- EAL_ARGS\n");
        return 2;
    }
    generation_cleanup_config=(struct ker_generation_cleanup_config){
        .version=KER_GENERATION_CLEANUP_CONFIG_VERSION, .size=sizeof(generation_cleanup_config),
        .ports=1, .queues=2, .rx_queue_mask=UINT64_C(1), .tx_queue_mask=UINT64_C(2)};
    if (cleanup_rx_set!=cleanup_tx_set ||
        ((cleanup_rx_set||cleanup_tx_set) && (!generation_rings || strcmp(role,"primary")))) {
        fprintf(stderr,"ker session: cleanup masks require one generation-ring primary configuration\n");
        return 2;
    }
    if (cleanup_rx_set) {
        generation_cleanup_config.rx_queue_mask=cleanup_rx_mask;
        generation_cleanup_config.tx_queue_mask=cleanup_tx_mask;
    }
    if (generation_cleanup_config.version!=KER_GENERATION_CLEANUP_CONFIG_VERSION ||
        generation_cleanup_config.size!=sizeof(generation_cleanup_config) ||
        generation_cleanup_config.ports!=1 || generation_cleanup_config.queues!=2 ||
        (generation_cleanup_config.rx_queue_mask&~UINT64_C(3)) ||
        (generation_cleanup_config.tx_queue_mask&~UINT64_C(3))) {
        fprintf(stderr,"ker session: invalid generation cleanup configuration\n");
        return 2;
    }
#ifdef KER_SESSION_TEST_HOOKS
    if (tc3_observer_arg && (ring_pmd != 2 || strcmp(role, "secondary") || probe_only || probe_count)) return 2;
    if (generation_frame_drain_test && (!generation_rings || ring_pmd!=2 || strcmp(role,"secondary") ||
        generation!=1)) return 2;
    if ((directory_test_gate_fd >= 0 || directory_test_replay_attached || generation_rings_test_replay) && strcmp(role, "secondary")) return 2;
    if (generation_rings_test_replay && !generation_rings) return 2;
    if (directory_test_gate_fd >= 0 && fcntl(directory_test_gate_fd, F_GETFD) < 0) return 2;
    tc3_observer = tc3_observer_arg;
#endif
    if (ring_pmd == 2 && !strcmp(role, "secondary") && (probe_only || probe_count ||
        packet_fd == wire_fd || packet_fd == mtu_fd || wire_fd == mtu_fd ||
        ker_session_packet_endpoint(packet_fd, SOCK_DGRAM) || ker_session_packet_endpoint(wire_fd, SOCK_DGRAM) ||
        ker_session_packet_endpoint(mtu_fd, SOCK_SEQPACKET))) return 2;
    if (fcntl(control, F_GETFD) < 0 || (!strcmp(role, "secondary") && fcntl(ticket, F_GETFD) < 0)) {
        perror("ker session control descriptor"); return 2;
    }
    generation_rings_enabled=generation_rings;
#ifdef KER_SESSION_TEST_HOOKS
    if((generation_test||generation_detach_test||generation_tx_full_test)&&(!generation_rings||strcmp(role,"secondary")))return 2;
    if(generation_tx_full_test&&(generation_test||generation_detach_test||generation_empty_cleanup_test))return 2;
    if(empty_cleanup_test&&(!generation_detach_test||!generation_rings||strcmp(role,"secondary")))return 2;
    if(generation_test_corrupt_after_collection&&(!generation_rings||strcmp(role,"primary")))return 2;
    generation_empty_cleanup_test=empty_cleanup_test;
#endif
    bool no_pci = false;
    for (int i = split + 1; i < argc; i++) {
        if (!strcmp(argv[i], "--no-pci")) no_pci = true;
        if ((ring_pmd == 1 && !strcmp(argv[i], "--vdev=net_ring_ker")) ||
            (ring_pmd == 2 && !strcmp(role, "secondary") && !strcmp(argv[i], "--vdev=" KER_SESSION_PACKET_PORT))) continue;
        if (!strcmp(argv[i], "--vdev") || !strncmp(argv[i], "--vdev=", 7) ||
            !strcmp(argv[i], "--allow") || !strncmp(argv[i], "--allow=", 8) ||
            !strcmp(argv[i], "-a") || !strncmp(argv[i], "-a", 2)) {
            fprintf(stderr, "ker session: registration stage does not admit devices\n"); return 2;
        }
    }
    if (!no_pci) {
        fprintf(stderr, "ker session: registration stage requires --no-pci\n"); return 2;
    }
    /* Do not publish readiness on hosts that cannot supply stable peer
     * process lifetime handles. Never fall back to a numeric PID census. */
    int pair[2], proof = -1;
    if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, pair)) return 1;
    socklen_t proof_size = sizeof(proof);
    int proof_result = getsockopt(pair[0], SOL_SOCKET, SO_PEERPIDFD, &proof, &proof_size);
    int proof_error = errno;
    if (proof >= 0) close(proof);
    close(pair[0]); close(pair[1]);
    if (proof_result || proof_size != sizeof(proof)) {
        fprintf(stderr, "ker session: SO_PEERPIDFD is required: %s\n", strerror(proof_error)); return 1;
    }
    struct sigaction action = {.sa_handler = stop_signal};
    sigemptyset(&action.sa_mask); sigaction(SIGTERM, &action, NULL); sigaction(SIGINT, &action, NULL);
    argv[split] = argv[0];
    if (!strcmp(role, "secondary"))
        return secondary(path, control, ticket, (unsigned)generation, (unsigned)process, (unsigned)probe_count, probe_only, standby,
#ifdef KER_SESSION_TEST_HOOKS
            generation_test, generation_detach_test, generation_tx_full_test, directory_test_gate_fd, directory_test_replay_attached,
            generation_rings_test_replay,
#endif
            coordinate_probe, packet_fd, wire_fd, mtu_fd, argc - split, argv + split);
    if (rte_eal_init(argc - split, argv + split) < 0) return 1;
    if (rte_eal_process_type() != RTE_PROC_PRIMARY) { rte_eal_cleanup(); return 1; }
    return primary(path, control);
}
