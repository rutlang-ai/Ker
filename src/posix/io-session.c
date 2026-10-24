/* SPDX-License-Identifier: GPL-2.0-only */
#define _GNU_SOURCE
#include "io-session.h"
#include <sys/types.h>
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
    uint64_t sequence, probe_sequence;
    struct rte_mbuf *leased_packet;
    struct ker_session_message request, reply;
};
struct slot { uint64_t epoch, token; int master; };
static struct client clients[CLIENTS];
static struct slot slots[KER_SESSION_SLOTS];
static struct rte_ring *rings[QUEUES];
static struct rte_mempool *message_pool;
static struct rte_mbuf *message_objects[KER_SESSION_OBJECTS];
static const struct rte_memzone *zone;
static struct ker_session_directory *directory;
static uint64_t next_epoch = 1;
static bool ring_pmd;
static uint16_t pmd_port;
static bool pmd_configured;
static int pmd_client = -1;
static struct rte_mbuf *pmd_packet;
static uint64_t pmd_key(const struct client *client)
{
    return 1 + ((uint64_t)client->slot * KER_SESSION_GENERATIONS + client->generation) * KER_SESSION_PROCESSES + client->process;
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
    struct rte_mbuf *packet;
    unsigned seen = 0;
    while (rte_eth_rx_burst(pmd_port, 0, &packet, 1))
        if (packet != pmd_packet || ++seen > 1) _Exit(125);
    atomic_store_explicit(&directory->pmd_lease, 0, memory_order_release);
    rte_pktmbuf_reset(pmd_packet);
    rte_pktmbuf_free(pmd_packet);
    pmd_packet = NULL; pmd_client = -1;
    atomic_store_explicit(&directory->pmd_owner, 0, memory_order_release);
}
static void reclaim_control(unsigned index)
{
    reclaim_pmd(index);
    struct client *client = &clients[index];
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
static void serve_probes(void)
{
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
static void drop_client(unsigned i)
{
    if (clients[i].fd >= 0) close(clients[i].fd);
    if (clients[i].pidfd >= 0) close(clients[i].pidfd);
    clients[i] = (struct client){.fd = -1, .pidfd = -1};
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
    for (unsigned g = 0; g < KER_SESSION_GENERATIONS; g++)
        for (unsigned p = 0; p < KER_SESSION_PROCESSES; p++) {
            if (atomic_load_explicit(&directory->lease[s][g][p], memory_order_acquire)) return -EBUSY;
            for (unsigned c = 0; c < KER_SESSION_CHANNELS; c++)
                if (!rte_ring_empty(rings[ring_index(s, g, p, c)])) return -EBUSY;
        }
    atomic_store_explicit(&directory->epoch[s], 0, memory_order_release);
    slots[s] = (struct slot){.master = -1};
    return 0;
}
static void reap_clients(void)
{
    /* EOF is not proof that an EAL borrower has stopped. Retain its pidfd. */
    for (unsigned i = 0; i < CLIENTS; i++)
        if (clients[i].kind != UNUSED && dead(clients[i].pidfd)) {
            if (clients[i].kind == MASTER) {
                if (!release_slot(clients[i].slot)) drop_client(i);
            } else {
                if (clients[i].kind == RESERVED || clients[i].kind == ATTACHED)
                    reclaim_control(i);
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
static int handle(unsigned i, const struct ker_session_message *request,
    struct ker_session_message *reply)
{
    struct client *client = &clients[i];
    *reply = *request;
    reply->session = directory->session;
    if (request->magic != KER_SESSION_MAGIC || request->version != KER_SESSION_VERSION ||
        request->status || !request->sequence) return -EPROTO;
    if (request->command == KER_SESSION_PMD_STATUS && client->kind == UNBOUND) {
        if (request->session || request->epoch || request->token || request->slot ||
            request->generation || request->process) return -EINVAL;
        if (!ring_pmd) return -EOPNOTSUPP;
        reply->epoch = reply->slot = reply->generation = reply->process = 0;
        reply->token = atomic_load_explicit(&directory->pmd_owner, memory_order_acquire);
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
            request->slot || request->generation || request->process) return -EINVAL;
        if (next_epoch == UINT64_MAX) return -EOVERFLOW;
        for (unsigned s = 1; s < KER_SESSION_SLOTS; s++) if (!slots[s].epoch) {
            uint64_t token;
            int result = random_id(&token);
            if (result) return result;
            slots[s] = (struct slot){.epoch = next_epoch++, .token = token, .master = (int)i};
            client->kind = MASTER; client->slot = s;
            atomic_store_explicit(&directory->epoch[s], slots[s].epoch, memory_order_release);
            reply->slot = s; reply->epoch = slots[s].epoch; reply->token = token;
            return 0;
        }
        return -ENOSPC;
    }
    unsigned s = (unsigned)request->slot;
    if (request->session != directory->session || request->slot >= KER_SESSION_SLOTS || !s ||
        request->epoch != slots[s].epoch || !request->epoch || request->token != slots[s].token)
        return -ESTALE;
    if (request->generation >= KER_SESSION_GENERATIONS || request->process >= KER_SESSION_PROCESSES)
        return -EINVAL;
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
        for (unsigned k = 0; k < CLIENTS; k++)
            if ((clients[k].kind == RESERVED || clients[k].kind == ATTACHED) && clients[k].slot == s &&
                clients[k].generation == request->generation && clients[k].process == request->process)
                return -EBUSY;
        _Atomic uintptr_t *lease = &directory->lease[s][request->generation][request->process];
        if (atomic_load_explicit(lease, memory_order_acquire)) return -EUCLEAN;
        struct rte_mbuf *packet = rte_pktmbuf_alloc(message_pool);
        if (!packet) return -ENOMEM;
        client->leased_packet = packet;
        client->kind = RESERVED; client->slot = s;
        client->generation = (unsigned)request->generation; client->process = (unsigned)request->process;
        atomic_store_explicit(lease, (uintptr_t)packet, memory_order_release);
        return 0;
    }
    if (request->command == KER_SESSION_PMD_ACQUIRE) {
        if (!ring_pmd) return -EOPNOTSUPP;
        if (client->kind != ATTACHED || client->slot != s || client->generation != request->generation ||
            client->process != request->process) return -EPERM;
        if (pmd_client >= 0) return -EBUSY;
        struct rte_mbuf *packet = rte_pktmbuf_alloc(message_pool);
        if (!packet) return -ENOMEM;
        /* Journal before publishing the grant or sending its acknowledgement. */
        pmd_client = (int)i; pmd_packet = packet;
        atomic_store_explicit(&directory->pmd_lease, (uintptr_t)packet, memory_order_release);
        atomic_store_explicit(&directory->pmd_owner, pmd_key(client), memory_order_release);
        return 0;
    }
    if (request->command == KER_SESSION_ATTACHED) {
        if (client->kind != RESERVED || client->slot != s || client->generation != request->generation ||
            client->process != request->process) return -EPERM;
        client->kind = ATTACHED;
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
    if (send(client->fd, &reply, sizeof(reply), MSG_DONTWAIT | MSG_NOSIGNAL) != sizeof(reply)) {
        disconnect_client(i);
    }
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
        clients[i] = (struct client){.fd = fd, .pidfd = pidfd, .pid = credential.pid, .kind = UNBOUND};
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
    struct stat socket_identity = {0};
    bool bound = false;
    for (unsigned i = 0; i < CLIENTS; i++) clients[i] = (struct client){.fd = -1, .pidfd = -1};
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
    atomic_init(&directory->pmd_lease, 0);
    for (unsigned s = 0; s < KER_SESSION_SLOTS; s++) {
        atomic_init(&directory->epoch[s], 0);
        for (unsigned g = 0; g < KER_SESSION_GENERATIONS; g++)
            for (unsigned p = 0; p < KER_SESSION_PROCESSES; p++) atomic_init(&directory->lease[s][g][p], 0);
    }
    if (!atomic_is_lock_free(&directory->pmd_owner) || !atomic_is_lock_free(&directory->pmd_lease) ||
        !atomic_is_lock_free(&directory->epoch[0]) ||
        !atomic_is_lock_free(&directory->lease[0][0][0]) || random_id(&directory->session)) goto cleanup;
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
    if (ring_pmd) {
        struct rte_eth_conf config = {0};
        if (rte_eth_dev_get_port_by_name("net_ring_ker", &pmd_port) || rte_eth_dev_count_avail() != 1 ||
            rte_eth_dev_configure(pmd_port, 1, 1, &config)) goto cleanup;
        pmd_configured = true;
        if (rte_eth_rx_queue_setup(pmd_port, 0, 128, SOCKET_ID_ANY, NULL, message_pool) ||
            rte_eth_tx_queue_setup(pmd_port, 0, 128, SOCKET_ID_ANY, NULL) || rte_eth_dev_start(pmd_port)) goto cleanup;
    }
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
    printf("KER_SESSION_READY {\"stage\":\"shared-control\",\"session\":%llu,\"rings\":%u,\"slots\":%u,\"ring_pmd\":%s}\n",
        (unsigned long long)directory->session, QUEUES, KER_SESSION_SLOTS, ring_pmd ? "true" : "false"); fflush(stdout);
    result = 0;
    while (!stopping) {
        reap_clients();
        serve_probes();
        struct pollfd fds[CLIENTS + 2];
        fds[0] = (struct pollfd){.fd = control, .events = POLLIN};
        fds[1] = (struct pollfd){.fd = listener, .events = POLLIN};
        for (unsigned i = 0; i < CLIENTS; i++) fds[i + 2] = (struct pollfd){.fd = clients[i].fd, .events = POLLIN};
        int ready = poll(fds, CLIENTS + 2, 50);
        if (ready < 0) { if (errno == EINTR) continue; result = 1; break; }
        if (fds[0].revents) break;
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
    if (pmd_configured) {
        if (rte_eth_dev_stop(pmd_port) || rte_eth_dev_close(pmd_port)) result = 1;
    }
    if (message_pool) {
        if (rte_mempool_in_use_count(message_pool)) {
            fprintf(stderr, "ker session: outstanding shared control objects prevent cleanup\n"); _Exit(125);
        }
        printf("KER_SESSION_DRAINED {\"outstanding\":0,\"objects\":%u}\n", KER_SESSION_OBJECTS); fflush(stdout);
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
static int exchange(int fd, struct ker_session_message *message)
{
    struct ker_session_message response;
    if (send(fd, message, sizeof(*message), MSG_NOSIGNAL) != sizeof(*message) ||
        recv(fd, &response, sizeof(response), MSG_TRUNC) != sizeof(response)) return -EIO;
    if (memcmp(&response, message, sizeof(response) - sizeof(response.status)) ||
        response.status > 0 || response.status < -4095) return -EPROTO;
    *message = response;
    return (int)response.status;
}
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
static int shared_probe(struct rte_ring *input, struct rte_ring *output,
    struct rte_mbuf *packet, const struct ker_session_message *identity, int control,
    unsigned *deferred_probes, unsigned count, uint64_t *next_sequence, int resident)
{
    for (unsigned sequence = 1; sequence <= count; sequence++) {
        require_resident_alive(resident);
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
    unsigned count, uint64_t *sequence, int peer, int control, unsigned *deferred_probes)
{
    uint64_t key = 1 + (identity->slot * KER_SESSION_GENERATIONS + identity->generation) * KER_SESSION_PROCESSES + identity->process;
    struct rte_eth_stats before, after;
    if (rte_eth_stats_get(pmd_port, &before)) return -EIO;
    for (unsigned i = 0; i < count; i++) {
        require_resident_alive(peer);
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
static int secondary(const char *path, int control, int ticket, unsigned generation,
    unsigned process, unsigned probe_count, bool probe_only, int argc, char **argv)
{
    int result = 1, fd = -1, peer = -1;
    bool initialized = false;
    struct ker_session_message message;
    if (receive_exact(ticket, &message, sizeof(message))) return 1;
    close(ticket);
    if (message.magic != KER_SESSION_MAGIC || message.version != KER_SESSION_VERSION || message.status ||
        message.command != KER_SESSION_MASTER || !message.session || !message.epoch || !message.token ||
        !message.slot || message.slot >= KER_SESSION_SLOTS) return 1;
    struct sockaddr_un address = {.sun_family = AF_UNIX};
    if (strlen(path) >= sizeof(address.sun_path)) return 1;
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
    message.command = KER_SESSION_RESERVE; message.sequence = 1;
    message.generation = generation; message.process = process;
    int status = exchange(fd, &message);
    if (status) { fprintf(stderr, "ker session reserve: %d\n", status); goto cleanup; }
    /* Register the process lifetime before EAL starts borrowing shared data. */
    if (rte_eal_init(argc, argv) < 0) goto cleanup;
    initialized = true;
    if (rte_eal_process_type() != RTE_PROC_SECONDARY) goto cleanup;
    const struct rte_memzone *shared = rte_memzone_lookup(KER_SESSION_ZONE);
    if (!shared || shared->len < sizeof(struct ker_session_directory)) goto cleanup;
    const struct ker_session_directory *d = shared->addr;
    directory = (struct ker_session_directory *)shared->addr;
    if (atomic_load_explicit(&d->state, memory_order_acquire) != KER_SESSION_READY ||
        d->magic != KER_SESSION_MAGIC || d->version != KER_SESSION_VERSION || d->size != sizeof(*d) ||
        d->session != message.session || d->primary_pid != (uint32_t)credential.pid ||
        d->slots != KER_SESSION_SLOTS || d->generations != KER_SESSION_GENERATIONS ||
        d->processes != KER_SESSION_PROCESSES || d->channels != KER_SESSION_CHANNELS ||
        d->capacity != KER_SESSION_CAPACITY ||
        atomic_load_explicit(&d->epoch[message.slot], memory_order_acquire) != message.epoch) goto cleanup;
    if (d->ring_pmd != ring_pmd) goto cleanup;
    if (ring_pmd && (rte_eth_dev_get_port_by_name("net_ring_ker", &pmd_port) || rte_eth_dev_count_avail() != 1)) goto cleanup;
    struct rte_mempool *pool = rte_mempool_lookup(KER_SESSION_POOL);
    if (!pool || pool->size != KER_SESSION_OBJECTS || pool->cache_size) goto cleanup;
    if (rte_mempool_obj_iter(pool, remember_object, NULL) != KER_SESSION_OBJECTS) goto cleanup;
    struct rte_mbuf *leased_packet = (struct rte_mbuf *)atomic_load_explicit(
        &d->lease[message.slot][generation][process], memory_order_acquire);
    if (!known_object(leased_packet) || leased_packet->pool != pool) goto cleanup;
    char names[KER_SESSION_CHANNELS][RTE_RING_NAMESIZE];
    struct rte_ring *channels[KER_SESSION_CHANNELS];
    for (unsigned c = 0; c < KER_SESSION_CHANNELS; c++) {
        if (ring_name(names[c], sizeof(names[c]), (unsigned)message.slot, generation, process, c)) goto cleanup;
        struct rte_ring *ring = rte_ring_lookup(names[c]);
        if (!ring || rte_ring_get_capacity(ring) != KER_SESSION_CAPACITY) goto cleanup;
        channels[c] = ring;
    }
    message.command = KER_SESSION_ATTACHED; message.sequence++;
    if (exchange(fd, &message)) goto cleanup;
    printf("KER_SESSION_ATTACHED {\"stage\":\"shared-control\",\"pid\":%ld,\"master\":%ld,\"epoch\":%llu,\"slot\":%llu,\"generation\":%u,\"process\":%u,\"rings\":[\"%s\",\"%s\",\"%s\",\"%s\"]}\n",
        (long)getpid(), (long)getppid(), (unsigned long long)message.epoch,
        (unsigned long long)message.slot, generation, process, names[0], names[1], names[2], names[3]); fflush(stdout);
    struct rte_mbuf *device_packet = NULL;
    if (ring_pmd) {
        message.command = KER_SESSION_PMD_ACQUIRE; message.sequence++;
        int acquired = exchange(fd, &message);
        if (acquired) { fprintf(stderr, "ker session: PMD consumer grant rejected %d\n", acquired); goto cleanup; }
        device_packet = (struct rte_mbuf *)atomic_load_explicit(&d->pmd_lease, memory_order_acquire);
        if (!known_object(device_packet) || device_packet->pool != pool || device_packet == leased_packet) goto cleanup;
        printf("KER_SESSION_PMD_GRANTED {\"pid\":%ld,\"epoch\":%llu,\"slot\":%llu}\n",
            (long)getpid(), (unsigned long long)message.epoch, (unsigned long long)message.slot); fflush(stdout);
    }
    uint64_t device_sequence = 0;
    uint64_t probe_sequence = 0;
    unsigned deferred_probes = 0;
    bool probe_pending = probe_only;
    while (!stopping) {
        if (probe_pending) {
            int probe_result = shared_probe(channels[0], channels[3], leased_packet, &message,
                control, &deferred_probes, probe_count, &probe_sequence, peer);
            if (probe_result == -ECANCELED) { result = 0; goto cleanup; }
            if (probe_result) { fprintf(stderr, "ker session: shared probe failed %d\n", probe_result); goto cleanup; }
            printf("KER_SESSION_PROBED {\"epoch\":%llu,\"slot\":%llu,\"generation\":%u,\"process\":%u,\"count\":%u,\"sequence\":%llu,\"primary_pid\":%u,\"payload_bytes\":%u}\n",
                (unsigned long long)message.epoch, (unsigned long long)message.slot,
                generation, process, probe_count, (unsigned long long)probe_sequence,
                directory->primary_pid, KER_SESSION_PROBE_PAYLOAD); fflush(stdout);
            if (ring_pmd) {
                int status = pmd_roundtrips(device_packet, &message, probe_count, &device_sequence,
                    peer, control, &deferred_probes);
                if (status == -ECANCELED) { result = 0; goto cleanup; }
                if (status) { fprintf(stderr, "ker session: PMD roundtrip failed %d\n", status); goto cleanup; }
                printf("KER_SESSION_PMD_PROBED {\"pid\":%ld,\"sequence\":%llu,\"count\":%u,\"frame_bytes\":%zu}\n",
                    (long)getpid(), (unsigned long long)device_sequence, probe_count, 14 + sizeof(struct ker_session_probe)); fflush(stdout);
            }
            probe_pending = false;
            if (probe_only) break;
            if (deferred_probes) {
                deferred_probes--;
                probe_pending = true;
                continue;
            }
        }
        struct pollfd fds[] = {{.fd = control, .events = POLLIN}, {.fd = fd, .events = POLLIN},
                              {.fd = peer, .events = POLLIN}};
        int ready = poll(fds, 3, 100);
        if (ready < 0) { if (errno == EINTR) continue; goto cleanup; }
        if (fds[2].revents) { fprintf(stderr, "ker session: primary process exited\n"); _Exit(125); }
        if (fds[0].revents || fds[1].revents) {
            /* A control event must not hide a concurrent resident death. */
            if (dead(peer)) { fprintf(stderr, "ker session: primary process exited\n"); _Exit(125); }
            char command;
            if (!fds[1].revents && probe_count && (fds[0].revents & POLLIN) &&
                read(control, &command, 1) == 1 && command == 'P') probe_pending = true;
            else break;
        }
    }
    result = 0;
cleanup:
    if (initialized && rte_eal_cleanup()) result = 1;
    if (fd >= 0) close(fd);
    if (peer >= 0) close(peer);
    return result;
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
    bool probe_only = false;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--")) { split = i; break; }
        if (!strcmp(argv[i], "--ring-pmd")) { ring_pmd = true; continue; }
        if (!strcmp(argv[i], "--probe-only")) { probe_only = true; continue; }
        if (i + 1 >= argc) break;
        if (!strcmp(argv[i], "--socket")) path = argv[++i];
        else if (!strcmp(argv[i], "--role")) role = argv[++i];
        else if (!strcmp(argv[i], "--control-fd")) control = number(argv[++i]);
        else if (!strcmp(argv[i], "--ticket-fd")) ticket = number(argv[++i]);
        else if (!strcmp(argv[i], "--generation")) generation = number(argv[++i]);
        else if (!strcmp(argv[i], "--process")) process = number(argv[++i]);
        else if (!strcmp(argv[i], "--probe-count")) probe_count = number(argv[++i]);
        else break;
    }
    if (probe_count < 0 || probe_count > 4096 || (probe_only && !probe_count)) return 2;
    if (!path || !role || control < 0 || split < 0 || generation < 0 || process < 0 ||
        generation >= (int)KER_SESSION_GENERATIONS || process >= (int)KER_SESSION_PROCESSES ||
        (strcmp(role, "primary") && strcmp(role, "secondary")) || (!strcmp(role, "secondary") && ticket < 0)) {
        fprintf(stderr, "usage: ker-io-session --role primary|secondary --socket PATH --control-fd N [--ticket-fd N --generation 0..1 --process 0..3] -- EAL_ARGS\n");
        return 2;
    }
    if (fcntl(control, F_GETFD) < 0 || (!strcmp(role, "secondary") && fcntl(ticket, F_GETFD) < 0)) {
        perror("ker session control descriptor"); return 2;
    }
    bool no_pci = false;
    for (int i = split + 1; i < argc; i++) {
        if (!strcmp(argv[i], "--no-pci")) no_pci = true;
        if (ring_pmd && !strcmp(argv[i], "--vdev=net_ring_ker")) continue;
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
        return secondary(path, control, ticket, (unsigned)generation, (unsigned)process, (unsigned)probe_count, probe_only, argc - split, argv + split);
    if (rte_eal_init(argc - split, argv + split) < 0) return 1;
    if (rte_eal_process_type() != RTE_PROC_PRIMARY) { rte_eal_cleanup(); return 1; }
    return primary(path, control);
}
