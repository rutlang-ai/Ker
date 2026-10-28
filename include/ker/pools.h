#ifndef KER_POOLS_H
#define KER_POOLS_H
#include <ker/ker.h>
#include <stddef.h>

struct rte_mempool;
struct rte_mbuf;
enum ker_pool_kind { KER_POOL_MBUF, KER_POOL_MESSAGE, KER_POOL_REFERENCE };
struct ker_pool_config {
    const char *name;
    unsigned count;
    enum ker_pool_kind kind;
    unsigned size; /* mbuf data room, message payload or opaque reference size */
    int shared;   /* 0: original legacy cache; 1: process-shared cache0 */
    int socket;
};
/* Optional ker::pools. Caller initializes EAL and owns all pools/objects and
 * teardown. Original cache policy is 256 for mbuf/reference,16 for message,
 * and0 for all process-shared pools. Message objects preserve the pinned C
 * ff_msg layout. Reference objects are caller-defined records; this does not
 * implement the FreeBSD page-array reference ABI. DPDK failures use rte_errno. */
KER_API struct rte_mempool *ker_pool_create(const struct ker_pool_config *config);
/* Original mbuf_pool_<socket>_gen<0|1> name. No EAL required; original-1 on
 * bad generation/truncation. Buffer and size are checked before forwarding. */
KER_API int ker_mbuf_generation_name(char *buffer, size_t size, int socket, int generation);
/* One process-global original pool bank. Serialize selection, binding and
 * allocation. shared=0 selects the legacy RX pool; shared=1 selects exactly
 * gen0/gen1, including NULL when it is not created. No implicit fallback.
 * EAL is borrowed. Concurrent EAL processes sharing a lcore must use cache0. */
KER_API int ker_mbuf_bank_attach(int shared);
/* Borrow genuine mbuf pools under original socket indices0..7. NULL is valid
 * for an uncreated slot. Old bindings must have no outstanding mbufs. A new
 * process may borrow shared pools already used by another EAL process.
 * In shared mode all borrowed pools must have cache0. Caller must quiesce all
 * users before rebinding/detaching, including observers holding bare pointers. */
KER_API int ker_mbuf_bank_bind(unsigned socket, struct rte_mempool *legacy,
    struct rte_mempool *gen0, struct rte_mempool *gen1);
/* Original invalid-generation setter behavior: ignored, retaining selection.
 * May configure the selector before attach; detach resets it to gen0. */
KER_API void ker_mbuf_bank_select(int generation);
KER_API struct rte_mempool *ker_mbuf_bank_pool(unsigned socket);
/* Allocates an actual mbuf from the selected original pool. NULL/ENOENT when
 * that generation is uncreated; no missing-generation fallback is simulated. */
KER_API struct rte_mbuf *ker_mbuf_bank_alloc(unsigned socket);
/* Refuses outstanding mbufs, drops bindings, frees no caller-owned resource. */
KER_API int ker_mbuf_bank_detach(void);
#endif
