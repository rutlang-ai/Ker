struct rte_ring *
create_ring(const char *name, unsigned count, int socket_id, unsigned flags)
{
    struct rte_ring *ring;

    if (name == NULL) {
        rte_exit(EXIT_FAILURE, "create ring failed, no name!\n");
    }

    if (rte_eal_process_type() == RTE_PROC_PRIMARY) {
        ring = rte_ring_create(name, count, socket_id, flags);
        /* EEXIST: the memzone survived a previous init (-1 detaches
         * without freeing) or belongs to another master (-2 name
         * clash). Attach to the existing ring instead of exiting; its
         * size/flags are reused as-is. */
        if (ring == NULL && rte_errno == EEXIST) {
            ring = rte_ring_lookup(name);
            if (ring != NULL)
                ff_log(FF_LOG_WARNING, FF_LOGTYPE_FSTACK_LIB,
                    "ring %s already exists, attaching "
                    "(size/flags of the existing ring are reused)\n", name);
        }
    } else {
        ring = rte_ring_lookup(name);
    }

    if (ring == NULL) {
        rte_exit(EXIT_FAILURE, "create ring:%s failed!\n", name);
    }

    return ring;
}
