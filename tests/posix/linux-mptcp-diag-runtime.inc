/* Private scaffold for actual namespace/proc/Netlink operations, not protocol
 * emulation. Included only in the uninstalled resident selftest fixture. */
struct diag_namespace { char name[64]; int fd; };
static struct diag_namespace diag_namespaces[16];
static pthread_mutex_t namespace_lock = PTHREAD_MUTEX_INITIALIZER;
static int root_namespace;
static long (*raw_native_call)(unsigned, const unsigned long[6]);
static atomic_uint namespaces_created, namespaces_deleted, diag_netlinks, max_live;
static atomic_ulong diag_sends, diag_receives, join_syn_rx, join_ack_rx;
static long native_call(unsigned op, unsigned long a, unsigned long b, unsigned long c)
{
    unsigned long args[6] = {a, b, c, 0, 0, 0};
    long result = raw_native_call(op, args);
    if (result < 0) { errno = (int)-result; return -1; }
    return result;
}
static void mark_active(struct client *client)
{
    unsigned value = atomic_fetch_add(&live, 1) + 1;
    unsigned previous = atomic_load(&max_live);
    while (value > previous && !atomic_compare_exchange_weak(&max_live, &previous, value));
    atomic_store_explicit(&client->active, 1, memory_order_release);
}
static int diag_initialize(long (*call)(unsigned, const unsigned long[6]))
{
    raw_native_call = call;
    for (unsigned i = 0; i < 16; i++) diag_namespaces[i].fd = -1;
    root_namespace = (int)native_call(KER_TEST_OPEN, (unsigned long)"/proc/thread-self/ns/net", O_RDONLY | O_CLOEXEC, 0);
    return root_namespace < 0 ? -1 : 0;
}
static int namespace_index(const char *name)
{
    for (unsigned i = 0; i < 16; i++)
        if (diag_namespaces[i].fd >= 0 && !strcmp(name, diag_namespaces[i].name)) return (int)i;
    errno = ENOENT; return -1;
}
static int select_namespace(const char *name, size_t length, int *index)
{
    if (length && (length > 64 || name[length - 1] || strlen(name) + 1 != length)) { errno = EINVAL; return -1; }
    pthread_mutex_lock(&namespace_lock);
    *index = *name ? namespace_index(name) : -1;
    int fd = *name && *index < 0 ? -1 : *index < 0 ? root_namespace : diag_namespaces[*index].fd;
    int result = fd < 0 ? -1 : (int)native_call(KER_TEST_SETNS, fd, CLONE_NEWNET, 0);
    pthread_mutex_unlock(&namespace_lock);
    return result;
}
/* Snapshot real namespace MIBs before deleting its last pin. No protocol
 * state is inferred from the shell exit code or reconstructed in the fixture. */
static int namespace_mptcp_counters(void)
{
    int fd = (int)native_call(KER_TEST_OPEN, (unsigned long)"/proc/thread-self/net/netstat", O_RDONLY, 0);
    if (fd < 0) return -1;
    char text[16384]; size_t used = 0; ssize_t got;
    while (used < sizeof(text) - 1 && (got = read(fd, text + used, sizeof(text) - 1 - used)) > 0) used += (size_t)got;
    int error = errno; close(fd); errno = error;
    if (got < 0) return -1;
    if (used == sizeof(text) - 1) { errno = EOVERFLOW; return -1; }
    text[used] = 0;
    char *header = strstr(text, "MPTcpExt:"), *values = header ? strchr(header, '\n') : NULL;
    if (!values) { errno = EPROTO; return -1; }
    *values++ = 0;
    char *end = strchr(values, '\n'); if (end) *end = 0;
    if (strncmp(values, "MPTcpExt:", 9)) { errno = EPROTO; return -1; }
    char *names_state = NULL, *values_state = NULL;
    char *name = strtok_r(header + 9, " \t", &names_state);
    char *value = strtok_r(values + 9, " \t", &values_state);
    unsigned found = 0;
    while (name && value) {
        if (!strcmp(name, "MPJoinSynRx") || !strcmp(name, "MPJoinAckRx")) {
            char *tail; errno = 0; unsigned long count = strtoul(value, &tail, 10);
            if (errno || *tail) { errno = EPROTO; return -1; }
            atomic_fetch_add(!strcmp(name, "MPJoinSynRx") ? &join_syn_rx : &join_ack_rx, count); found++;
        }
        name = strtok_r(NULL, " \t", &names_state); value = strtok_r(NULL, " \t", &values_state);
    }
    if (name || value || found != 2) { errno = EPROTO; return -1; }
    return 0;
}
static long namespace_change(unsigned op, const char *name)
{
    if (!*name || strlen(name) >= 64) { errno = EINVAL; return -1; }
    pthread_mutex_lock(&namespace_lock);
    int index = namespace_index(name);
    long result = -1;
    if (op == MS_DELNS) {
        /* Leave the dying namespace before dropping its pin: veth teardown
         * must run from a task in the root namespace, not the retiring one. */
        if (index >= 0 && !native_call(KER_TEST_SETNS, diag_namespaces[index].fd, CLONE_NEWNET, 0) &&
            !namespace_mptcp_counters() &&
            !native_call(KER_TEST_SETNS, root_namespace, CLONE_NEWNET, 0) &&
            !(result = close(diag_namespaces[index].fd))) {
            diag_namespaces[index].fd = -1; atomic_fetch_add(&namespaces_deleted, 1);
        }
    } else if (index >= 0) errno = EEXIST;
    else {
        for (index = 0; index < 16 && diag_namespaces[index].fd >= 0; index++);
        if (index == 16) errno = ENOSPC;
        else if (!native_call(KER_TEST_SETNS, root_namespace, CLONE_NEWNET, 0) &&
                 !native_call(KER_TEST_UNSHARE, CLONE_NEWNET, 0, 0)) {
            int fd = (int)native_call(KER_TEST_OPEN, (unsigned long)"/proc/thread-self/ns/net", O_RDONLY | O_CLOEXEC, 0);
            if (fd >= 0) {
                strcpy(diag_namespaces[index].name, name); diag_namespaces[index].fd = fd;
                atomic_fetch_add(&namespaces_created, 1); result = 0;
            }
        }
    }
    pthread_mutex_unlock(&namespace_lock);
    return result;
}
static int diag_control(struct ms_message *m, unsigned char *data, size_t input, long *result)
{
    if (m->operation < MS_NEWNS || m->operation > MS_FILE_CHUNK) return 0;
    *result = -1;
    if (!input || data[input - 1]) { errno = EINVAL; return 1; }
    char *name = (char *)data;
    size_t length = strlen(name) + 1;
    if (length > input) { errno = EINVAL; return 1; }
    if (m->operation == MS_LISTNS) {
        size_t used = 0;
        pthread_mutex_lock(&namespace_lock);
        for (unsigned i = 0; i < 16; i++) if (diag_namespaces[i].fd >= 0)
            used += (size_t)snprintf((char *)data + used, MS_MAX - used, "%s\n", diag_namespaces[i].name);
        pthread_mutex_unlock(&namespace_lock);
        m->length = (uint32_t)used; *result = 0; return 1;
    }
    if (m->operation == MS_STATUS) {
        m->length = (uint32_t)snprintf((char *)data, MS_MAX, "{\"live\":%u,\"created\":%u,\"deleted\":%u}",
            atomic_load(&live), atomic_load(&namespaces_created), atomic_load(&namespaces_deleted));
        *result = 0; return 1;
    }
    if (m->operation == MS_NEWNS || m->operation == MS_DELNS) {
        if (length != input) { errno = EINVAL; return 1; }
        *result = namespace_change(m->operation, name); return 1;
    }
    int index;
    if (select_namespace(name, length, &index)) return 1;
    if (m->operation == MS_UP) {
        unsigned lo = if_nametoindex("lo");
        *result = lo ? native_call(KER_TEST_IF_UP, lo, 0, 0) : -1;
        return 1;
    }
    if (m->operation == MS_PIDS) {
        size_t used = 0;
        pthread_mutex_lock(&clients_lock);
        for (unsigned i = 0; i < clients_count; i++) {
            if (!atomic_load_explicit(&clients[i].active, memory_order_acquire) || clients[i].ns != index) continue;
            int duplicate = 0;
            for (unsigned j = 0; j < i; j++)
                if (atomic_load_explicit(&clients[j].active, memory_order_acquire) &&
                    clients[j].ns == index && clients[j].pid == clients[i].pid) duplicate = 1;
            if (!duplicate) used += (size_t)snprintf((char *)data + used, MS_MAX - used, "%ld\n", (long)clients[i].pid);
        }
        pthread_mutex_unlock(&clients_lock);
        m->length = (uint32_t)used; *result = 0; return 1;
    }
    if (m->operation == MS_NS_FD) {
        if (input != length || index < 0) { errno = EINVAL; return 1; }
        pthread_mutex_lock(&namespace_lock);
        *result = native_call(KER_TEST_FD_NUMBER, diag_namespaces[index].fd, 0, 0);
        pthread_mutex_unlock(&namespace_lock); return 1;
    }
    if (m->operation == MS_IFINDEX) {
        const char *device = (char *)data + length;
        if (input <= length || strlen(device) + length + 1 != input) { errno = EINVAL; return 1; }
        unsigned value = if_nametoindex(device); *result = value ? (long)value : -1; return 1;
    }
    char path[192];
    if (m->operation == MS_SYSCTL) {
        char *setting = (char *)data + length;
        if (input <= length || strlen(setting) + length + 1 != input || strncmp(setting, "net.", 4)) { errno = EINVAL; return 1; }
        char *equals = strchr(setting, '=');
        if (!equals || equals - setting > 128) { errno = EINVAL; return 1; }
        *equals++ = 0;
        snprintf(path, sizeof(path), "/proc/sys/%s", setting);
        for (char *p = path + 10; *p; p++) {
            if (*p == '.') *p = '/';
            else if (!((*p >= 'a' && *p <= 'z') || (*p >= '0' && *p <= '9') || *p == '_')) { errno = EINVAL; return 1; }
        }
        int fd = (int)native_call(KER_TEST_OPEN, (unsigned long)path, O_WRONLY, 0);
        if (fd < 0) return 1;
        ssize_t count = write(fd, equals, strlen(equals)); int error = errno;
        close(fd); errno = error;
        if (count == (ssize_t)strlen(equals)) *result = 0;
        else if (count >= 0) errno = EIO;
        return 1;
    }
    if (m->operation == MS_FILE || m->operation == MS_FILE_CHUNK) {
        const char *file = (char *)data + length;
        if (input <= length || strlen(file) + length + 1 != input) { errno = EINVAL; return 1; }
        const char *allowed[] = {"/proc/net/tcp", "/proc/net/tcp6", "/proc/net/protocols", "/proc/net/netstat",
            "/proc/net/snmp", "/proc/net/snmp6", "/proc/sys/net/mptcp/enabled", "/proc/kallsyms",
            "/proc/meminfo", "/proc/sys/net/ipv4/tcp_wmem", "/proc/sys/net/ipv4/tcp_rmem"};
        int found = 0;
        for (unsigned i = 0; i < sizeof(allowed) / sizeof(allowed[0]); i++) if (!strcmp(file, allowed[i])) found = 1;
        if (!found) { errno = EOPNOTSUPP; return 1; }
        /* /proc/net resolves via the process leader. The resident fixture has
         * several host threads in different native namespaces; select the
         * actual calling task, as each original standalone tool would do. */
        if (!strncmp(file, "/proc/net/", 10))
            snprintf(path, sizeof(path), "/proc/thread-self/net/%s", file + 10);
        else strcpy(path, file);
        int fd = (int)native_call(KER_TEST_OPEN, (unsigned long)path, O_RDONLY, 0);
        if (fd < 0) return 1;
        if (m->operation == MS_FILE_CHUNK) {
            if (lseek(fd, m->a, SEEK_SET) < 0) { int error = errno; close(fd); errno = error; return 1; }
            ssize_t got = read(fd, data, MS_MAX); int error = errno; close(fd); errno = error;
            if (got >= 0) { m->length = (uint32_t)got; *result = 0; }
            return 1;
        }
        size_t used = 0; ssize_t got;
        while (used < MS_MAX && (got = read(fd, data + used, MS_MAX - used)) > 0) used += (size_t)got;
        int error = errno; close(fd); errno = error;
        if (used == MS_MAX) { errno = EOVERFLOW; return 1; }
        if (got < 0) return 1;
        m->length = (uint32_t)used; *result = 0; return 1;
    }
    errno = EOPNOTSUPP; return 1;
}
