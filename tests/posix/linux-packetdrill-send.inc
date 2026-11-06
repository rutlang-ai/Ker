/* Test transport only. Preserve each original vector and its bytes. Native
 * MSG_ZEROCOPY buffers stay immutable until normal kernel shutdown, including
 * when the original test closes a socket before its completion arrives. */
static long packetdrill_send_vectors(int fd, unsigned count, unsigned char *data, size_t input)
{
    struct ms_io io;
    if (count > 64 || input < sizeof(io) + count * sizeof(uint32_t)) { errno = EINVAL; return -1; }
    memcpy(&io, data, sizeof(io));
    size_t prefix = sizeof(io) + count * sizeof(uint32_t);
    if (io.data > MS_MAX - prefix || io.control > MS_MAX - prefix - io.data ||
        io.name > sizeof(struct sockaddr_storage) ||
        input != prefix + io.data + io.control + io.name) { errno = EINVAL; return -1; }
    struct iovec vectors[64];
    size_t offset = 0;
    /* Validate the whole wire layout before allocating any native VMA. */
    for (unsigned i = 0; i < count; i++) {
        uint32_t size; memcpy(&size, data + sizeof(io) + i * sizeof(size), sizeof(size));
        if (size > io.data - offset) { errno = EINVAL; return -1; }
        offset += size;
    }
    if (offset != io.data) { errno = EINVAL; return -1; }
    offset = 0;
    void *(*allocate)(size_t) = dlsym(RTLD_DEFAULT, "ker_posix_buffer_alloc");
    int (*copy)(void *, size_t, const void *, size_t) = dlsym(RTLD_DEFAULT, "ker_posix_buffer_write");
    for (unsigned i = 0; i < count; i++) {
        uint32_t size; memcpy(&size, data + sizeof(io) + i * sizeof(size), sizeof(size));
        if (size > io.data - offset) { errno = EINVAL; return -1; }
        vectors[i].iov_base = data + prefix + offset;
        vectors[i].iov_len = size;
        if (size && (io.flags & MSG_ZEROCOPY)) {
            if (!allocate || !copy) { errno = EOPNOTSUPP; return -1; }
            vectors[i].iov_base = allocate(size);
            if (!vectors[i].iov_base || copy(vectors[i].iov_base, 0, data + prefix + offset, size) != (int)size) return -1;
        }
        offset += size;
    }
    if (offset != io.data) { errno = EINVAL; return -1; }
    struct msghdr message = {.msg_iov = vectors, .msg_iovlen = count,
        .msg_control = io.control ? data + prefix + io.data : NULL, .msg_controllen = io.control,
        .msg_name = io.name ? data + prefix + io.data + io.control : NULL, .msg_namelen = io.name};
    long result = sendmsg(fd, &message, (int)io.flags);
    atomic_fetch_add(&writes_count, 1);
    if (result >= 0) atomic_fetch_add(&sent_bytes, (unsigned long)result);
    return result;
}
