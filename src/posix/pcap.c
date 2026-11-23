#define _GNU_SOURCE
#include "pcap.h"
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <rte_mbuf.h>

/* Classic PCAP, native byte order, Ethernet linktype; the magic identifies
 * byte order and timestamp units. Encode fields individually, without padding. */
static int output(struct ker_pcap *c, const void *bytes, size_t length)
{
    if (fwrite(bytes, 1, length, c->file) == length) {
        c->bytes += length;
        return 0;
    }
    c->failed = true;
    if (!errno) errno = EIO;
    return -1;
}
static int open_slot(struct ker_pcap *c)
{
    char *path;
    if (asprintf(&path, "%s/%s-%u.pcap", c->directory, c->prefix, c->slot) < 0)
        return -1;
    c->file = fopen(path, "wb");
    free(path);
    if (!c->file) return -1;
    c->bytes = 0;
    uint32_t magic = c->nanoseconds ? UINT32_C(0xa1b23c4d) : UINT32_C(0xa1b2c3d4);
    uint16_t version[] = {2, 4};
    uint32_t fields[] = {0, 0, c->snaplen, 1};
    return output(c, &magic, sizeof(magic)) || output(c, version, sizeof(version)) ||
        output(c, fields, sizeof(fields)) ? -1 : 0;
}
int ker_pcap_close(struct ker_pcap *c)
{
    int result = c->failed ? -1 : 0;
    int saved = c->failed ? EIO : 0;
    if (c->file && fclose(c->file)) { result = -1; saved = errno; }
    free(c->directory);
    free(c->prefix);
    memset(c, 0, sizeof(*c));
    if (result) errno = saved;
    return result;
}
int ker_pcap_open(struct ker_pcap *c, const char *directory, const char *prefix,
    uint32_t snaplen, uint64_t maximum, bool nanoseconds)
{
    /* The caller must close an existing capture before reopening it. */
    if (!c || !prefix || !*prefix || strchr(prefix, '/') || !snaplen || !maximum) {
        errno = EINVAL; return -1;
    }
    memset(c, 0, sizeof(*c));
    c->directory = strdup(directory ? directory : ".");
    if (!c->directory) return -1;
    c->prefix = strdup(prefix);
    if (!c->prefix) { free(c->directory); c->directory = NULL; return -1; }
    c->snaplen = snaplen;
    c->maximum = maximum;
    c->nanoseconds = nanoseconds;
    /* A reused capture prefix starts a new stream. Slot 0 is truncated by
     * open_slot(); remove older rotation slots first so readers cannot mix
     * packets from the previous run with this one. */
    for (unsigned int slot = 1; slot < 10; ++slot) {
        char *path;
        if (asprintf(&path, "%s/%s-%u.pcap", c->directory, c->prefix, slot) < 0) {
            int saved = errno ? errno : ENOMEM;
            (void)ker_pcap_close(c);
            errno = saved;
            return -1;
        }
        int result = unlink(path);
        int saved = errno;
        free(path);
        if (result && saved != ENOENT) {
            (void)ker_pcap_close(c);
            errno = saved;
            return -1;
        }
    }
    if (!open_slot(c)) return 0;
    int saved = errno;
    (void)ker_pcap_close(c);
    errno = saved;
    return -1;
}
int ker_pcap_write(struct ker_pcap *c, const struct rte_mbuf *packet,
    const struct timespec *timestamp)
{
    if (!c || !c->file) { errno = EBADF; return -1; }
    if (c->failed) { errno = EIO; return -1; }
    if (!packet || !timestamp || timestamp->tv_sec < 0 ||
        (uint64_t)timestamp->tv_sec > UINT32_MAX || timestamp->tv_nsec < 0 ||
        timestamp->tv_nsec >= 1000000000) { errno = EINVAL; return -1; }
    /* Reject malformed chains before writing any record header. Bound the walk
     * by nb_segs so a cycle cannot hang packet I/O. */
    uint64_t total = 0;
    const struct rte_mbuf *segment = packet;
    for (unsigned int i = 0; i < packet->nb_segs; ++i) {
        if (!segment || segment->data_off > segment->buf_len ||
            segment->data_len > segment->buf_len - segment->data_off) {
            errno = EINVAL; return -1;
        }
        total += segment->data_len;
        segment = segment->next;
    }
    if (segment || !packet->nb_segs || total != packet->pkt_len) { errno = EINVAL; return -1; }
    /* Rotate between complete records. A record may exceed the soft byte limit;
     * ten slots bound disk usage to ten (header + limit + largest record). */
    if (c->bytes > 24 && c->bytes >= c->maximum) {
        FILE *previous = c->file;
        c->file = NULL;
        if (fclose(previous)) { c->failed = true; return -1; }
        c->slot = (c->slot + 1) % 10;
        if (open_slot(c)) { c->failed = true; return -1; }
    }
    uint32_t captured = packet->pkt_len < c->snaplen ? packet->pkt_len : c->snaplen;
    uint32_t header[] = {(uint32_t)timestamp->tv_sec,
        (uint32_t)(c->nanoseconds ? timestamp->tv_nsec : timestamp->tv_nsec / 1000),
        captured, packet->pkt_len};
    if (output(c, header, sizeof(header))) return -1;
    for (segment = packet; captured; segment = segment->next) {
        uint32_t length = segment->data_len < captured ? segment->data_len : captured;
        if (output(c, rte_pktmbuf_mtod(segment, const void *), length)) return -1;
        captured -= length;
    }
    return 0;
}
