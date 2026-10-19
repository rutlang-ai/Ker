#define _GNU_SOURCE
#include "pcap.h"
#include "eal.h"
#include <dirent.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <rte_mbuf.h>
#define ERROR(call, code) do { errno = 0; CHECK((call) == -1); CHECK(errno == (code)); } while (0)
static const struct timespec stamp = {.tv_sec = 123456, .tv_nsec = 987654321};
static struct rte_mempool *pool;
static struct rte_mbuf *packet(const char *text)
{
    struct rte_mbuf *m = rte_pktmbuf_alloc(pool);
    CHECK(m);
    void *data = rte_pktmbuf_append(m, strlen(text));
    CHECK(data); memcpy(data, text, strlen(text));
    return m;
}
static FILE *read_header(const char *prefix, unsigned int slot, bool ns, uint32_t snaplen)
{
    char path[128];
    snprintf(path, sizeof(path), "%s-%u.pcap", prefix, slot);
    FILE *f = fopen(path, "rb"); CHECK(f);
    uint32_t magic, fields[4]; uint16_t version[2];
    CHECK(fread(&magic, sizeof(magic), 1, f) == 1);
    CHECK(magic == (ns ? UINT32_C(0xa1b23c4d) : UINT32_C(0xa1b2c3d4)));
    CHECK(fread(version, sizeof(version), 1, f) == 1);
    CHECK(version[0] == 2 && version[1] == 4);
    CHECK(fread(fields, sizeof(fields), 1, f) == 1);
    CHECK(fields[0] == 0 && fields[1] == 0 && fields[2] == snaplen && fields[3] == 1);
    return f;
}
static void record(FILE *f, bool ns, const char *bytes, uint32_t length, uint32_t original)
{
    uint32_t h[4]; unsigned char data[128];
    CHECK(length <= sizeof(data));
    CHECK(fread(h, sizeof(h), 1, f) == 1);
    CHECK(h[0] == 123456 && h[1] == (ns ? 987654321U : 987654U));
    CHECK(h[2] == length && h[3] == original);
    CHECK(fread(data, 1, length, f) == length);
    CHECK(memcmp(bytes, data, length) == 0);
}
static void basic_and_precision(void)
{
    for (unsigned int ns = 0; ns < 2; ++ns) {
        struct ker_pcap c;
        const char *prefix = ns ? "nano" : "micro";
        CHECK(ker_pcap_open(&c, NULL, prefix, 64, 4096, ns) == 0);
        struct stat st; char path[128];
        snprintf(path, sizeof(path), "%s-0.pcap", prefix);
        CHECK(stat(path, &st) == 0);
        struct rte_mbuf *m = packet("hello!");
        CHECK(ker_pcap_write(&c, m, &stamp) == 0);
        CHECK(ker_pcap_close(&c) == 0);
        FILE *f = read_header(prefix, 0, ns, 64);
        record(f, ns, "hello!", 6, 6);
        CHECK(fgetc(f) == EOF); CHECK(fclose(f) == 0);
        CHECK(m->pkt_len == 6 && rte_mbuf_refcnt_read(m) == 1);
        CHECK(memcmp(rte_pktmbuf_mtod(m, const void *), "hello!", 6) == 0);
        rte_pktmbuf_free(m);
    }
}
static void disabled_and_open_failure(void)
{
    struct ker_pcap c = {0}; struct rte_mbuf *m = packet("x");
    ERROR(ker_pcap_write(&c, m, &stamp), EBADF);
    ERROR(ker_pcap_open(&c, "missing/child", "bad", 64, 4096, false), ENOENT);
    CHECK(ker_pcap_close(&c) == 0);
    ERROR(ker_pcap_open(&c, ".", "bad", 0, 4096, false), EINVAL);
    CHECK(mkdir("cleanup-fail-3.pcap", 0700) == 0);
    ERROR(ker_pcap_open(&c, ".", "cleanup-fail", 64, 4096, false), EISDIR);
    CHECK(access("cleanup-fail-0.pcap", F_OK) == -1 && errno == ENOENT);
    CHECK(rmdir("cleanup-fail-3.pcap") == 0);
    rte_pktmbuf_free(m);
}
static void rotate_and_append(void)
{
    struct ker_pcap c; struct rte_mbuf *m = packet("x");
    CHECK(ker_pcap_open(&c, ".", "rolling", 64, 1, false) == 0);
    for (unsigned int i = 0; i < 12; ++i) {
        *rte_pktmbuf_mtod(m, char *) = 'a' + i;
        CHECK(ker_pcap_write(&c, m, &stamp) == 0);
    }
    CHECK(ker_pcap_close(&c) == 0);
    for (unsigned int i = 0; i < 10; ++i) {
        FILE *f = read_header("rolling", i, false, 64);
        char byte = 'a' + (i < 2 ? i + 10 : i);
        record(f, false, &byte, 1, 1);
        CHECK(fgetc(f) == EOF); CHECK(fclose(f) == 0);
    }
    CHECK(access("rolling-10.pcap", F_OK) == -1);
    /* Reopening a prefix removes stale rotation slots while preserving other
     * capture prefixes in the same directory. */
    FILE *other = fopen("other-1.pcap", "wb"); CHECK(other);
    CHECK(fclose(other) == 0);
    CHECK(ker_pcap_open(&c, ".", "rolling", 64, 4096, false) == 0);
    CHECK(ker_pcap_write(&c, m, &stamp) == 0);
    CHECK(ker_pcap_close(&c) == 0);
    FILE *fresh = read_header("rolling", 0, false, 64);
    record(fresh, false, "l", 1, 1);
    CHECK(fgetc(fresh) == EOF); CHECK(fclose(fresh) == 0);
    for (unsigned int i = 1; i < 10; ++i) {
        char path[128]; snprintf(path, sizeof(path), "rolling-%u.pcap", i);
        CHECK(access(path, F_OK) == -1 && errno == ENOENT);
    }
    CHECK(access("other-1.pcap", F_OK) == 0);
    CHECK(ker_pcap_open(&c, ".", "append", 64, 4096, false) == 0);
    CHECK(ker_pcap_write(&c, m, &stamp) == 0);
    CHECK(ker_pcap_write(&c, m, &stamp) == 0);
    CHECK(ker_pcap_close(&c) == 0);
    FILE *f = read_header("append", 0, false, 64);
    record(f, false, "l", 1, 1); record(f, false, "l", 1, 1);
    CHECK(fgetc(f) == EOF); CHECK(fclose(f) == 0);
    CHECK(access("append-1.pcap", F_OK) == -1);
    rte_pktmbuf_free(m);
}
static void multisegment_and_failures(void)
{
    struct ker_pcap c; struct rte_mbuf *m = packet("abcdef"), *tail = packet("ghijkl");
    CHECK(rte_pktmbuf_chain(m, tail) == 0);
    CHECK(ker_pcap_open(&c, ".", "chain", 8, 4096, false) == 0);
    CHECK(ker_pcap_write(&c, m, &stamp) == 0);
    uint32_t original = m->pkt_len;
    m->pkt_len++;
    ERROR(ker_pcap_write(&c, m, &stamp), EINVAL);
    m->pkt_len = original;
    tail->next = m;
    ERROR(ker_pcap_write(&c, m, &stamp), EINVAL);
    tail->next = NULL;
    m->nb_segs++;
    ERROR(ker_pcap_write(&c, m, &stamp), EINVAL);
    m->nb_segs--;
    struct timespec bad = {.tv_sec = 1, .tv_nsec = 1000000000};
    ERROR(ker_pcap_write(&c, m, &bad), EINVAL);
    CHECK(ker_pcap_close(&c) == 0);
    FILE *f = read_header("chain", 0, false, 8);
    record(f, false, "abcdefgh", 8, 12);
    CHECK(fgetc(f) == EOF); CHECK(fclose(f) == 0);
    CHECK(m->pkt_len == 12 && m->nb_segs == 2 && m->next == tail);
    CHECK(rte_mbuf_refcnt_read(m) == 1 && rte_mbuf_refcnt_read(tail) == 1);
    CHECK(memcmp(rte_pktmbuf_mtod(tail, const void *), "ghijkl", 6) == 0);
    /* Rotation failures and buffered write failures must reach the caller. */
    CHECK(ker_pcap_open(&c, ".", "rotate-fail", 8, 1, false) == 0);
    CHECK(ker_pcap_write(&c, m, &stamp) == 0);
    CHECK(mkdir("rotate-fail-1.pcap", 0700) == 0);
    ERROR(ker_pcap_write(&c, m, &stamp), EISDIR);
    CHECK(ker_pcap_close(&c) == -1);
    CHECK(rmdir("rotate-fail-1.pcap") == 0);
    CHECK(symlink("/dev/full", "full-0.pcap") == 0);
    CHECK(ker_pcap_open(&c, ".", "full", 8, 4096, false) == 0);
    (void)ker_pcap_write(&c, m, &stamp);
    CHECK(ker_pcap_close(&c) == -1);
    rte_pktmbuf_free(m);
}
int main(void)
{
    ker_test_eal_init();
    pool = rte_pktmbuf_pool_create("pcap-packets", 31, 0, 0, 2048, SOCKET_ID_ANY);
    CHECK(pool);
    char directory[] = "/tmp/ker-pcap-XXXXXX";
    char *previous = getcwd(NULL, 0); CHECK(previous);
    CHECK(mkdtemp(directory)); CHECK(chdir(directory) == 0);
    basic_and_precision(); disabled_and_open_failure(); rotate_and_append();
    multisegment_and_failures();
    CHECK(rte_mempool_in_use_count(pool) == 0);
    rte_mempool_free(pool);
    DIR *dir = opendir("."); CHECK(dir); struct dirent *entry;
    while ((entry = readdir(dir))) if (strcmp(entry->d_name, ".") && strcmp(entry->d_name, ".."))
        CHECK(unlink(entry->d_name) == 0);
    CHECK(closedir(dir) == 0); CHECK(chdir(previous) == 0); free(previous);
    CHECK(rmdir(directory) == 0); CHECK(rte_eal_cleanup() == 0);
    puts("PASS: F-Stack PCAP scenarios, real DPDK chains, rotation and I/O failures");
    return 0;
}
