#ifndef KER_SOURCE_NATIVE_INI_H
#define KER_SOURCE_NATIVE_INI_H

#include <ker/socket-broker.h>
#include <arpa/inet.h>
#include <errno.h>
#include <ctype.h>
#include <ker/ini.h>
#include <limits.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define KER_SOURCE_NATIVE_INI_PATH_MAX 4096
#define KER_SOURCE_NATIVE_INI_SEEN_ALL UINT32_C(0x1fff)
#define KER_SOURCE_NATIVE_INI_KNI_FIELDS UINT32_C(0x3e000)
#define KER_SOURCE_NATIVE_EAL_PREFIX_MAX 64
#define KER_SOURCE_NATIVE_INI_BYTES_MAX 16384
#define KER_SOURCE_NATIVE_INI_LINE_MAX 2047
#define KER_SOURCE_NATIVE_INI_SNAPSHOT_VERSION UINT32_C(2)

struct ker_source_native_ini {
    char broker_path[KER_SOCKET_BROKER_PATH_MAX + 1];
    char file_prefix[65];
    char log_prefix[KER_SOURCE_NATIVE_INI_PATH_MAX];
    char lcore_mask[4];
    char address[INET_ADDRSTRLEN];
    char netmask[INET_ADDRSTRLEN];
    char broadcast[INET_ADDRSTRLEN];
    char gateway[INET_ADDRSTRLEN];
    uint32_t seen;
    unsigned source_process_count;
};

/* This is an adapter-cycle snapshot, not an imported Nginx generation or
 * source-bootstrap epoch. The callback verifies its opaque cycle identity
 * against the process's current ngx_cycle before returning it. */
struct ker_source_native_ini_cycle_snapshot {
    uint32_t version;
    uint32_t size;
    struct ker_source_native_ini config;
    uint8_t config_sha256[32];
    uint8_t ini_sha256[32];
    uint64_t adapter_cycle_serial;
    uintptr_t cycle_identity;
    char ini_path[KER_SOURCE_NATIVE_INI_PATH_MAX];
};
_Static_assert(sizeof(struct ker_source_native_ini_cycle_snapshot) <= UINT32_MAX,
    "source INI snapshot ABI size must fit the versioned size field");

static inline int
ker_source_native_ini_snapshot_abi_valid(
    const struct ker_source_native_ini_cycle_snapshot *snapshot)
{
    return snapshot && snapshot->version == KER_SOURCE_NATIVE_INI_SNAPSHOT_VERSION &&
        snapshot->size == sizeof(*snapshot);
}

static inline int
ker_source_native_ini_snapshot_matches_cycle(
    const struct ker_source_native_ini_cycle_snapshot *snapshot,
    uintptr_t current_cycle_identity)
{
    return snapshot && current_cycle_identity &&
        snapshot->cycle_identity == current_cycle_identity &&
        snapshot->adapter_cycle_serial != 0;
}

int ker_nginx_source_native_ini_snapshot_read(
    struct ker_source_native_ini_cycle_snapshot *snapshot);

struct ker_source_native_ini_input {
    const char *bytes;
    size_t length;
    size_t offset;
};

static inline FILE *
ker_source_native_ini_open(const char *path)
{
    struct stat st;
    if (!path || !*path) { errno = EINVAL; return NULL; }
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (fd < 0) return NULL;
    if (fstat(fd, &st) < 0) {
        int saved = errno;
        close(fd);
        errno = saved;
        return NULL;
    }
    if (!S_ISREG(st.st_mode) || st.st_uid != geteuid() || st.st_size < 0 ||
        (uint64_t)st.st_size > KER_SOURCE_NATIVE_INI_BYTES_MAX) {
        close(fd);
        errno = !S_ISREG(st.st_mode) ? EINVAL :
            (st.st_uid != geteuid() ? EACCES : EFBIG);
        return NULL;
    }
    FILE *file = fdopen(fd, "r");
    if (!file) {
        int saved = errno;
        close(fd);
        errno = saved;
    }
    return file;
}

static inline char *
ker_source_native_ini_memory_reader(char *line, int capacity, void *opaque)
{
    struct ker_source_native_ini_input *input = opaque;
    if (!input || !line || capacity < 2 || input->offset >= input->length)
        return NULL;
    size_t count = 0;
    while (input->offset < input->length && count + 1 < (size_t)capacity) {
        char ch = input->bytes[input->offset++];
        line[count++] = ch;
        if (ch == '\n') break;
    }
    line[count] = '\0';
    return line;
}

static inline int
ker_source_native_ini_kni_enabled(void)
{
    const char *value = getenv("KER_NGINX_SOURCE_KNI_ENABLE");
    return value && !strcmp(value, "1");
}

static inline int
ker_source_native_ini_serial_enabled(void)
{
    const char *path = getenv("KER_NGINX_SOURCE_SERIAL_PATH");
    return path && path[0] == '/';
}

static inline uint32_t
ker_source_native_ini_expected_fields(void)
{
    return KER_SOURCE_NATIVE_INI_SEEN_ALL |
        (ker_source_native_ini_kni_enabled() ? KER_SOURCE_NATIVE_INI_KNI_FIELDS : 0);
}

/* Validate section records across the complete captured file. The upstream
 * inih callback only reports key/value records, so it cannot reject empty,
 * unknown, or repeated sections on its own. */
static inline int
ker_source_native_ini_validate_sections(const char *bytes, size_t length)
{
    uint32_t seen = 0;
    size_t offset = 0;
    unsigned line_number = 0;
    while (offset < length) {
        size_t end = offset;
        while (end < length && bytes[end] != '\n') end++;
        size_t first = offset, last = end;
        line_number++;
        if (last > first && bytes[last - 1] == '\r') last--;
        if (line_number == 1 && last - first >= 3 &&
            (unsigned char)bytes[first] == 0xef &&
            (unsigned char)bytes[first + 1] == 0xbb &&
            (unsigned char)bytes[first + 2] == 0xbf) first += 3;
        while (first < last && isspace((unsigned char)bytes[first])) first++;
        while (last > first && isspace((unsigned char)bytes[last - 1])) last--;
        size_t line_bytes = end - offset + (end < length ? 1 : 0);
        if (line_bytes > KER_SOURCE_NATIVE_INI_LINE_MAX) return -E2BIG;
        if (first < last && bytes[first] == '[') {
            size_t close = first + 1;
            while (close < last && bytes[close] != ']' &&
                bytes[close] != ';' && bytes[close] != '#') close++;
            if (close >= last || bytes[close] != ']') return -EINVAL;
            size_t tail = close + 1;
            while (tail < last && isspace((unsigned char)bytes[tail])) tail++;
            if (tail < last && bytes[tail] != ';' && bytes[tail] != '#')
                return -EINVAL;
            size_t name_length = close - first - 1;
            uint32_t bit;
            if (name_length == sizeof("ker_socket_broker") - 1 &&
                !memcmp(bytes + first + 1, "ker_socket_broker", name_length))
                bit = 1u;
            else if (name_length == sizeof("dpdk") - 1 &&
                !memcmp(bytes + first + 1, "dpdk", name_length)) bit = 2u;
            else if (name_length == sizeof("port0") - 1 &&
                !memcmp(bytes + first + 1, "port0", name_length)) bit = 4u;
            else if (ker_source_native_ini_kni_enabled() && name_length == sizeof("kni") - 1 &&
                !memcmp(bytes + first + 1, "kni", name_length)) bit = 8u;
            else return -EINVAL;
            if (seen & bit) return -EINVAL;
            seen |= bit;
        }
        offset = end + (end < length ? 1 : 0);
    }
    uint32_t expected = ker_source_native_ini_kni_enabled() ? 15u : 7u;
    return seen == expected ? 0 : -EINVAL;
}

static inline int
ker_source_native_ini_parse_file_capture(FILE *file, ker_ini_handler handler,
    void *user, char *captured, size_t captured_capacity, size_t *captured_length)
{
    if (!file || !handler || ((captured == NULL) != (captured_length == NULL)))
        return -EINVAL;
    char *bytes = malloc(KER_SOURCE_NATIVE_INI_BYTES_MAX + 1);
    if (!bytes) return -ENOMEM;
    size_t length = fread(bytes, 1, KER_SOURCE_NATIVE_INI_BYTES_MAX + 1, file);
    int result = 0;
    if (ferror(file)) result = -EIO;
    else if (length > KER_SOURCE_NATIVE_INI_BYTES_MAX ||
        memchr(bytes, '\0', length)) result = -E2BIG;
    else if ((result = ker_source_native_ini_validate_sections(bytes, length)) == 0) {
        struct ker_source_native_ini_input input = {bytes, length, 0};
        result = ker_ini_parse_stream(ker_source_native_ini_memory_reader,
            &input, handler, user);
    }
    if (!result && captured) {
        if (length > captured_capacity) result = -ENOSPC;
        else {
            memcpy(captured, bytes, length);
            *captured_length = length;
        }
    }
    free(bytes);
    return result;
}

static inline int
ker_source_native_ini_parse_file(FILE *file, ker_ini_handler handler, void *user)
{
    return ker_source_native_ini_parse_file_capture(file, handler, user,
        NULL, 0, NULL);
}

static inline int
ker_source_native_ini_field(struct ker_source_native_ini *config,
    uint32_t bit, char *destination, size_t capacity, const char *value)
{
    size_t length;
    if ((config->seen & bit) || !value) return 0;
    length = strnlen(value, capacity);
    if (!length || length >= capacity) return 0;
    memcpy(destination, value, length + 1);
    config->seen |= bit;
    return 1;
}

static inline int
ker_source_native_ini_ipv4(const char *text, struct in_addr *address)
{
    if (!text || !*text || strnlen(text, INET_ADDRSTRLEN) >= INET_ADDRSTRLEN ||
        inet_pton(AF_INET, text, address) != 1)
        return -EINVAL;
    return 0;
}

/* The source profile supports ordinary IPv4 subnets only. Preserve the
 * original values; reject unsupported point-to-point prefixes, custom
 * broadcasts, and off-link gateways instead of silently projecting them. */
static inline int
ker_source_native_ini_network_valid(const struct ker_source_native_ini *config)
{
    struct in_addr address, netmask, broadcast, gateway;
    if (!config || ker_source_native_ini_ipv4(config->address, &address) ||
        ker_source_native_ini_ipv4(config->netmask, &netmask) ||
        ker_source_native_ini_ipv4(config->broadcast, &broadcast) ||
        ker_source_native_ini_ipv4(config->gateway, &gateway))
        return -EINVAL;

    uint32_t host_address = ntohl(address.s_addr);
    uint32_t host_mask = ntohl(netmask.s_addr);
    uint32_t host_broadcast = ntohl(broadcast.s_addr);
    uint32_t host_gateway = ntohl(gateway.s_addr);
    uint32_t inverse_mask = ~host_mask;
    if (!host_mask || (inverse_mask & (inverse_mask + 1u)) != 0)
        return -EINVAL;

    unsigned prefix = 0;
    for (uint32_t bit = UINT32_C(0x80000000); bit && (host_mask & bit); bit >>= 1)
        prefix++;
    if (prefix < 1 || prefix > 30) return -EOPNOTSUPP;

    uint32_t network = host_address & host_mask;
    uint32_t expected_broadcast = network | inverse_mask;
    uint32_t address_first_octet = host_address >> 24;
    uint32_t gateway_first_octet = host_gateway >> 24;
    if (address_first_octet < 1 || address_first_octet > 223 ||
        address_first_octet == 127 ||
        (host_address & UINT32_C(0xf0000000)) == UINT32_C(0xe0000000) ||
        host_address == network || host_address == expected_broadcast ||
        host_broadcast != expected_broadcast ||
        gateway_first_octet < 1 || gateway_first_octet > 223 ||
        gateway_first_octet == 127 ||
        (host_gateway & UINT32_C(0xf0000000)) == UINT32_C(0xe0000000) ||
        (host_gateway & host_mask) != network || host_gateway == network ||
        host_gateway == expected_broadcast || host_gateway == host_address)
        return -EINVAL;
    return 0;
}

static inline int
ker_source_native_ini_parse(void *opaque, const char *section,
    const char *name, const char *value)
{
    struct ker_source_native_ini *config = opaque;
    if (!config || !section || !name || !value) return 0;
    bool serial = ker_source_native_ini_serial_enabled();
    const char *profile_flag = serial ? "0" : "1";
    const char *mask = serial ? "1" : "3";
    const char *hex_mask = serial ? "0x1" : "0x3";
    if (!strcmp(section, "ker_socket_broker")) {
        if (!strcmp(name, "version") && !(config->seen & (1u << 0)) &&
            !strcmp(value, "1")) {
            config->seen |= 1u << 0;
            return 1;
        }
        if (!strcmp(name, "path") &&
            ker_source_native_ini_field(config, 1u << 1,
                config->broker_path, sizeof(config->broker_path), value) &&
            config->broker_path[0] == '/') return 1;
        return 0;
    }
    if (!strcmp(section, "dpdk")) {
        if (!strcmp(name, "graceful_reload") && !strcmp(value, profile_flag) &&
            !(config->seen & (1u << 2))) {
            config->seen |= 1u << 2;
            return 1;
        }
        if (!strcmp(name, "lcore_mask") && !(config->seen & (1u << 3)) &&
            (!strcmp(value, mask) || !strcmp(value, hex_mask))) {
            memcpy(config->lcore_mask, value, strlen(value) + 1);
            config->source_process_count = serial ? 1 : 2;
            config->seen |= 1u << 3;
            return 1;
        }
        if (!strcmp(name, "primary_slim") && !strcmp(value, profile_flag) &&
            !(config->seen & (1u << 4))) {
            config->seen |= 1u << 4;
            return 1;
        }
        if (!strcmp(name, "file_prefix") &&
            ker_source_native_ini_field(config, 1u << 5,
                config->file_prefix, sizeof(config->file_prefix), value)) {
            size_t n = strlen(config->file_prefix);
            if (!strcmp(config->file_prefix, ".") ||
                !strcmp(config->file_prefix, "..")) return 0;
            for (size_t i = 0; i < n; ++i) {
                unsigned char ch = (unsigned char)config->file_prefix[i];
                if (!((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
                    (ch >= '0' && ch <= '9') || ch == '_' || ch == '-' || ch == '.'))
                    return 0;
            }
            return 1;
        }
        if (!strcmp(name, "fstack_log_file_prefix") &&
            ker_source_native_ini_field(config, 1u << 6,
                config->log_prefix, sizeof(config->log_prefix), value)) return 1;
        if (!strcmp(name, "fstack_log_level") && !strcmp(value, "0") &&
            !(config->seen & (1u << 7))) {
            config->seen |= 1u << 7;
            return 1;
        }
        return 0;
    }
    if (!strcmp(section, "kni") && ker_source_native_ini_kni_enabled()) {
        static const struct {
            const char *name;
            const char *value;
        } options[] = {
            {"enable", "1"}, {"method", "reject"}, {"owner_proc_id", "1"},
            {"tcp_port", "80,443"}, {"udp_port", "53"},
        };
        for (size_t index = 0; index < sizeof(options) / sizeof(options[0]); ++index) {
            uint32_t bit = UINT32_C(1) << (13 + index);
            if (!strcmp(name, options[index].name) && !strcmp(value, options[index].value) &&
                    !(config->seen & bit)) {
                config->seen |= bit;
                return 1;
            }
        }
        return 0;
    }
    if (!strcmp(section, "port0")) {
        if (!strcmp(name, "lcore_list") && !strcmp(value, profile_flag) &&
            !(config->seen & (1u << 8))) {
            config->seen |= 1u << 8;
            return 1;
        }
        if (!strcmp(name, "addr") &&
            !ker_source_native_ini_ipv4(value, &(struct in_addr){0}) &&
            ker_source_native_ini_field(config, 1u << 9,
                config->address, sizeof(config->address), value)) return 1;
        if (!strcmp(name, "netmask") &&
            !ker_source_native_ini_ipv4(value, &(struct in_addr){0}) &&
            ker_source_native_ini_field(config, 1u << 10,
                config->netmask, sizeof(config->netmask), value)) return 1;
        if (!strcmp(name, "broadcast") &&
            !ker_source_native_ini_ipv4(value, &(struct in_addr){0}) &&
            ker_source_native_ini_field(config, 1u << 11,
                config->broadcast, sizeof(config->broadcast), value)) return 1;
        if (!strcmp(name, "gateway") &&
            !ker_source_native_ini_ipv4(value, &(struct in_addr){0}) &&
            ker_source_native_ini_field(config, 1u << 12,
                config->gateway, sizeof(config->gateway), value)) return 1;
    }
    return 0;
}

static inline int
ker_source_native_ini_finish(const struct ker_source_native_ini *config,
    const char *ini_path)
{
    char expected[KER_SOURCE_NATIVE_INI_PATH_MAX];
    const char *slash;
    size_t path_length, directory_length, prefix_length;
    bool serial = ker_source_native_ini_serial_enabled();
    if (!config || config->seen != ker_source_native_ini_expected_fields() ||
        (serial && ker_source_native_ini_kni_enabled()) ||
        config->source_process_count != (serial ? 1u : 2u) ||
        !ini_path || ini_path[0] != '/')
        return -EINVAL;
    int network_status = ker_source_native_ini_network_valid(config);
    if (network_status) return network_status;
    path_length = strnlen(ini_path, sizeof(expected));
    if (!path_length || path_length >= sizeof(expected)) return -ENAMETOOLONG;
    slash = strrchr(ini_path, '/');
    if (!slash || !slash[1]) return -EINVAL;
    for (const char *part = ini_path; part < ini_path + path_length;) {
        const char *end = memchr(part, '/', (size_t)(ini_path + path_length - part));
        size_t length = end ? (size_t)(end - part) : (size_t)(ini_path + path_length - part);
        if (length == 2 && part[0] == '.' && part[1] == '.') return -EINVAL;
        part += length + (end ? 1 : 0);
    }
    directory_length = (size_t)(slash - ini_path) + 1;
    prefix_length = sizeof("fstack-") - 1;
    if (directory_length + prefix_length >= sizeof(expected)) return -ENAMETOOLONG;
    memcpy(expected, ini_path, directory_length);
    memcpy(expected + directory_length, "fstack-", prefix_length + 1);
    return strcmp(config->log_prefix, expected) ? -EINVAL : 0;
}

static inline int
ker_source_native_io_argv_validate(char *const argv[], size_t argc,
    const struct ker_source_native_ini *config, const uint8_t nonce[16],
    uint64_t epoch)
{
    struct option { const char *name; bool takes_value; };
    static const struct option options[] = {
        {"--rss", false}, {"--numa", false}, {"--no-numa", false},
        {"--promiscuous", false}, {"--no-promiscuous", false},
        {"--all-multicast", false}, {"--pcap-nsec", false},
        {"--exception-mode", true}, {"--exception-policy", true},
        {"--exception-tcp-ports", true}, {"--exception-udp-ports", true},
        {"--exception-iface", true}, {"--exception-type", true},
        {"--exception-queue", true}, {"--exception-console-rate", true},
        {"--exception-general-rate", true}, {"--exception-rate", true},
        {"--tx-delay-us", true}, {"--idle-sleep-us", true},
        {"--packet-fd", true}, {"--rx-decision-fd", true},
        {"--queue-proof-session", true}, {"--queue-proof-epoch", true},
        {"--queue-proof-source-proc-id", true}, {"--bond-policy", true},
        {"--tx-offloads", true}, {"--rx-lcores", true}, {"--queues", true},
        {"--mtu-fd", true}, {"--max-mtu", true}, {"--control-fd", true},
        {"--port", true}, {"--mbuf-mode", true}, {"--mtu", true},
        {"--log-dir", true}, {"--log-level", true}, {"--pcap-dir", true},
        {"--pcap-snaplen", true}, {"--pcap-max-bytes", true}
    };
    static const struct { const char *name; const char *value; } kni[] = {
        {"--exception-mode", "ports"}, {"--exception-policy", "reject"},
        {"--exception-tcp-ports", "80,443"}, {"--exception-udp-ports", "53"},
        {"--exception-iface", "kerkni"},
    };
    size_t kni_matches = 0;
    bool kni_enabled = ker_source_native_ini_kni_enabled();
    size_t split = 0;
    const char *queues = NULL, *rx_lcores = NULL, *port = NULL;
    const char *proof_nonce = NULL, *proof_epoch = NULL, *source_proc = NULL;
    const char *decision_fd = NULL;
    unsigned char option_seen[(sizeof(options) / sizeof(options[0]) + 7) / 8] = {0};
    char expected_nonce[33], expected_epoch[32];
    char expected_prefix[KER_SOURCE_NATIVE_EAL_PREFIX_MAX + 1];
    if (!argv || argc < 2 || !config || !nonce || !epoch ||
        config->seen != ker_source_native_ini_expected_fields()) return -EINVAL;
    for (size_t i = 0; i < argc; ++i) {
        if (!argv[i] || !*argv[i]) return -EINVAL;
    }
    for (split = 1; split < argc && strcmp(argv[split], "--");) {
        size_t option_index;
        for (option_index = 0; option_index < sizeof(options) / sizeof(options[0]);
            ++option_index)
            if (!strcmp(argv[split], options[option_index].name)) break;
        if (option_index == sizeof(options) / sizeof(options[0])) return -EINVAL;
        unsigned char bit = (unsigned char)(1u << (option_index % 8));
        unsigned char *byte = &option_seen[option_index / 8];
        if (*byte & bit) return -EINVAL;
        *byte |= bit;
        const char *value = NULL;
        if (options[option_index].takes_value) {
            if (split + 1 >= argc || !strcmp(argv[split + 1], "--")) return -EINVAL;
            value = argv[split + 1];
            split += 2;
        } else {
            split++;
        }
        const char *name = options[option_index].name;
        if (kni_enabled) {
            for (size_t i = 0; i < sizeof(kni) / sizeof(kni[0]); ++i) {
                if (strcmp(name, kni[i].name)) continue;
                if (strcmp(value, kni[i].value)) return -EINVAL;
                ++kni_matches;
                break;
            }
        }
        if (!strcmp(name, "--queues")) queues = value;
        else if (!strcmp(name, "--rx-lcores")) rx_lcores = value;
        else if (!strcmp(name, "--port")) port = value;
        else if (!strcmp(name, "--queue-proof-session")) proof_nonce = value;
        else if (!strcmp(name, "--queue-proof-epoch")) proof_epoch = value;
        else if (!strcmp(name, "--queue-proof-source-proc-id")) source_proc = value;
        else if (!strcmp(name, "--rx-decision-fd")) decision_fd = value;
    }
    if (kni_enabled && kni_matches != sizeof(kni) / sizeof(kni[0])) return -EINVAL;
    if (split >= argc || strcmp(argv[split], "--") || !queues ||
        strcmp(queues, "1") || !rx_lcores || strcmp(rx_lcores, "1") ||
        !port || !*port || !proof_nonce || !proof_epoch || !source_proc ||
        strcmp(source_proc, "1") || !decision_fd || !*decision_fd) return -EINVAL;
    unsigned long parsed_fd = 0;
    for (const char *digit = decision_fd; *digit; ++digit) {
        if (*digit < '0' || *digit > '9' || parsed_fd > ((unsigned long)INT_MAX -
            (unsigned long)(*digit - '0')) / 10) return -EINVAL;
        parsed_fd = parsed_fd * 10 + (unsigned long)(*digit - '0');
    }
    if (parsed_fd < 3) return -EINVAL;
    if (snprintf(expected_nonce, sizeof(expected_nonce),
            "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
            nonce[0],nonce[1],nonce[2],nonce[3],nonce[4],nonce[5],nonce[6],nonce[7],
            nonce[8],nonce[9],nonce[10],nonce[11],nonce[12],nonce[13],nonce[14],nonce[15]) < 0 ||
        snprintf(expected_epoch, sizeof(expected_epoch), "%llu", (unsigned long long)epoch) < 0 ||
        strcmp(proof_nonce, expected_nonce) || strcmp(proof_epoch, expected_epoch))
        return -EINVAL;
    size_t prefix_length = strlen(config->file_prefix);
    const size_t decoration_length = sizeof("container-") - 1;
    if (decoration_length > KER_SOURCE_NATIVE_EAL_PREFIX_MAX ||
        prefix_length > KER_SOURCE_NATIVE_EAL_PREFIX_MAX - decoration_length)
        return -EINVAL;
    memcpy(expected_prefix, "container-", decoration_length);
    memcpy(expected_prefix + decoration_length, config->file_prefix,
        prefix_length + 1);
    unsigned prefix_count = 0, vdev_count = 0;
    const char *prefix = NULL;
    bool port_vdev_match = false;
    for (size_t i = split + 1; i < argc; ++i) {
        const char *vdev = NULL;
        if (!strcmp(argv[i], "--")) return -EINVAL;
        if (!strncmp(argv[i], "--file-prefix=", sizeof("--file-prefix=") - 1)) {
            if (++prefix_count != 1) return -EINVAL;
            prefix = argv[i] + sizeof("--file-prefix=") - 1;
        } else if (!strcmp(argv[i], "--file-prefix")) {
            if (++prefix_count != 1 || i + 1 >= argc || !*argv[i + 1] ||
                !strcmp(argv[i + 1], "--")) return -EINVAL;
            prefix = argv[++i];
        } else if (!strncmp(argv[i], "--vdev=", sizeof("--vdev=") - 1)) {
            vdev = argv[i] + sizeof("--vdev=") - 1;
        } else if (!strcmp(argv[i], "--vdev")) {
            if (i + 1 >= argc || !*argv[i + 1] || !strcmp(argv[i + 1], "--"))
                return -EINVAL;
            vdev = argv[++i];
        }
        if (vdev) {
            size_t name_length = strcspn(vdev, ",");
            if (++vdev_count != 1 || !name_length || strlen(port) != name_length ||
                memcmp(vdev, port, name_length)) return -EINVAL;
            port_vdev_match = true;
        }
    }
    return prefix_count == 1 && prefix && !strcmp(prefix, expected_prefix) &&
        vdev_count == 1 && port_vdev_match ? 0 : -EINVAL;
}

#endif
