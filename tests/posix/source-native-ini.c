#include "source-native-ini.h"
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #x); return 1; } } while (0)

static int add(struct ker_source_native_ini *config, const char *section,
    const char *name, const char *value)
{
    return ker_source_native_ini_parse(config, section, name, value);
}
static int valid(struct ker_source_native_ini *c, const char *mask)
{
    memset(c, 0, sizeof(*c));
    return add(c,"ker_socket_broker","version","1") &&
        add(c,"ker_socket_broker","path","/run/ker/broker.sock") &&
        add(c,"dpdk","graceful_reload","1") &&
        add(c,"dpdk","lcore_mask",mask) &&
        add(c,"dpdk","primary_slim","1") &&
        add(c,"dpdk","file_prefix","run_7f3a") &&
        add(c,"dpdk","fstack_log_file_prefix","/tmp/native/fstack-") &&
        add(c,"dpdk","fstack_log_level","0") &&
        add(c,"port0","lcore_list","1") &&
        add(c,"port0","addr","192.168.1.2") &&
        add(c,"port0","netmask","255.255.255.0") &&
        add(c,"port0","broadcast","192.168.1.255") &&
        add(c,"port0","gateway","192.168.1.1");
}
static int parse_text(const char *text)
{
    struct ker_source_native_ini config = {0};
    size_t length = strlen(text);
    FILE *file = fmemopen((void *)text, length, "r");
    if (!file) return -1;
    int result = ker_source_native_ini_parse_file(file,
        ker_source_native_ini_parse, &config);
    if (!result) result = ker_source_native_ini_finish(&config,
        "/tmp/native/fstack.conf");
    if (fclose(file) != 0 && !result) result = -1;
    return result;
}
static int parse_network_text(const char *address, const char *netmask,
    const char *broadcast, const char *gateway)
{
    char text[1024];
    int length = snprintf(text, sizeof(text),
        "[ker_socket_broker]\nversion=1\npath=/run/ker/broker.sock\n"
        "[dpdk]\ngraceful_reload=1\nlcore_mask=3\nprimary_slim=1\n"
        "file_prefix=run_7f3a\nfstack_log_file_prefix=/tmp/native/fstack-\n"
        "fstack_log_level=0\n[port0]\nlcore_list=1\naddr=%s\nnetmask=%s\n"
        "broadcast=%s\ngateway=%s\n", address, netmask, broadcast, gateway);
    if (length < 0 || (size_t)length >= sizeof(text)) return -1;
    return parse_text(text);
}
static int capture_controls(const char *text)
{
    struct ker_source_native_ini config = {0};
    char captured[KER_SOURCE_NATIVE_INI_BYTES_MAX];
    size_t captured_length = 0;
    size_t length = strlen(text);
    FILE *file = fmemopen((void *)text, length, "r");
    if (!file) return 0;
    int result = ker_source_native_ini_parse_file_capture(file,
        ker_source_native_ini_parse, &config, captured, sizeof(captured),
        &captured_length);
    if (fclose(file) != 0 || result || captured_length != length ||
        memcmp(captured, text, length) != 0) return 0;

    file = fmemopen((void *)text, length, "r");
    if (!file) return 0;
    memset(&config, 0, sizeof(config));
    size_t sentinel_length = 99;
    result = ker_source_native_ini_parse_file_capture(file,
        ker_source_native_ini_parse, &config, captured, length - 1,
        &sentinel_length);
    if (fclose(file) != 0 || result != -ENOSPC || sentinel_length != 99)
        return 0;

    /* Capture is a stable copy of the exact stream bytes; later mutation of
     * the caller's backing storage cannot rewrite the recorded observation. */
    char mutable_text[512];
    if (length >= sizeof(mutable_text)) return 0;
    memcpy(mutable_text, text, length + 1);
    file = fmemopen(mutable_text, length, "r");
    if (!file) return 0;
    memset(&config, 0, sizeof(config));
    captured_length = 0;
    result = ker_source_native_ini_parse_file_capture(file,
        ker_source_native_ini_parse, &config, captured, sizeof(captured),
        &captured_length);
    if (fclose(file) != 0 || result || captured_length != length) return 0;
    memset(mutable_text, 'x', length);
    return memcmp(captured, text, length) == 0;
}
static int file_open_controls(const char *contents)
{
    char directory[] = "/tmp/ker-source-native-ini-XXXXXX";
    char regular[256], fifo[256], linkpath[256];
    if (!mkdtemp(directory)) return 0;
    snprintf(regular, sizeof(regular), "%s/config.ini", directory);
    snprintf(fifo, sizeof(fifo), "%s/config.fifo", directory);
    snprintf(linkpath, sizeof(linkpath), "%s/config.link", directory);
    int fd = open(regular, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0644);
    if (fd < 0) return 0;
    size_t length = strlen(contents);
    int ok = fchmod(fd, 0644) == 0 && write(fd, contents, length) == (ssize_t)length;
    if (close(fd) != 0) ok = 0;
    FILE *file = ker_source_native_ini_open(regular);
    struct ker_source_native_ini config = {0};
    if (!file || ker_source_native_ini_parse_file(file,
            ker_source_native_ini_parse, &config) != 0 ||
        ker_source_native_ini_finish(&config, "/tmp/native/fstack.conf") != 0)
        ok = 0;
    if (file && fclose(file) != 0) ok = 0;
    if (mkfifo(fifo, 0600) != 0 || ker_source_native_ini_open(fifo) != NULL) ok = 0;
    if (symlink(regular, linkpath) != 0 ||
        ker_source_native_ini_open(linkpath) != NULL) ok = 0;
    unlink(linkpath); unlink(fifo); unlink(regular); rmdir(directory);
    return ok;
}
int main(void)
{
    struct ker_source_native_ini config;
    struct ker_source_native_ini_cycle_snapshot cycle_snapshot = {
        .version = KER_SOURCE_NATIVE_INI_SNAPSHOT_VERSION,
        .size = sizeof(struct ker_source_native_ini_cycle_snapshot),
        .adapter_cycle_serial = 7, .cycle_identity = (uintptr_t)0x1234
    };
    struct ker_source_native_ini_cycle_snapshot abi_sentinel = cycle_snapshot;
    CHECK(ker_source_native_ini_snapshot_abi_valid(&cycle_snapshot));
    cycle_snapshot.version++;
    abi_sentinel = cycle_snapshot;
    CHECK(!ker_source_native_ini_snapshot_abi_valid(&cycle_snapshot));
    CHECK(memcmp(&cycle_snapshot, &abi_sentinel, sizeof(cycle_snapshot)) == 0);
    cycle_snapshot = abi_sentinel;
    cycle_snapshot.version = KER_SOURCE_NATIVE_INI_SNAPSHOT_VERSION;
    cycle_snapshot.size--;
    abi_sentinel = cycle_snapshot;
    CHECK(!ker_source_native_ini_snapshot_abi_valid(&cycle_snapshot));
    CHECK(memcmp(&cycle_snapshot, &abi_sentinel, sizeof(cycle_snapshot)) == 0);
    cycle_snapshot = abi_sentinel;
    cycle_snapshot.version = KER_SOURCE_NATIVE_INI_SNAPSHOT_VERSION;
    cycle_snapshot.size = sizeof(cycle_snapshot);
    CHECK(ker_source_native_ini_snapshot_matches_cycle(&cycle_snapshot,
        (uintptr_t)0x1234));
    CHECK(!ker_source_native_ini_snapshot_matches_cycle(&cycle_snapshot,
        (uintptr_t)0x5678));
    cycle_snapshot.adapter_cycle_serial = 0;
    CHECK(!ker_source_native_ini_snapshot_matches_cycle(&cycle_snapshot,
        (uintptr_t)0x1234));
    cycle_snapshot.adapter_cycle_serial = 7;
    CHECK(valid(&config,"3"));
    static const char source_ini[] =
        "[ker_socket_broker]\nversion=1\npath=/run/ker/broker.sock\n"
        "[dpdk]\ngraceful_reload=1\nlcore_mask=3\nprimary_slim=1\n"
        "file_prefix=run_7f3a\nfstack_log_file_prefix=/tmp/native/fstack-\n"
        "fstack_log_level=0\n[port0]\nlcore_list=1\n"
        "addr=192.168.1.2\nnetmask=255.255.255.0\n"
        "broadcast=192.168.1.255\ngateway=192.168.1.1\n";
    CHECK(parse_text(source_ini) == 0);
    static const char serial_ini[] =
        "[ker_socket_broker]\nversion=1\npath=/run/ker/broker.sock\n"
        "[dpdk]\ngraceful_reload=0\nlcore_mask=1\nprimary_slim=0\n"
        "file_prefix=run_7f3a\nfstack_log_file_prefix=/tmp/native/fstack-\n"
        "fstack_log_level=0\n[port0]\nlcore_list=0\n"
        "addr=192.168.1.2\nnetmask=255.255.255.0\n"
        "broadcast=192.168.1.255\ngateway=192.168.1.1\n";
    CHECK(parse_text(serial_ini) != 0);
    CHECK(setenv("KER_NGINX_SOURCE_SERIAL_PATH", "/tmp/serial.sock", 1) == 0);
    CHECK(parse_text(serial_ini) == 0);
    CHECK(parse_text(source_ini) != 0);
    CHECK(setenv("KER_NGINX_SOURCE_KNI_ENABLE", "1", 1) == 0);
    CHECK(parse_text(serial_ini) != 0);
    CHECK(unsetenv("KER_NGINX_SOURCE_KNI_ENABLE") == 0);
    CHECK(unsetenv("KER_NGINX_SOURCE_SERIAL_PATH") == 0);
    char kni_ini[1024];
    int kni_length = snprintf(kni_ini, sizeof(kni_ini),
        "%s\n[kni]\nenable=1\nmethod=reject\nowner_proc_id=1\ntcp_port=80,443\nudp_port=53\n",
        source_ini);
    CHECK(kni_length > 0 && (size_t)kni_length < sizeof(kni_ini));
    CHECK(parse_text(kni_ini) != 0);
    CHECK(setenv("KER_NGINX_SOURCE_KNI_ENABLE", "1", 1) == 0);
    CHECK(parse_text(source_ini) != 0);
    CHECK(parse_text(kni_ini) == 0);
    char *kni_owner = strstr(kni_ini, "owner_proc_id=1");
    CHECK(kni_owner != NULL);
    kni_owner[sizeof("owner_proc_id=") - 1] = '0';
    CHECK(parse_text(kni_ini) != 0);
    CHECK(unsetenv("KER_NGINX_SOURCE_KNI_ENABLE") == 0);
    CHECK(capture_controls(source_ini));
    CHECK(file_open_controls(source_ini));
    CHECK(valid(&config, "3"));
    CHECK(ker_source_native_ini_finish(&config, "/tmp/native/fstack.conf") == 0);
    CHECK(strcmp(config.address, "192.168.1.2") == 0);
    CHECK(strcmp(config.netmask, "255.255.255.0") == 0);
    CHECK(strcmp(config.broadcast, "192.168.1.255") == 0);
    CHECK(strcmp(config.gateway, "192.168.1.1") == 0);
    CHECK(parse_network_text("0.1.2.3", "255.255.255.0",
        "0.1.2.255", "0.1.2.1") != 0);
    CHECK(parse_network_text("240.1.2.3", "255.255.255.0",
        "240.1.2.255", "240.1.2.1") != 0);
    CHECK(parse_network_text("10.1.2.4", "128.0.0.0",
        "127.255.255.255", "0.1.2.3") != 0);
    CHECK(parse_network_text("240.1.2.4", "255.255.255.0",
        "240.1.2.255", "240.1.2.3") != 0);
    CHECK(parse_text("[ker_socket_broker]\nversion=1\npath=/run/ker/broker.sock\n"
        "[dpdk]\ngraceful_reload=1\nlcore_mask=3\nprimary_slim=1\n"
        "file_prefix=run_7f3a\nfstack_log_file_prefix=/tmp/native/fstack-\n"
        "fstack_log_level=0\n[port0]\nlcore_list=1\naddr=192.168.1.2\n"
        "netmask=255.255.255.0\nbroadcast=192.168.1.254\n"
        "gateway=192.168.1.1\n") != 0);
    CHECK(parse_text("[ker_socket_broker]\nversion=1\npath=/run/ker/broker.sock\n"
        "[dpdk]\ngraceful_reload=1\nlcore_mask=3\nprimary_slim=1\n"
        "file_prefix=run_7f3a\nfstack_log_file_prefix=/tmp/native/fstack-\n"
        "fstack_log_level=0\n[port0]\nlcore_list=1\naddr=192.168.1.2\n"
        "netmask=255.255.255.254\nbroadcast=192.168.1.3\n"
        "gateway=192.168.1.1\n") != 0);
    CHECK(parse_text("[ker_socket_broker]\nversion=1\npath=/run/ker/broker.sock\n"
        "[dpdk]\ngraceful_reload=1\nlcore_mask=3\nprimary_slim=1\n"
        "file_prefix=run_7f3a\nfstack_log_file_prefix=/tmp/native/fstack-\n"
        "fstack_log_level=0\n[port0]\nlcore_list=1\naddr=192.168.1.2\n"
        "netmask=255.255.255.255\nbroadcast=192.168.1.2\n"
        "gateway=192.168.1.1\n") != 0);
    CHECK(parse_text("[ker_socket_broker]\nversion=1\npath=/run/ker/broker.sock\n"
        "[dpdk]\ngraceful_reload=1\nlcore_mask=3\nprimary_slim=1\n"
        "file_prefix=run_7f3a\nfstack_log_file_prefix=/tmp/native/fstack-\n"
        "fstack_log_level=0\n[port0]\nlcore_list=1\naddr=192.168.1.2\n"
        "netmask=255.0.255.0\nbroadcast=192.255.255.255\n"
        "gateway=192.168.1.1\n") != 0);
    CHECK(parse_text("[ker_socket_broker]\nversion=1\npath=/run/ker/broker.sock\n"
        "[dpdk]\ngraceful_reload=1\nlcore_mask=3\nprimary_slim=1\n"
        "file_prefix=run_7f3a\nfstack_log_file_prefix=/tmp/native/fstack-\n"
        "fstack_log_level=0\n[port0]\nlcore_list=1\naddr=192.168.1.2\n"
        "netmask=0.0.0.255\nbroadcast=192.168.1.255\n"
        "gateway=192.168.1.1\n") != 0);
    CHECK(parse_text("[ker_socket_broker]\nversion=1\npath=/run/ker/broker.sock\n"
        "[dpdk]\ngraceful_reload=1\nlcore_mask=3\nprimary_slim=1\n"
        "file_prefix=run_7f3a\nfstack_log_file_prefix=/tmp/native/fstack-\n"
        "fstack_log_level=0\n[port0]\nlcore_list=1\naddr=192.168.1.2\n"
        "netmask=255.255.255.0\nbroadcast=192.168.1.255\n"
        "gateway=192.168.2.1\n") != 0);
    CHECK(parse_network_text("0.1.2.3", "255.255.255.0",
        "0.1.2.255", "0.1.2.1") != 0);
    CHECK(parse_network_text("240.1.2.3", "255.255.255.0",
        "240.1.2.255", "240.1.2.1") != 0);
    CHECK(parse_network_text("10.1.2.4", "128.0.0.0",
        "127.255.255.255", "0.1.2.3") != 0);
    CHECK(parse_network_text("192.168.1.4", "255.255.255.0",
        "192.168.1.255", "240.1.2.3") != 0);
    CHECK(parse_text("[unknown]\n[ker_socket_broker]\nversion=1\n") != 0);
    CHECK(parse_text("[ker_socket_broker]\nversion=1\n"
        "[dpdk]\n[dpdk]\n") != 0);
    CHECK(parse_text("[ker_socket_broker]\nversion=1\n"
        "[dpdk]\ngraceful_reload=1\n[port0]\nlcore_list=1\n") != 0);
    char line_limit[4096];
    static const char section_prefix[] = "[ker_socket_broker]\n[dpdk]\n[port0]\n";
    size_t line_offset = sizeof(section_prefix) - 1;
    memcpy(line_limit, section_prefix, line_offset);
    line_limit[line_offset++] = '#';
    memset(line_limit + line_offset, 'x', 2045);
    line_offset += 2045;
    line_limit[line_offset++] = '\n';
    CHECK(ker_source_native_ini_validate_sections(line_limit, line_offset) == 0);
    line_offset = sizeof(section_prefix) - 1;
    line_limit[line_offset++] = '#';
    memset(line_limit + line_offset, 'x', 2046);
    line_offset += 2046;
    line_limit[line_offset++] = '\n';
    CHECK(ker_source_native_ini_validate_sections(line_limit, line_offset) == -E2BIG);
    char oversized[KER_SOURCE_NATIVE_INI_LINE_MAX + 64];
    memset(oversized, 'x', sizeof(oversized) - 1);
    oversized[sizeof(oversized) - 1] = '\0';
    CHECK(ker_source_native_ini_validate_sections(oversized,
        strlen(oversized)) == -E2BIG);
    CHECK(ker_source_native_ini_finish(&config,"/tmp/native/fstack.conf") == 0);
    CHECK(valid(&config,"0x3"));
    CHECK(ker_source_native_ini_finish(&config,"/tmp/native/fstack.conf") == 0);
    CHECK(valid(&config,"3"));
    CHECK(!add(&config,"dpdk","graceful_reload","1"));
    CHECK(valid(&config,"3"));
    CHECK(!add(&config,"freebsd","sysctl","net.inet.tcp.foo=1"));
    CHECK(valid(&config,"3"));
    CHECK(!add(&config,"dpdk","ignored_key","value"));
    CHECK(valid(&config,"3"));
    CHECK(!add(&config,"dpdk","lcore_mask","0x7"));
    CHECK(valid(&config,"3"));
    CHECK(!add(&config,"dpdk","primary_slim","0"));
    CHECK(valid(&config,"3"));
    CHECK(!add(&config,"dpdk","fstack_log_level","1"));
    CHECK(valid(&config,"3"));
    CHECK(!add(&config,"port0","lcore_list","0,1"));
    CHECK(valid(&config,"3"));
    CHECK(!add(&config,"port0","addr","not-an-address"));
    CHECK(valid(&config,"3"));
    CHECK(!add(&config,"dpdk","file_prefix","../escape"));
    CHECK(valid(&config,"3"));
    CHECK(ker_source_native_ini_finish(&config,"/tmp/other/fstack.conf") == -EINVAL);
    memset(&config, 0, sizeof(config));
    CHECK(add(&config,"ker_socket_broker","version","1"));
    CHECK(ker_source_native_ini_finish(&config,"/tmp/native/fstack.conf") == -EINVAL);
    CHECK(valid(&config,"3"));
    const uint8_t nonce[16] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
    char *argv[] = {"ker-io-worker", "--packet-fd", "3", "--rx-decision-fd", "4",
        "--queues", "1",
        "--rx-lcores", "1", "--port", "net_tap0",
        "--queue-proof-session", "0102030405060708090a0b0c0d0e0f10",
        "--queue-proof-epoch", "42", "--queue-proof-source-proc-id", "1",
        "--", "--no-pci", "--vdev=net_tap0,iface=kerpeer,remote=kerlink",
        "--file-prefix=container-run_7f3a"};
    CHECK(ker_source_native_io_argv_validate(argv,
        sizeof(argv)/sizeof(argv[0]), &config, nonce, 42) == 0);
    argv[10] = "0";
    CHECK(ker_source_native_io_argv_validate(argv,
        sizeof(argv)/sizeof(argv[0]), &config, nonce, 42) == -EINVAL);
    argv[10] = "net_tap0";
    argv[19] = "--vdev=net_other0,iface=kerpeer,remote=kerlink";
    CHECK(ker_source_native_io_argv_validate(argv,
        sizeof(argv)/sizeof(argv[0]), &config, nonce, 42) == -EINVAL);
    argv[19] = "--vdev=net_tap0,iface=kerpeer,remote=kerlink";
    char *separated_vdev_argv[22];
    memcpy(separated_vdev_argv, argv, 19 * sizeof(argv[0]));
    separated_vdev_argv[19] = "--vdev";
    separated_vdev_argv[20] = "net_tap0,iface=kerpeer,remote=kerlink";
    separated_vdev_argv[21] = argv[20];
    CHECK(ker_source_native_io_argv_validate(separated_vdev_argv,
        sizeof(separated_vdev_argv)/sizeof(separated_vdev_argv[0]), &config, nonce, 42) == 0);
    char *duplicate_vdev_argv[22];
    memcpy(duplicate_vdev_argv, argv, sizeof(argv));
    duplicate_vdev_argv[21] = "--vdev=net_tap1,iface=kerother,remote=kerpeer";
    CHECK(ker_source_native_io_argv_validate(duplicate_vdev_argv,
        sizeof(duplicate_vdev_argv)/sizeof(duplicate_vdev_argv[0]), &config, nonce, 42) == -EINVAL);
    argv[19] = "--no-telemetry";
    CHECK(ker_source_native_io_argv_validate(argv,
        sizeof(argv)/sizeof(argv[0]), &config, nonce, 42) == -EINVAL);
    argv[19] = "--vdev=net_tap0,iface=kerpeer,remote=kerlink";
    argv[4] = "2";
    CHECK(ker_source_native_io_argv_validate(argv,
        sizeof(argv)/sizeof(argv[0]), &config, nonce, 42) == -EINVAL);
    argv[4] = "4";
    char saved_file_prefix[sizeof(config.file_prefix)];
    memcpy(saved_file_prefix, config.file_prefix, sizeof(saved_file_prefix));
    char maximum_run_id[55], maximum_eal_prefix[sizeof("--file-prefix=") + KER_SOURCE_NATIVE_EAL_PREFIX_MAX];
    memset(maximum_run_id, 'a', sizeof(maximum_run_id) - 1);
    maximum_run_id[sizeof(maximum_run_id) - 1] = '\0';
    memcpy(config.file_prefix, maximum_run_id, sizeof(maximum_run_id));
    memcpy(maximum_eal_prefix, "--file-prefix=container-", sizeof("--file-prefix=container-") - 1);
    memset(maximum_eal_prefix + sizeof("--file-prefix=container-") - 1, 'a', 54);
    maximum_eal_prefix[sizeof(maximum_eal_prefix) - 1] = '\0';
    argv[20] = maximum_eal_prefix;
    CHECK(ker_source_native_io_argv_validate(argv,
        sizeof(argv)/sizeof(argv[0]), &config, nonce, 42) == 0);
    char excessive_run_id[56], excessive_eal_prefix[sizeof("--file-prefix=") + KER_SOURCE_NATIVE_EAL_PREFIX_MAX + 1];
    memset(excessive_run_id, 'b', sizeof(excessive_run_id) - 1);
    excessive_run_id[sizeof(excessive_run_id) - 1] = '\0';
    memcpy(config.file_prefix, excessive_run_id, sizeof(excessive_run_id));
    memcpy(excessive_eal_prefix, "--file-prefix=container-", sizeof("--file-prefix=container-") - 1);
    memset(excessive_eal_prefix + sizeof("--file-prefix=container-") - 1, 'b', 55);
    excessive_eal_prefix[sizeof(excessive_eal_prefix) - 1] = '\0';
    argv[20] = excessive_eal_prefix;
    CHECK(ker_source_native_io_argv_validate(argv,
        sizeof(argv)/sizeof(argv[0]), &config, nonce, 42) == -EINVAL);
    memcpy(config.file_prefix, saved_file_prefix, sizeof(saved_file_prefix));
    argv[20] = "--file-prefix=container-run_7f3a";
    argv[6] = "2";
    CHECK(ker_source_native_io_argv_validate(argv,
        sizeof(argv)/sizeof(argv[0]), &config, nonce, 42) == -EINVAL);
    argv[6] = "1"; argv[12] = "ffffffffffffffffffffffffffffffff";
    CHECK(ker_source_native_io_argv_validate(argv,
        sizeof(argv)/sizeof(argv[0]), &config, nonce, 42) == -EINVAL);
    argv[12] = "0102030405060708090a0b0c0d0e0f10"; argv[14] = "43";
    CHECK(ker_source_native_io_argv_validate(argv,
        sizeof(argv)/sizeof(argv[0]), &config, nonce, 42) == -EINVAL);
    argv[14] = "42"; argv[20] = "--file-prefix=container-wrong";
    CHECK(ker_source_native_io_argv_validate(argv,
        sizeof(argv)/sizeof(argv[0]), &config, nonce, 42) == -EINVAL);
    puts("PASS: strict source-shell original INI and IO argv controls");
    return 0;
}
