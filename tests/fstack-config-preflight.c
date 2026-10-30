#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <rte_config.h>

#include "check.h"
#include "fstack-config-policy.h"

#define CONFIG_PATH_TEMPLATE "/tmp/ker-fstack-config-preflight-XXXXXX"
static char config_path[sizeof(CONFIG_PATH_TEMPLATE)];
static char body[16384];

static void write_config(void)
{
    int fd;
    FILE *file;

    memcpy(config_path, CONFIG_PATH_TEMPLATE, sizeof(config_path));
    fd = mkstemp(config_path);
    CHECK(fd >= 0);
    file = fdopen(fd, "w");
    CHECK(file != NULL);
    CHECK(fputs(body, file) >= 0);
    CHECK(fclose(file) == 0);
}

static void write_body_to(char *path, const char *content)
{
    int fd;
    FILE *file;

    memcpy(path, CONFIG_PATH_TEMPLATE, sizeof(CONFIG_PATH_TEMPLATE));
    fd = mkstemp(path);
    CHECK(fd >= 0);
    file = fdopen(fd, "w");
    CHECK(file != NULL);
    CHECK(fputs(content, file) >= 0);
    CHECK(fclose(file) == 0);
}

static int load_config(int *eal_argc)
{
    char program[] = "config-inspect";
    char option[] = "-c";
    char *argv[] = { program, option, config_path, NULL };
    int result = example_fstack_config_load(3, argv);

    if (eal_argc != NULL)
        *eal_argc = example_fstack_config_eal_argc();
    example_fstack_config_unload();
    CHECK(unlink(config_path) == 0);
    return result;
}

static void append_allow_entries(char *buffer, size_t size, unsigned count)
{
    size_t used = strlen(buffer);
    unsigned i;

    for (i = 0; i < count; i++) {
        int written = snprintf(buffer + used, size - used, "%s0000:00:%02x.0",
                               i == 0 ? "" : ",", i);
        CHECK(written > 0 && (size_t)written < size - used);
        used += (size_t)written;
    }
}

static void append_port_sections(unsigned ports)
{
    size_t used = strlen(body);
    unsigned port;

    for (port = 0; port < ports; port++) {
        int written = snprintf(body + used, sizeof(body) - used,
            "[port%u]\n"
            "addr=192.168.%u.10\n"
            "netmask=255.255.255.0\n"
            "broadcast=192.168.%u.255\n"
            "gateway=192.168.%u.1\n",
            port, port, port, port);
        CHECK(written > 0 && (size_t)written < sizeof(body) - used);
        used += (size_t)written;
    }
}

static void build_body(const char *dpdk_lines, unsigned ports)
{
    int written = snprintf(body, sizeof(body),
        "[dpdk]\n"
        "lcore_mask=1\n"
        "channel=4\n"
        "%s\n"
        "[freebsd.boot]\n"
        "hz=100\n"
        "physmem=268435456\n"
        "fd_reserve=1024\n"
        "mem_size=256\n"
        "[freebsd.sysctl]\n"
        "kern.ipc.maxsockbuf=16777216\n",
        dpdk_lines);
    CHECK(written > 0 && (size_t)written < sizeof(body));
    append_port_sections(ports);
}

static void test_minimal_document_loads(void)
{
    build_body("port_list=0", 1);
    write_config();
    CHECK(load_config(NULL) == 0);
}

/* 32 slots: f-stack + -c + -n + --proc-type + allow entries. */
static void test_argument_capacity_boundary(void)
{
    char dpdk_lines[4096];
    int eal_argc;
    int written;

    written = snprintf(dpdk_lines, sizeof(dpdk_lines), "port_list=0\nallow=");
    CHECK(written > 0);
    append_allow_entries(dpdk_lines, sizeof(dpdk_lines), 28);
    build_body(dpdk_lines, 1);
    write_config();
    CHECK(load_config(&eal_argc) == 0);
    CHECK(eal_argc == DPDK_CONFIG_NUM);

    written = snprintf(dpdk_lines, sizeof(dpdk_lines), "port_list=0\nallow=");
    CHECK(written > 0);
    append_allow_entries(dpdk_lines, sizeof(dpdk_lines), 29);
    build_body(dpdk_lines, 1);
    write_config();
    CHECK(load_config(NULL) != 0);
}

static void test_oversized_file_prefix_rejected(void)
{
    char dpdk_lines[1024];
    size_t used = (size_t)snprintf(dpdk_lines, sizeof(dpdk_lines),
                                   "port_list=0\nfile_prefix=");
    unsigned i;

    CHECK(used > 0 && used < sizeof(dpdk_lines));
    for (i = 0; i < 300; i++) {
        CHECK(used + 1 < sizeof(dpdk_lines));
        dpdk_lines[used++] = 'a';
    }
    dpdk_lines[used] = '\0';
    build_body(dpdk_lines, 1);
    write_config();
    CHECK(load_config(NULL) != 0);
}

static void test_oversized_allow_entry_rejected(void)
{
    char dpdk_lines[1024];
    size_t used = (size_t)snprintf(dpdk_lines, sizeof(dpdk_lines),
                                   "port_list=0\nallow=");
    unsigned i;

    CHECK(used > 0 && used < sizeof(dpdk_lines));
    for (i = 0; i < 300; i++) {
        CHECK(used + 1 < sizeof(dpdk_lines));
        dpdk_lines[used++] = 'a';
    }
    dpdk_lines[used] = '\0';
    build_body(dpdk_lines, 1);
    write_config();
    CHECK(load_config(NULL) != 0);
}

static void test_oversized_port_list_rejected(void)
{
    char dpdk_lines[128];

    /* The parser's stack array holds exactly RTE_MAX_ETHPORTS entries. */
    snprintf(dpdk_lines, sizeof(dpdk_lines), "port_list=0-%d",
             RTE_MAX_ETHPORTS - 1);
    build_body(dpdk_lines, RTE_MAX_ETHPORTS);
    write_config();
    CHECK(load_config(NULL) == 0);

    snprintf(dpdk_lines, sizeof(dpdk_lines), "port_list=0-%d",
             RTE_MAX_ETHPORTS);
    build_body(dpdk_lines, 1);
    write_config();
    CHECK(load_config(NULL) != 0);
}

static void test_empty_list_rejected(void)
{
    build_body("port_list=3-0", 1);
    write_config();
    CHECK(load_config(NULL) != 0);
}

/* Port ids index a RTE_MAX_ETHPORTS-sized allocation, so a single out-of-range
 * value must be rejected even though the element count stays in bounds. */
static void test_port_id_value_range(void)
{
    char dpdk_lines[128];

    snprintf(dpdk_lines, sizeof(dpdk_lines), "port_list=%d",
             RTE_MAX_ETHPORTS - 1);
    build_body(dpdk_lines, RTE_MAX_ETHPORTS);
    write_config();
    CHECK(load_config(NULL) == 0);

    snprintf(dpdk_lines, sizeof(dpdk_lines), "port_list=%d", RTE_MAX_ETHPORTS);
    build_body(dpdk_lines, 1);
    write_config();
    CHECK(load_config(NULL) != 0);
}

/* A malformed line after an oversized list must not turn the preflight's
 * recorded invalid plan into permission to replay the list through the
 * retained parser. */
static void test_oversized_list_then_malformed_rejected(void)
{
    char dpdk_lines[128];

    snprintf(dpdk_lines, sizeof(dpdk_lines), "port_list=0-%d",
             RTE_MAX_ETHPORTS);
    build_body(dpdk_lines, 1);
    CHECK(strlen(body) + sizeof("[unclosed\n") < sizeof(body));
    strcat(body, "[unclosed\n");
    write_config();
    CHECK(load_config(NULL) != 0);
}

/* A negative port section id indexes port_cfgs[-1] in the retained parser;
 * reject it before upstream load. */
static void test_negative_port_section_rejected(void)
{
    snprintf(body, sizeof(body),
             "[dpdk]\n"
             "lcore_mask=1\n"
             "channel=4\n"
             "port_list=0\n"
             "[port-1]\n"
             "addr=192.168.0.10\n"
             "netmask=255.255.255.0\n"
             "broadcast=192.168.0.255\n"
             "gateway=192.168.0.1\n");
    write_config();
    CHECK(load_config(NULL) != 0);
}

/* A listed port with no [portN] section leaves port_cfgs NULL, so ff_check_config
 * dereferences a null pointer; reject it before upstream load. */
static void test_port_list_without_section_rejected(void)
{
    snprintf(body, sizeof(body),
             "[dpdk]\n"
             "lcore_mask=1\n"
             "channel=4\n"
             "port_list=0\n");
    write_config();
    CHECK(load_config(NULL) != 0);
}

/* A negative vlan parent-port id indexes port_cfgs[-1] in the retained parser;
 * reject it before upstream load. */
static void test_negative_vlan_portid_rejected(void)
{
    snprintf(body, sizeof(body),
             "[dpdk]\n"
             "lcore_mask=1\n"
             "channel=4\n"
             "port_list=0\n"
             "vlan_filter=1\n"
             "[port0]\n"
             "addr=192.168.0.10\n"
             "netmask=255.255.255.0\n"
             "broadcast=192.168.0.255\n"
             "gateway=192.168.0.1\n"
             "[vlan1]\n"
             "portid=-1\n");
    write_config();
    CHECK(load_config(NULL) != 0);
}

/* Repeated vlan attachments to one port write past vlan_cfgs[DPDK_MAX_VLAN_FILTER];
 * reject before upstream load. */
static void test_vlan_attachment_overflow_rejected(void)
{
    size_t used;
    int i;

    used = (size_t)snprintf(body, sizeof(body),
             "[dpdk]\n"
             "lcore_mask=1\n"
             "channel=4\n"
             "port_list=0\n"
             "vlan_filter=1\n"
             "[port0]\n"
             "addr=192.168.0.10\n"
             "netmask=255.255.255.0\n"
             "broadcast=192.168.0.255\n"
             "gateway=192.168.0.1\n"
             "[vlan1]\n");
    CHECK(used < sizeof(body));
    for (i = 0; i <= DPDK_MAX_VLAN_FILTER; i++) {
        int written = snprintf(body + used, sizeof(body) - used, "portid=0\n");
        CHECK(written > 0 && (size_t)written < sizeof(body) - used);
        used += (size_t)written;
    }
    write_config();
    CHECK(load_config(NULL) != 0);
}

/* The preflight must resolve the same document as ff_parse_args: getopt stops
 * at `--`, so the trailing `-c safe.ini` must not hide the oversized unsafe.ini. */
static void test_option_terminator_filename_rejected(void)
{
    char unsafe_path[sizeof(CONFIG_PATH_TEMPLATE)];
    char safe_path[sizeof(CONFIG_PATH_TEMPLATE)];
    char safe_body[1024];
    char program[] = "config-inspect";
    char option[] = "-c";
    char terminator[] = "--";
    char *argv[] = { program, option, unsafe_path, terminator, option, safe_path, NULL };
    int result;

    snprintf(body, sizeof(body),
             "[dpdk]\n"
             "lcore_mask=1\n"
             "channel=4\n"
             "port_list=0-%d\n", RTE_MAX_ETHPORTS);
    write_body_to(unsafe_path, body);

    snprintf(safe_body, sizeof(safe_body),
             "[dpdk]\n"
             "lcore_mask=1\n"
             "channel=4\n"
             "port_list=0\n"
             "[port0]\n"
             "addr=192.168.0.10\n"
             "netmask=255.255.255.0\n"
             "broadcast=192.168.0.255\n"
             "gateway=192.168.0.1\n");
    write_body_to(safe_path, safe_body);

    result = example_fstack_config_load(6, argv);
    example_fstack_config_unload();
    CHECK(result != 0);
    CHECK(unlink(unsafe_path) == 0);
    CHECK(unlink(safe_path) == 0);
}

/* A vlan attachment that precedes the first [portN] section dereferences the
 * still-unallocated port_cfgs array; reject it before upstream load. */
static void test_vlan_attachment_before_port_rejected(void)
{
    snprintf(body, sizeof(body),
             "[dpdk]\n"
             "lcore_mask=1\n"
             "channel=4\n"
             "port_list=0\n"
             "vlan_filter=1\n"
             "[vlan1]\n"
             "portid=0\n"
             "[port0]\n"
             "addr=192.168.0.10\n"
             "netmask=255.255.255.0\n"
             "broadcast=192.168.0.255\n"
             "gateway=192.168.0.1\n");
    write_config();
    CHECK(load_config(NULL) != 0);
}

/* A mask enabling more than DPDK_MAX_LCORE cores overflows the per-port
 * lcore_list copy; reject it before upstream load. */
static void test_lcore_mask_population_rejected(void)
{
    char mask[64];
    int i;

    mask[0] = '0';
    mask[1] = 'x';
    for (i = 0; i < 33; i++)
        mask[2 + i] = 'f';
    mask[35] = '\0';

    snprintf(body, sizeof(body),
             "[dpdk]\n"
             "lcore_mask=%s\n"
             "channel=4\n"
             "port_list=0\n"
             "[port0]\n"
             "addr=192.168.0.10\n"
             "netmask=255.255.255.0\n"
             "broadcast=192.168.0.255\n"
             "gateway=192.168.0.1\n", mask);
    write_config();
    CHECK(load_config(NULL) != 0);
}

/* Range endpoints that exceed int range narrow in the retained int loop,
 * diverging from the preflight count; reject them before counting. */
static void test_range_endpoint_out_of_int_rejected(void)
{
    snprintf(body, sizeof(body),
             "[dpdk]\n"
             "lcore_mask=1\n"
             "channel=4\n"
             "port_list=0\n"
             "vlan_filter=4294967296-4294967296\n"
             "[port0]\n"
             "addr=192.168.0.10\n"
             "netmask=255.255.255.0\n"
             "broadcast=192.168.0.255\n"
             "gateway=192.168.0.1\n");
    write_config();
    CHECK(load_config(NULL) != 0);
}

/* A range whose upper endpoint is INT_MAX makes the retained loop execute
 * ++j past INT_MAX; reject it before counting. */
static void test_range_upper_int_max_rejected(void)
{
    snprintf(body, sizeof(body),
             "[dpdk]\n"
             "lcore_mask=1\n"
             "channel=4\n"
             "port_list=0\n"
             "vlan_filter=2147483647-2147483647\n"
             "[port0]\n"
             "addr=192.168.0.10\n"
             "netmask=255.255.255.0\n"
             "broadcast=192.168.0.255\n"
             "gateway=192.168.0.1\n");
    write_config();
    CHECK(load_config(NULL) != 0);
}

/* A KNI owner_proc_id outside [0, RTE_MAX_LCORE) indexes proc_lcore out of
 * bounds in ff_check_config; reject it before upstream load. */
static void test_kni_owner_proc_id_rejected(void)
{
    snprintf(body, sizeof(body),
             "[dpdk]\n"
             "lcore_mask=3\n"
             "channel=4\n"
             "port_list=0\n"
             "primary_slim=1\n"
             "[kni]\n"
             "enable=1\n"
             "method=accept\n"
             "owner_proc_id=-1\n"
             "[port0]\n"
             "addr=192.168.0.10\n"
             "netmask=255.255.255.0\n"
             "broadcast=192.168.0.255\n"
             "gateway=192.168.0.1\n");
    write_config();
    CHECK(load_config(NULL) != 0);

    snprintf(body, sizeof(body),
             "[dpdk]\n"
             "lcore_mask=3\n"
             "channel=4\n"
             "port_list=0\n"
             "primary_slim=1\n"
             "[kni]\n"
             "enable=1\n"
             "method=accept\n"
             "owner_proc_id=%d\n"
             "[port0]\n"
             "addr=192.168.0.10\n"
             "netmask=255.255.255.0\n"
             "broadcast=192.168.0.255\n"
             "gateway=192.168.0.1\n", RTE_MAX_LCORE);
    write_config();
    CHECK(load_config(NULL) != 0);
}

int main(void)
{
    test_minimal_document_loads();
    test_argument_capacity_boundary();
    test_oversized_file_prefix_rejected();
    test_oversized_allow_entry_rejected();
    test_oversized_port_list_rejected();
    test_empty_list_rejected();
    test_port_id_value_range();
    test_oversized_list_then_malformed_rejected();
    test_negative_port_section_rejected();
    test_port_list_without_section_rejected();
    test_negative_vlan_portid_rejected();
    test_vlan_attachment_overflow_rejected();
    test_option_terminator_filename_rejected();
    test_vlan_attachment_before_port_rejected();
    test_lcore_mask_population_rejected();
    test_range_endpoint_out_of_int_rejected();
    test_range_upper_int_max_rejected();
    test_kni_owner_proc_id_rejected();
    return 0;
}
