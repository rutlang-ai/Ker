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
    return 0;
}
