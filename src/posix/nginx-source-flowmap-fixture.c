/* Test-only source-map identity check.  This file is compiled only into the
 * source-classifier alias DSO; it does not install broker admission ops. */
#define _GNU_SOURCE
#include <ff_api.h>
#include <ff_config.h>
#include <ff_reload.h>
#include "ff_flow_map.h"
#include "socket-broker-preload-internal.h"
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

/* This bridge invokes the callback registered by the unchanged upstream arm
 * on the authenticated owner PID/TID. */
int ker_fstack_rx_owner_relay_dispatch(void *, uint16_t *, uint16_t,
    uint16_t, uint16_t, uint8_t, int32_t *);
int ker_nginx_original_flow_map_arm(void);

static uint32_t checksum_add(uint32_t sum, const unsigned char *bytes,
    size_t length)
{
    while (length > 1) {
        sum += (uint16_t)((bytes[0] << 8) | bytes[1]);
        bytes += 2;
        length -= 2;
    }
    if (length) sum += (uint16_t)(bytes[0] << 8);
    return sum;
}

static uint16_t checksum_finish(uint32_t sum)
{
    while (sum >> 16) sum = (sum & 0xffffu) + (sum >> 16);
    return (uint16_t)~sum;
}

static void source_frame_trace(uint8_t af, const unsigned char *frame,
    uint16_t length)
{
    static const char digits[] = "0123456789abcdef";
    char line[2 * (14 + 40 + 20) + 128];
    int prefix = snprintf(line, sizeof(line),
        "SOURCE_FLOWMAP_FRAME pid=%ld tid=%ld af=%u bytes=%u hex=",
        (long)getpid(), (long)syscall(SYS_gettid),
        af == FF_FLOW_MAP_V4 ? 4u : 6u, length);
    if (prefix <= 0 || (size_t)prefix + (size_t)length * 2 + 1 > sizeof(line))
        return;
    size_t offset = (size_t)prefix;
    for (size_t i = 0; i < length; ++i) {
        line[offset + i * 2] = digits[frame[i] >> 4];
        line[offset + i * 2 + 1] = digits[frame[i] & 0x0f];
    }
    offset += (size_t)length * 2;
    line[offset++] = '\n';
    (void)syscall(SYS_write, STDERR_FILENO, line, offset);
}

static int source_classifier_cycle(uint8_t af, uint16_t source_port,
    uint16_t destination_port)
{
    unsigned char frame[14 + 40 + 20] = {0};
    uint16_t length;
    struct ff_flow_key key = {0};
    int created = 0;
    int32_t decision = -1;

    frame[12] = af == FF_FLOW_MAP_V4 ? 0x08 : 0x86;
    frame[13] = af == FF_FLOW_MAP_V4 ? 0x00 : 0xdd;
    if (af == FF_FLOW_MAP_V4) {
        length = 14 + 20 + 20;
        frame[14] = 0x45;
        frame[16] = 0; frame[17] = 40;
        frame[22] = 64;
        frame[23] = 6;
        frame[26] = 192; frame[27] = 0; frame[28] = 2; frame[29] = 101;
        frame[30] = 192; frame[31] = 0; frame[32] = 2; frame[33] = 202;
        frame[34] = (unsigned char)(source_port >> 8);
        frame[35] = (unsigned char)source_port;
        frame[36] = (unsigned char)(destination_port >> 8);
        frame[37] = (unsigned char)destination_port;
        frame[46] = 0x50; frame[47] = 0x10; frame[48] = 0x10;
        uint16_t ip_sum = checksum_finish(checksum_add(0, frame + 14, 20));
        frame[24] = (unsigned char)(ip_sum >> 8); frame[25] = (unsigned char)ip_sum;
        uint32_t tcp_sum = checksum_add(0, frame + 26, 8) + 6 + 20;
        tcp_sum = checksum_add(tcp_sum, frame + 34, 20);
        uint16_t tcp_check = checksum_finish(tcp_sum);
        frame[50] = (unsigned char)(tcp_check >> 8); frame[51] = (unsigned char)tcp_check;
        key.af = FF_FLOW_MAP_V4;
        memcpy(&key.src[0], frame + 26, 4);
        memcpy(&key.dst[0], frame + 30, 4);
    } else if (af == FF_FLOW_MAP_V6) {
        length = 14 + 40 + 20;
        frame[14] = 0x60;
        frame[18] = 0; frame[19] = 20;
        frame[21] = 64;
        frame[20] = 6;
        frame[22] = 0x20; frame[23] = 0x01; frame[37] = 0x65;
        frame[38] = 0x20; frame[39] = 0x01; frame[53] = 0xca;
        frame[54] = (unsigned char)(source_port >> 8);
        frame[55] = (unsigned char)source_port;
        frame[56] = (unsigned char)(destination_port >> 8);
        frame[57] = (unsigned char)destination_port;
        frame[66] = 0x50; frame[67] = 0x10; frame[68] = 0x10;
        uint32_t tcp_sum = checksum_add(0, frame + 22, 32) + 20 + 6;
        tcp_sum = checksum_add(tcp_sum, frame + 54, 20);
        uint16_t tcp_check = checksum_finish(tcp_sum);
        frame[70] = (unsigned char)(tcp_check >> 8); frame[71] = (unsigned char)tcp_check;
        key.af = FF_FLOW_MAP_V6;
        memcpy(key.src, frame + 22, 16);
        memcpy(key.dst, frame + 38, 16);
    } else {
        return -EINVAL;
    }
    memcpy(&key.sport, frame + (af == FF_FLOW_MAP_V4 ? 34 : 54), 2);
    memcpy(&key.dport, frame + (af == FF_FLOW_MAP_V4 ? 36 : 56), 2);

    if (ker_fstack_rx_owner_relay_dispatch(frame, &length, 0, 1, 0, 0,
            &decision) || decision != FF_DISPATCH_PEER) return -EILSEQ;
    if (ff_flow_map_admit(&key, &created) != 1 || created != 1) return -EEXIST;
    if (ker_fstack_rx_owner_relay_dispatch(frame, &length, 0, 1, 0, 0,
            &decision) || decision != 0)
        return -ERANGE;
    if (ff_flow_map_revoke(&key) != 1) return -ENOMSG;
    if (ker_fstack_rx_owner_relay_dispatch(frame, &length, 0, 1, 0, 0,
            &decision) || decision != FF_DISPATCH_PEER) return -ENODATA;
    source_frame_trace(af, frame, length);
    return 0;
}

__attribute__((visibility("default")))
int ker_nginx_source_flowmap_fixture_cycle(void)
{
    if (!ff_reload_state_attached() || !ff_reload_hw_locked() ||
        ff_reload_gen() != ff_reload_target_gen() || !ff_flow_map_active())
        return -ESTALE;
    int result = source_classifier_cycle(FF_FLOW_MAP_V4, 43127, 8080);
    if (!result) result = source_classifier_cycle(FF_FLOW_MAP_V6, 43128, 8080);
    return result;
}

int ker_nginx_source_flowmap_owner_ready(struct ff_reload_state *state)
{
    if (!state || !ff_reload_state_valid(state, sizeof(*state))) {
        return -EPROTO;
    }
    ff_reload_attach_state(state);
    ff_reload_set_epoch(state->epoch);
    uint32_t target = (uint32_t)ff_reload_target_gen();
    if (!ff_reload_hw_locked() || target >= FF_RELOAD_GEN_MAX) {
        return -EPROTO;
    }
    ff_reload_set_gen((int)target);
    ff_global_cfg.dpdk.graceful_reload = 1;

    int entered = ker_sb_preload_owner_loop_enter();
    if (entered) return entered < 0 ? entered : -entered;
    int result = ker_nginx_original_flow_map_arm();
    if (!result && (!ff_reload_state_attached() || !ff_reload_hw_locked() ||
            ff_reload_gen() != ff_reload_target_gen() || !ff_flow_map_active())) {
        result = -ESTALE;
    }
    ker_sb_preload_owner_loop_leave();
    return result;
}

int ker_nginx_source_previous_owner_ready(struct ff_reload_state *state)
{
    if (!state || !ff_reload_state_valid(state, sizeof(*state)) || state->epoch != 2)
        return -ESTALE;
    ff_reload_attach_state(state);
    ff_reload_set_epoch(state->epoch);
    ff_reload_set_gen(0);
    ff_global_cfg.dpdk.graceful_reload = 1;
    if (!ff_reload_hw_locked() || ff_reload_target_gen() != 0) return -EPROTO;
    int entered = ker_sb_preload_owner_loop_enter();
    if (entered) return entered;
    int status = ker_nginx_original_flow_map_arm();
    if (!status) {
        /* The unchanged original callback stays registered as this generation
         * becomes the previous owner of the next real source-API window. */
        ff_reload_master_complete();
        uint32_t epoch = 0, target = 0;
        ff_reload_master_begin(&epoch, &target);
        ff_reload_set_epoch(epoch);
        if (epoch != 3 || target != 1 || ff_reload_gen() != 0 || !ff_reload_hw_locked())
            status = -EPROTO;
        else dprintf(STDERR_FILENO, "SOURCE_PREVIOUS_OWNER_ARMED pid=%ld tid=%ld epoch=%u gen=%d target=%d\n",
            (long)getpid(), (long)syscall(SYS_gettid), epoch, ff_reload_gen(), ff_reload_target_gen());
    }
    ker_sb_preload_owner_loop_leave();
    return status;
}
