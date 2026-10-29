#include <ker/reload.h>
#include "check.h"
#include <errno.h>
#include <stdlib.h>
#include <string.h>

int main(void)
{
    ker_ipc_message message;
    memset(&message, 0, sizeof(message));
    ker_reload_message_fill(&message, FF_RELOAD_CMD_DRAIN_DONE, 1, 7, 12345);
    CHECK(message.msg_type == FF_RELOAD && message.result == 0);
    CHECK(message.reload.cmd == FF_RELOAD_CMD_DRAIN_DONE && message.reload.gen == 1);
    CHECK(message.reload.status == 7 && message.reload.heartbeat == 12345);
    int command = 0, generation = 0, status = 0; uint64_t heartbeat = 0;
    CHECK(!ker_reload_message_parse(&message, &command, &generation, &status, &heartbeat));
    CHECK(command == FF_RELOAD_CMD_DRAIN_DONE && generation == 1 && status == 7 && heartbeat == 12345);
    message.msg_type = FF_SYSCTL;
    CHECK(ker_reload_message_parse(&message, NULL, NULL, NULL, NULL) == -1);
    message.msg_type = FF_RELOAD; message.reload.cmd = FF_RELOAD_CMD_QUERY + 1;
    CHECK(ker_reload_message_parse(&message, NULL, NULL, NULL, NULL) == -1);
    message.reload.cmd = 0;
    CHECK(ker_reload_message_parse(&message, NULL, NULL, NULL, NULL) == -1);
    message.reload.cmd = FF_RELOAD_CMD_READY;
    CHECK(!ker_reload_message_parse(&message, NULL, NULL, NULL, NULL));
    CHECK(ker_reload_message_parse(NULL, NULL, NULL, NULL, NULL) == -1);
    for (int c = FF_RELOAD_CMD_READY; c <= FF_RELOAD_CMD_QUERY; c++) {
        message.reload.cmd = c;
        CHECK(!ker_reload_message_parse(&message, &command, NULL, NULL, NULL) && command == c);
    }
    ker_reload_message_fill(NULL, 0, 0, 0, 0);
    message.msg_type = FF_SYSCTL;
    command = generation = status = 77; heartbeat = 77;
    CHECK(ker_reload_message_parse(&message, &command, &generation, &status, &heartbeat) == -1);
    CHECK(command == 77 && generation == 77 && status == 77 && heartbeat == 77);

    size_t size = ker_reload_state_size(); void *state = calloc(1, size); CHECK(state);
    CHECK(ker_reload_bind_state(state, size, 2, 1) == -EINVAL);
    CHECK(ker_reload_state_init(state, size - 1, 1) == -EINVAL);
    CHECK(!ker_reload_state_init(state, size, 1));
    CHECK(!ker_reload_bind_state(state, size, 2, 1));
    CHECK(ker_reload_state_init(state, size, 0) == -EBUSY);
    CHECK(ker_reload_bind_state(state, size, 2, 1) == -EBUSY);
    message.ipc_owner_pid = 123; message.ipc_cookie = 456;
    char payload[] = "caller ownership";
    message.buf_addr = payload; message.buf_len = sizeof(payload);
    ker_reload_message_fill(&message, FF_RELOAD_CMD_QUERY, 1, 7, 12345);
    CHECK(message.reload.active_gen == 1 && message.reload.epoch == 2);
    CHECK(message.ipc_owner_pid == 123 && message.ipc_cookie == 456);
    CHECK(message.buf_addr == payload && message.buf_len == sizeof(payload) && !strcmp(payload, "caller ownership"));
    ker_reload_unbind_state(); ker_reload_unbind_state(); free(state);
    ker_reload_message_fill(&message, FF_RELOAD_CMD_QUERY, 0, 0, 0);
    CHECK(message.reload.epoch == 0 && message.reload.active_gen == 0);
    puts("PASS: original reload message fill/parse and borrowed-state lifetime");
    return 0;
}
