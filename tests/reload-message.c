#include <ker/reload.h>
#include "check.h"

int main(void)
{
    char payload[] = "caller data";
    ker_ipc_message message = {
        .buf_addr = payload, .buf_len = sizeof(payload),
        .ipc_owner_pid = 123, .ipc_cookie = 456,
    };
    ker_reload_message_fill(&message, FF_RELOAD_CMD_DRAIN_DONE, 1, 7, 12345);
    CHECK(message.msg_type == FF_RELOAD && message.result == 0);
    CHECK(message.reload.cmd == FF_RELOAD_CMD_DRAIN_DONE && message.reload.gen == 1);
    CHECK(message.reload.status == 7 && message.reload.heartbeat == 12345);
    CHECK(message.reload.active_gen == 0 && message.reload.epoch == 0);
    CHECK(message.buf_addr == payload && message.buf_len == sizeof(payload));
    CHECK(message.ipc_owner_pid == 123 && message.ipc_cookie == 456);

    int command = 0, generation = 0, status = 0;
    uint64_t heartbeat = 0;
    CHECK(ker_reload_message_parse(&message, &command, &generation, &status, &heartbeat) == 0);
    CHECK(command == FF_RELOAD_CMD_DRAIN_DONE && generation == 1);
    CHECK(status == 7 && heartbeat == 12345);

    message.msg_type = FF_SYSCTL;
    CHECK(ker_reload_message_parse(&message, &command, &generation, &status, &heartbeat) == -1);
    CHECK(command == FF_RELOAD_CMD_DRAIN_DONE && generation == 1);
    CHECK(status == 7 && heartbeat == 12345);
    message.msg_type = FF_RELOAD;
    message.reload.cmd = FF_RELOAD_CMD_QUERY + 1;
    CHECK(ker_reload_message_parse(&message, NULL, NULL, NULL, NULL) == -1);
    message.reload.cmd = 0;
    CHECK(ker_reload_message_parse(&message, NULL, NULL, NULL, NULL) == -1);
    CHECK(ker_reload_message_parse(NULL, NULL, NULL, NULL, NULL) == -1);

    static const int commands[] = {
        FF_RELOAD_CMD_READY, FF_RELOAD_CMD_HANDOVER_REQ, FF_RELOAD_CMD_HANDOVER_ACK,
        FF_RELOAD_CMD_DRAIN_PROGRESS, FF_RELOAD_CMD_DRAIN_DONE, FF_RELOAD_CMD_REJECT,
        FF_RELOAD_CMD_QUERY,
    };
    for (size_t i = 0; i < sizeof(commands) / sizeof(commands[0]); ++i) {
        message.reload.cmd = commands[i];
        command = 0;
        CHECK(ker_reload_message_parse(&message, &command, NULL, NULL, NULL) == 0);
        CHECK(command == commands[i]);
    }
    CHECK(ker_reload_message_parse(&message, NULL, NULL, NULL, NULL) == 0);
    return 0;
}
