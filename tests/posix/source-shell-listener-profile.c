/* Exercise the real C22 listener validator seam against pinned Nginx structs.
 * This does not execute Nginx or create a socket/listener capability. */
#define KER_NGINX_OWNER_TEST_ALIAS 1
#include "../../src/posix/fstack-nginx-owner-activation-module.c"

#include <stdio.h>

static int failures;

static void
expect(const char *name, const ngx_listening_t *listener,
    bool source_shell_profile, ngx_int_t expected)
{
    ngx_int_t actual = listener_profile_supported(listener, source_shell_profile);

    if (actual != expected) {
        fprintf(stderr, "%s: expected %ld, got %ld\n", name,
            (long) expected, (long) actual);
        ++failures;
    }
}

int
main(void)
{
    struct sockaddr_in address = {
        .sin_family = AF_INET,
        .sin_port = htons(80),
        .sin_addr = {.s_addr = htonl(INADDR_ANY)},
    };
    ngx_log_t log;
    ngx_listening_t listener;

    memset(&log, 0, sizeof(log));
    memset(&listener, 0, sizeof(listener));
    listener.type = SOCK_STREAM;
    listener.sockaddr = (struct sockaddr *) &address;
    listener.socklen = sizeof(address);
    listener.fd = (ngx_socket_t) -1;
    listener.open = 1;
    listener.backlog = NGX_LISTEN_BACKLOG;
    listener.rcvbuf = -1;
    listener.sndbuf = -1;
    listener.logp = &log;
#if (NGX_HAVE_SETFIB)
    listener.setfib = -1;
#endif
#if (NGX_HAVE_TCP_FASTOPEN)
    listener.fastopen = -1;
#endif

    expect("exact rt01 plain listener", &listener, true, NGX_OK);
    expect("plain listener outside source shell", &listener, false, NGX_ERROR);

    listener.reuseport = 1;
    expect("legacy reuseport listener", &listener, false, NGX_OK);
    listener.reuseport = 0;

    address.sin_port = htons(81);
    expect("wrong port", &listener, true, NGX_ERROR);
    address.sin_port = htons(80);
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    expect("non-wildcard address", &listener, true, NGX_ERROR);
    address.sin_addr.s_addr = htonl(INADDR_ANY);
    address.sin_family = AF_INET6;
    expect("wrong address family", &listener, true, NGX_ERROR);
    address.sin_family = AF_INET;

    listener.type = SOCK_DGRAM;
    expect("wrong socket type", &listener, true, NGX_ERROR);
    listener.type = SOCK_STREAM;
    listener.backlog = NGX_LISTEN_BACKLOG - 1;
    expect("wrong backlog", &listener, true, NGX_ERROR);
    listener.backlog = NGX_LISTEN_BACKLOG;

#define REJECT_MUTATION(name, field, value) do { \
    listener.field = value; \
    expect(name, &listener, true, NGX_ERROR); \
    listener.field = 0; \
} while (0)
    REJECT_MUTATION("host-owned listener", belong_to_host, 1);
    listener.fd = 3;
    expect("already-open listener", &listener, true, NGX_ERROR);
    listener.fd = (ngx_socket_t) -1;
    REJECT_MUTATION("ignored listener", ignore, 1);
    listener.open = 0;
    expect("not-open listener", &listener, true, NGX_ERROR);
    listener.open = 1;
    REJECT_MUTATION("bound listener", bound, 1);
    REJECT_MUTATION("inherited listener", inherited, 1);
    REJECT_MUTATION("pending reuseport add", add_reuseport, 1);
    listener.rcvbuf = 4096;
    expect("receive buffer option", &listener, true, NGX_ERROR);
    listener.rcvbuf = -1;
    listener.sndbuf = 4096;
    expect("send buffer option", &listener, true, NGX_ERROR);
    listener.sndbuf = -1;
    REJECT_MUTATION("keepalive option", keepalive, 1);
    REJECT_MUTATION("deferred accept", deferred_accept, 1);
    REJECT_MUTATION("deferred accept add", add_deferred, 1);
    REJECT_MUTATION("deferred accept delete", delete_deferred, 1);
    REJECT_MUTATION("QUIC listener", quic, 1);
    listener.logp = NULL;
    expect("missing listener log", &listener, true, NGX_ERROR);
    listener.logp = &log;
#undef REJECT_MUTATION

#if (NGX_HAVE_KEEPALIVE_TUNABLE)
    listener.keepidle = 1;
    expect("keepalive tuning", &listener, true, NGX_ERROR);
#endif
#if (NGX_HAVE_SETFIB)
    listener.setfib = 0;
    expect("setfib option", &listener, true, NGX_ERROR);
#endif
#if (NGX_HAVE_TCP_FASTOPEN)
    listener.fastopen = 1;
    expect("TCP fast-open option", &listener, true, NGX_ERROR);
#endif
#if (NGX_HAVE_DEFERRED_ACCEPT && defined SO_ACCEPTFILTER)
    listener.accept_filter = (u_char *) "filter";
    expect("accept-filter option", &listener, true, NGX_ERROR);
#endif

    if (failures) return 1;
    puts("source-shell listener profile controls passed");
    return 0;
}
