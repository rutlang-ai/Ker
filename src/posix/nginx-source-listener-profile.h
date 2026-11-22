#ifndef KER_NGINX_SOURCE_LISTENER_PROFILE_H
#define KER_NGINX_SOURCE_LISTENER_PROFILE_H

#include <ngx_connection.h>

static inline int
ker_nginx_source_rt01_plain_listener(const ngx_listening_t *listener)
{
    const struct sockaddr_in *address;

    if (!listener || listener->reuseport || listener->belong_to_host ||
        listener->type != SOCK_STREAM || !listener->sockaddr ||
        listener->socklen != sizeof(struct sockaddr_in) ||
        listener->sockaddr->sa_family != AF_INET ||
        listener->backlog != NGX_LISTEN_BACKLOG)
        return 0;

    address = (const struct sockaddr_in *)listener->sockaddr;
    return address->sin_addr.s_addr == htonl(INADDR_ANY) &&
        address->sin_port == htons(80);
}

#endif
