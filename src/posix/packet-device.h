#ifndef KER_POSIX_PACKET_DEVICE_H
#define KER_POSIX_PACKET_DEVICE_H
struct lkl_netdev;
/* Requires a connected AF_UNIX datagram/seqpacket descriptor. On success
 * takes ownership and sets FD_CLOEXEC; failure leaves the fd and flags intact.
 * Remove the registered native device
 * before freeing it; poll_hup wakes polling without closing live descriptors. */
struct lkl_netdev *ker_packet_device_create(int fd);
#endif
