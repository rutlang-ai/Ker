#ifndef KER_POSIX_PACKET_DEVICE_H
#define KER_POSIX_PACKET_DEVICE_H
struct lkl_netdev;
/* Takes ownership of fd only on success. Remove the registered native device
 * before freeing it; poll_hup wakes polling without closing live descriptors. */
struct lkl_netdev *ker_packet_device_create(int fd);
#endif
