#ifndef KER_MTU_CONTROL_H
#define KER_MTU_CONTROL_H
void ker_mtu_control_init(int fd, int index, int maximum);
long ker_mtu_ioctl(int native_fd, unsigned long request, unsigned long argument);
#endif
