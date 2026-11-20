#ifndef KER_POSIX_MTU_CONTROL_H
#define KER_POSIX_MTU_CONTROL_H

void ker_mtu_control_init(int fd, int index, int ceiling);
void ker_mtu_control_close(void);
long ker_mtu_ioctl(int fd, unsigned long request, unsigned long argument);

#endif
