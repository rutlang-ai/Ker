#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s: %m\n", __FILE__, __LINE__, #x); exit(1); } } while (0)
static const char *ips[] = {"198.19.100.2", "198.19.100.3", "198.19.100.4", "198.19.100.5", "198.19.200.2"};
static const int tags[] = {100,100,100,100,200};
static int make_socket(int type, int slot, const char *prefix)
{
    int fd = socket(AF_INET, type | SOCK_CLOEXEC, 0); CHECK(fd >= 0);
    struct timeval timeout = {.tv_sec = 5};
    CHECK(!setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)));
    CHECK(!setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)));
    char name[IFNAMSIZ]; snprintf(name, sizeof(name), "%s.%d", prefix, tags[slot]);
    struct ifreq request = {0}; strcpy(request.ifr_name, name);
    CHECK(!ioctl(fd, SIOCGIFINDEX, &request) && request.ifr_ifindex > 0);
    CHECK(!setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, name, strlen(name) + 1));
    CHECK(!ioctl(fd, SIOCGIFMTU, &request) && request.ifr_mtu == 1500);
    int one = 1;
    CHECK(!setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)));
    if (type == SOCK_DGRAM) CHECK(!setsockopt(fd, IPPROTO_IP, IP_PKTINFO, &one, sizeof(one)));
    struct sockaddr_in address = {.sin_family=AF_INET, .sin_port=htons(29100 + slot)};
    CHECK(inet_pton(AF_INET, ips[slot], &address.sin_addr) == 1);
    CHECK(!bind(fd, (void *)&address, sizeof(address)));
    return fd;
}
int main(int argc, char **argv)
{
    if (argc == 3 && !strcmp(argv[2], "absent")) {
        int fd=socket(AF_INET,SOCK_DGRAM,0);CHECK(fd>=0);
        struct ifreq request={0};strcpy(request.ifr_name,"ker.300");
        errno=0;CHECK(ioctl(fd,SIOCGIFINDEX,&request)==-1 && errno==ENODEV);
        struct sockaddr_in address={.sin_family=AF_INET};
        CHECK(inet_pton(AF_INET,"192.0.2.30",&address.sin_addr)==1);
        errno=0;CHECK(bind(fd,(void *)&address,sizeof(address))==-1 && errno==EADDRNOTAVAIL);
        CHECK(!close(fd));puts("PASS: ambient VLAN settings are not inherited");return 0;
    }
    CHECK(argc == 2);
    const char *prefix = argv[1];
    int tcp[5], udp[5];
    for (int i=0;i<5;i++) { tcp[i]=make_socket(SOCK_STREAM,i,prefix);udp[i]=make_socket(SOCK_DGRAM,i,prefix);CHECK(!listen(tcp[i],1)); }
    struct ifreq hardware={0};snprintf(hardware.ifr_name,sizeof(hardware.ifr_name),"%s.100",prefix);
    CHECK(!ioctl(udp[0],SIOCGIFHWADDR,&hardware));
    unsigned char *mac=(unsigned char *)hardware.ifr_hwaddr.sa_data;
    printf("READY %02x:%02x:%02x:%02x:%02x:%02x\n",mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);fflush(stdout);
    for (int i=0;i<5;i++) {
        int accepted=accept4(tcp[i],NULL,NULL,SOCK_CLOEXEC);CHECK(accepted>=0);
        char message[32], expected[32];snprintf(expected,sizeof(expected),"vlan-%d-slot-%d",tags[i],i);
        size_t n=strlen(expected);
        CHECK(recv(accepted,message,n,MSG_WAITALL)==(ssize_t)n && !memcmp(message,expected,n));
        CHECK(send(accepted,message,n,MSG_NOSIGNAL)==(ssize_t)n);CHECK(!close(accepted));
        unsigned char data[1473], control[CMSG_SPACE(sizeof(struct in_pktinfo))];
        struct sockaddr_in peer;struct iovec vector={data,sizeof(data)};
        struct msghdr packet={.msg_name=&peer,.msg_namelen=sizeof(peer),.msg_iov=&vector,.msg_iovlen=1,.msg_control=control,.msg_controllen=sizeof(control)};
        CHECK(recvmsg(udp[i],&packet,0)==1472 && !packet.msg_flags);
        for (int j=0;j<1472;j++) CHECK(data[j]==(unsigned char)(j*17+i));
        struct cmsghdr *metadata=CMSG_FIRSTHDR(&packet);
        CHECK(metadata && metadata->cmsg_level==IPPROTO_IP && metadata->cmsg_type==IP_PKTINFO && metadata->cmsg_len==CMSG_LEN(sizeof(struct in_pktinfo)));
        struct in_pktinfo info;memcpy(&info,CMSG_DATA(metadata),sizeof(info));
        struct ifreq request={0};snprintf(request.ifr_name,sizeof(request.ifr_name),"%s.%d",prefix,tags[i]);
        CHECK(!ioctl(udp[i],SIOCGIFINDEX,&request) && info.ipi_ifindex==request.ifr_ifindex);
        struct in_addr local;CHECK(inet_pton(AF_INET,ips[i],&local)==1 && info.ipi_addr.s_addr==local.s_addr);
        CHECK(sendto(udp[i],data,1472,MSG_NOSIGNAL,(void *)&peer,sizeof(peer))==1472);
        CHECK(!close(tcp[i]) && !close(udp[i]));
    }
    puts("PASS: dual VLAN, VIP, device-bound TCP/UDP and VLAN interface packet metadata");
    return 0;
}
