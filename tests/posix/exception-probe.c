#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>
static void check(int ok,const char*message){if(!ok){perror(message);exit(1);}}
int main(void)
{
    puts("READY");fflush(stdout);check(getchar()=='G',"host setup barrier");
    int fd=socket(AF_INET,SOCK_DGRAM,0);check(fd>=0,"native UDP");
    struct timeval timeout={.tv_sec=3};check(!setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout)),"receive timeout");
    struct sockaddr_in peer={.sin_family=AF_INET,.sin_port=htons(42000)};inet_pton(AF_INET,"198.18.0.1",&peer.sin_addr);
    const char payload[]="native-UDP-remains-on-original-Linux";char data[128];
    for (unsigned i=0;i<32;i++) {
        check(sendto(fd,payload,sizeof(payload),0,(void*)&peer,sizeof(peer))==sizeof(payload),"native send");
        check(recv(fd,data,sizeof(data),0)==sizeof(payload)&&!memcmp(data,payload,sizeof(payload)),"native independent echo");
    }
    /* Bridge MTU changes are explicitly unsupported until a two-device
     * transaction can preserve both sides; no successful one-sided change. */
    struct ifreq entries[16], request={0};struct ifconf list={.ifc_len=sizeof(entries),.ifc_req=entries};
    check(!ioctl(fd,SIOCGIFCONF,&list),"native interface list");
    for(unsigned i=0;i<(unsigned)list.ifc_len/sizeof(entries[0]);i++)
        if(((struct sockaddr_in*)&entries[i].ifr_addr)->sin_addr.s_addr==htonl(0xc6120002))strcpy(request.ifr_name,entries[i].ifr_name);
    check(*request.ifr_name,"native device found");request.ifr_mtu=1400;
    check(ioctl(fd,SIOCSIFMTU,&request)==-1&&errno==EOPNOTSUPP,"bridge MTU mutation rejected");
    check(!ioctl(fd,SIOCGIFMTU,&request)&&request.ifr_mtu==1500,"native MTU preserved");
    check(!close(fd),"native close");puts("NATIVE_DONE");fflush(stdout);
    check(getchar()=='Q',"exception frame barrier");puts("PASS: native UDP and exception bridge coexist");return 0;
}
