#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
static void check(int ok,const char*message){if(!ok){perror(message);exit(1);}}
static void transfer(int fd,char *bytes,size_t size,int sending)
{
    while(size){ssize_t n=sending?send(fd,bytes,size,MSG_NOSIGNAL):recv(fd,bytes,size,0);
        if(n<0&&errno==EINTR)continue;
        check(n>0,"native TCP transfer");bytes+=n;size-=(size_t)n;}
}
static void fixed_mtu(void)
{
    int fd=socket(AF_INET,SOCK_DGRAM,0);check(fd>=0,"MTU control socket");
    struct ifreq entries[16],request={0};struct ifconf list={.ifc_len=sizeof(entries),.ifc_req=entries};
    check(!ioctl(fd,SIOCGIFCONF,&list),"native interface list");
    for(unsigned i=0;i<(unsigned)list.ifc_len/sizeof(entries[0]);i++)
        if(((struct sockaddr_in*)&entries[i].ifr_addr)->sin_addr.s_addr==htonl(0xc6120002))strcpy(request.ifr_name,entries[i].ifr_name);
    check(*request.ifr_name,"native interface found");request.ifr_mtu=1400;
    check(ioctl(fd,SIOCSIFMTU,&request)==-1&&errno==EOPNOTSUPP,"remote RX MTU mutation rejected");
    check(!ioctl(fd,SIOCGIFMTU,&request)&&request.ifr_mtu==1500,"native MTU preserved");
    check(!close(fd),"MTU control close");
}
int main(int argc,char **argv)
{
    check(argc==1||(argc==2&&!strcmp(argv[1],"--fixed-mtu")),"service test arguments");
    int sockets[2][2];struct timeval timeout={.tv_sec=10};
    for(unsigned family=0;family<2;family++)for(unsigned tcp=0;tcp<2;tcp++){
        int fd=socket(family?AF_INET6:AF_INET,tcp?SOCK_STREAM:SOCK_DGRAM,0);check(fd>=0,"native service socket");
        sockets[family][tcp]=fd;check(!setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout)),"native timeout");
        struct sockaddr_storage address={0};socklen_t length;
        if(family){struct sockaddr_in6*a=(void*)&address;a->sin6_family=AF_INET6;a->sin6_port=htons(45000);inet_pton(AF_INET6,"2001:db8:1::2",&a->sin6_addr);length=sizeof(*a);}
        else{struct sockaddr_in*a=(void*)&address;a->sin_family=AF_INET;a->sin_port=htons(45000);inet_pton(AF_INET,"198.18.0.2",&a->sin_addr);length=sizeof(*a);}
        check(!bind(fd,(void*)&address,length),"native service bind");if(tcp)check(!listen(fd,4),"native listen");
    }
    puts("READY");fflush(stdout);check(getchar()=='G',"service setup barrier");
    for(unsigned family=0;family<2;family++){
        int connection=accept(sockets[family][1],NULL,NULL);check(connection>=0,"native TCP accept");
        check(!setsockopt(connection,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout)),"accepted timeout");
        char data[4097],prefix[]="NATIVE:";transfer(connection,data,sizeof(data),0);
        for(unsigned i=0;i<sizeof(data);i++)check((unsigned char)data[i]==(unsigned char)(i*17+(i>>8)),"native request bytes");
        transfer(connection,prefix,sizeof(prefix)-1,1);transfer(connection,data,sizeof(data),1);check(!close(connection),"native accepted close");
        struct sockaddr_storage peer;socklen_t length=sizeof(peer);
        check(recvfrom(sockets[family][0],data,sizeof(data),0,(void*)&peer,&length)==512,"native UDP receive");
        for(unsigned i=0;i<512;i++)check((unsigned char)data[i]==(unsigned char)(i*17+(i>>8)),"native UDP bytes");
        char reply[519];memcpy(reply,prefix,7);memcpy(reply+7,data,512);
        check(sendto(sockets[family][0],reply,sizeof(reply),0,(void*)&peer,length)==sizeof(reply),"native UDP reply");
        check(!close(sockets[family][0])&&!close(sockets[family][1]),"native service close");
    }
    if(argc==2)fixed_mtu();
    puts("NATIVE_DONE");fflush(stdout);check(getchar()=='Q',"remote service barrier");
    puts("PASS: original native IPv4/IPv6 TCP/UDP services");return 0;
}
