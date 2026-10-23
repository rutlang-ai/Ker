/* Inject failures only at the actual worker -> native packet-channel send.
 * All successful sends continue through the original host socket syscall. */
#define _GNU_SOURCE
#include "packet-channel.h"
#include <dlfcn.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
ssize_t sendmsg(int fd,const struct msghdr *message,int flags)
{
    static _Thread_local ssize_t (*original)(int,const struct msghdr*,int);
    static _Thread_local bool initialized,worker;
    static _Thread_local unsigned left=3;
    if(!original)original=dlsym(RTLD_NEXT,"sendmsg");
    if(!initialized){char path[4096];ssize_t n=readlink("/proc/self/exe",path,sizeof(path)-1);
        if(n>=0){path[n]=0;worker=strstr(path,"/ker-io-worker")!=NULL;}initialized=true;}
    if(worker&&left&&message&&message->msg_iovlen==2&&message->msg_iov[0].iov_len==sizeof(struct ker_packet_header)&&
       message->msg_iov[1].iov_len>=14){const unsigned char *p=message->msg_iov[1].iov_base;
        if(p[12]==8&&p[13]==6){left--;fprintf(stderr,"INJECT: exception ARP native-channel EAGAIN\n");errno=EAGAIN;return -1;}}
    if(!original){errno=ENOSYS;return -1;}return original(fd,message,flags);
}
