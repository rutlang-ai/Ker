#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <limits.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
static volatile sig_atomic_t stop_requested;
static volatile sig_atomic_t udp_trigger_requested;
static void request_stop(int number){(void)number;stop_requested=1;}
static void request_udp_trigger(int number){(void)number;udp_trigger_requested=1;}
static void check(int ok,const char*message){if(!ok){perror(message);exit(1);}}

static int parse_startup_fd(void)
{
    const char *value=getenv("KER_STARTUP_FD");
    char *end=NULL;
    long parsed;
    struct stat status;
    int flags;

    if(!value||!*value){errno=EINVAL;return -1;}
    errno=0;parsed=strtol(value,&end,10);
    if(errno||end==value||*end||parsed<3||parsed>INT_MAX){errno=EINVAL;return -1;}
    flags=(int)syscall(SYS_fcntl,(int)parsed,F_GETFL);
    if(flags<0)return -1;
    if((flags&O_ACCMODE)==O_RDONLY){errno=EBADF;return -1;}
    if(syscall(SYS_fstat,(int)parsed,&status)<0)return -1;
    if(!S_ISFIFO(status.st_mode)){errno=EINVAL;return -1;}
    return (int)parsed;
}

static int termination_pending(void)
{
    sigset_t pending;
    if(stop_requested)return 1;
    if(sigpending(&pending)<0)return -errno;
    int member=sigismember(&pending,SIGTERM);
    return member<0?-errno:member;
}

static int wait_for_udp_trigger(const sigset_t *wait_mask)
{
    for(;;){
        int terminating=termination_pending();
        if(terminating<0)return terminating;
        if(terminating)return 0;
        if(udp_trigger_requested)return 1;
        int result=sigsuspend(wait_mask);
        if(result<0&&errno==EINTR)continue;
        return result<0?-errno:-EIO;
    }
}

static int write_startup_ack(int fd,const char *bytes,size_t size)
{
    unsigned attempts=0;
    while(size){
        struct pollfd event={.fd=fd,.events=POLLOUT};
        int ready;
        do {
            ready=(int)syscall(SYS_poll,&event,1,250);
            if(ready<0&&errno==EINTR&&stop_requested)return -ECANCELED;
        } while(ready<0&&errno==EINTR&&++attempts<16);
        if(ready<0)return -errno;
        if(ready==0){if(++attempts>=16)return -ETIMEDOUT;continue;}
        if(event.revents&(POLLERR|POLLHUP|POLLNVAL))return -EPIPE;
        if(!(event.revents&POLLOUT)){if(++attempts>=16)return -ETIMEDOUT;continue;}
        /* The startup descriptor is the host control pipe, so bypass the
         * interposed POSIX write path used for application network I/O. */
        long written=syscall(SYS_write,fd,bytes,size);
        if(written<0&&errno==EINTR){
            if(stop_requested)return -ECANCELED;
            if(++attempts>=16)return -EINTR;
            continue;
        }
        if(written<=0)return written<0?-errno:-EPIPE;
        bytes+=(size_t)written;size-=(size_t)written;attempts=0;
    }
    return 0;
}

static int handoff_udp_trigger(int control_fd,int udp_fd,const sigset_t *wait_mask)
{
    /* Excluding the NUL, requests are exactly
     * "KER-A09-HANDOFF-UDP seq=1\n" and "KER-A09-HANDOFF-UDP seq=2\n". */
    static const char payloads[2][32]={
        "KER-A09-HANDOFF-UDP seq=1\n",
        "KER-A09-HANDOFF-UDP seq=2\n"
    };
    sigset_t term_signal;
    sigemptyset(&term_signal);sigaddset(&term_signal,SIGTERM);
    struct sockaddr_in destination={.sin_family=AF_INET,.sin_port=htons(45001)};
    check(inet_pton(AF_INET,"198.18.0.1",&destination.sin_addr)==1,"handoff UDP destination");

    for(unsigned sequence=0;sequence<2;sequence++){
        int trigger=wait_for_udp_trigger(wait_mask);
        if(trigger<0){errno=-trigger;perror("wait for UDP trigger");return 1;}
        if(trigger==0)return 128+SIGTERM;
        udp_trigger_requested=0;

        /* SIGUSR1 stays blocked while one request is handled. SIGTERM is
         * unblocked so shutdown can win before we report an accepted send. */
        if(sigprocmask(SIG_UNBLOCK,&term_signal,NULL)<0){perror("unblock SIGTERM");return 1;}
        if(stop_requested)return 128+SIGTERM;
        size_t payload_size=strlen(payloads[sequence]);
        ssize_t sent=sendto(udp_fd,payloads[sequence],payload_size,0,
            (struct sockaddr*)&destination,sizeof(destination));
        if(stop_requested)return 128+SIGTERM;
        if(sent<0){perror("handoff UDP sendto");return 1;}
        if((size_t)sent!=payload_size){errno=EIO;perror("short handoff UDP sendto");return 1;}

        char acknowledgement[96];
        int length=snprintf(acknowledgement,sizeof(acknowledgement),
            "KER_HANDOFF_UDP_SENT seq=%u bytes=%zu\n",sequence+1,payload_size);
        if(length<0||(size_t)length>=sizeof(acknowledgement)){errno=EOVERFLOW;perror("handoff UDP acknowledgement");return 1;}
        int result=write_startup_ack(control_fd,acknowledgement,(size_t)length);
        if(result<0){errno=-result;perror("handoff UDP acknowledgement write");return stop_requested?128+SIGTERM:1;}
        if(sigprocmask(SIG_BLOCK,&term_signal,NULL)<0){perror("block SIGTERM");return 1;}
        if(stop_requested)return 128+SIGTERM;
    }

    for(;;){
        int terminating=termination_pending();
        if(terminating<0){perror("check pending SIGTERM");return 1;}
        if(terminating)return 128+SIGTERM;
        if(udp_trigger_requested){errno=EOVERFLOW;perror("unexpected extra UDP trigger");return 1;}
        int result=sigsuspend(wait_mask);
        if(result<0&&errno==EINTR)continue;
        perror("wait for application SIGTERM");return 1;
    }
}

static void transfer(int fd,char *bytes,size_t size,int sending)
{
    while(size){ssize_t n=sending?send(fd,bytes,size,MSG_NOSIGNAL):recv(fd,bytes,size,0);
        if(n<0&&errno==EINTR)continue;
        check(n>0,"native TCP transfer");bytes+=n;size-=(size_t)n;}
}
static void mtu_control(int requested,int expected_errno)
{
    int fd=socket(AF_INET,SOCK_DGRAM,0);check(fd>=0,"MTU control socket");
    struct ifreq entries[16],request={0};struct ifconf list={.ifc_len=sizeof(entries),.ifc_req=entries};
    check(!ioctl(fd,SIOCGIFCONF,&list),"native interface list");
    for(unsigned i=0;i<(unsigned)list.ifc_len/sizeof(entries[0]);i++)
        if(((struct sockaddr_in*)&entries[i].ifr_addr)->sin_addr.s_addr==htonl(0xc6120002))strcpy(request.ifr_name,entries[i].ifr_name);
    check(*request.ifr_name,"native interface found");request.ifr_mtu=requested;
    int result;
    for(unsigned attempt=0;;attempt++){
        result=ioctl(fd,SIOCSIFMTU,&request);
        if(result<0&&errno==EBUSY&&attempt<100){usleep(1000);request.ifr_mtu=requested;continue;}
        break;
    }
    check(expected_errno?(result==-1&&errno==expected_errno):result==0,"native MTU transaction result");
    check(!ioctl(fd,SIOCGIFMTU,&request)&&request.ifr_mtu==(expected_errno?1500:requested),"native MTU transaction readback");
    check(!close(fd),"MTU control close");
}
int main(int argc,char **argv)
{
    int signal_ready=argc==2&&!strcmp(argv[1],"--signal-ready");
    int udp_trigger=argc==2&&!strcmp(argv[1],"--handoff-udp-trigger");
    int fixed=argc==2&&!strcmp(argv[1],"--fixed-mtu");
    int live=argc==2&&!strcmp(argv[1],"--live-mtu");
    int rollback=argc==2&&!strcmp(argv[1],"--rollback-mtu");
    check(argc==1||signal_ready||udp_trigger||fixed||live||rollback,"service test arguments");
    struct sigaction action={.sa_handler=request_stop};sigemptyset(&action.sa_mask);
    sigset_t trigger_signals,wait_mask;
    if(udp_trigger){
        sigemptyset(&trigger_signals);sigaddset(&trigger_signals,SIGUSR1);sigaddset(&trigger_signals,SIGTERM);
        check(!sigprocmask(SIG_BLOCK,&trigger_signals,NULL),"block UDP trigger signals during setup");
    }
    check(!sigaction(SIGTERM,&action,NULL),"install application SIGTERM handler");
    if(udp_trigger){
        struct sigaction trigger_action={.sa_handler=request_udp_trigger};sigemptyset(&trigger_action.sa_mask);
        check(!sigaction(SIGUSR1,&trigger_action,NULL),"install application SIGUSR1 handler");
        struct sigaction pipe_action={.sa_handler=SIG_IGN};sigemptyset(&pipe_action.sa_mask);
        check(!sigaction(SIGPIPE,&pipe_action,NULL),"ignore startup-pipe SIGPIPE");
        check(sigprocmask(SIG_SETMASK,NULL,&wait_mask)==0,"read UDP trigger signal mask");
        sigdelset(&wait_mask,SIGUSR1);sigdelset(&wait_mask,SIGTERM);
    }
    int startup_fd=-1;
    if(udp_trigger){startup_fd=parse_startup_fd();check(startup_fd>=0,"validate KER_STARTUP_FD");}
    if(rollback)mtu_control(9000,EIO);
    if(live||rollback)mtu_control(1400,0);
    int sockets[2][2];struct timeval timeout={.tv_sec=10};
    for(unsigned family=0;family<2;family++)for(unsigned tcp=0;tcp<2;tcp++){
        int fd=socket(family?AF_INET6:AF_INET,tcp?SOCK_STREAM:SOCK_DGRAM,0);check(fd>=0,"native service socket");
        sockets[family][tcp]=fd;check(!setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout)),"native timeout");
        struct sockaddr_storage address={0};socklen_t length;
        if(family){struct sockaddr_in6*a=(void*)&address;a->sin6_family=AF_INET6;a->sin6_port=htons(45000);inet_pton(AF_INET6,"2001:db8:1::2",&a->sin6_addr);length=sizeof(*a);}
        else{struct sockaddr_in*a=(void*)&address;a->sin_family=AF_INET;a->sin_port=htons(45000);inet_pton(AF_INET,"198.18.0.2",&a->sin_addr);length=sizeof(*a);}
        check(!bind(fd,(void*)&address,length),"native service bind");if(tcp)check(!listen(fd,4),"native listen");
    }
    puts("READY");fflush(stdout);
    if(udp_trigger){
        int result=handoff_udp_trigger(startup_fd,sockets[0][0],&wait_mask);
        for(unsigned family=0;family<2;family++)for(unsigned tcp=0;tcp<2;tcp++)close(sockets[family][tcp]);
        return result;
    }
    if(signal_ready){while(!stop_requested)pause();
        for(unsigned family=0;family<2;family++)for(unsigned tcp=0;tcp<2;tcp++)close(sockets[family][tcp]);
        return 128+SIGTERM;
    }
    int barrier=getchar();
    if(barrier!='G'&&stop_requested){
        for(unsigned family=0;family<2;family++)for(unsigned tcp=0;tcp<2;tcp++)close(sockets[family][tcp]);
        return 128+SIGTERM;
    }
    check(barrier=='G',"service setup barrier");
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
    if(fixed)mtu_control(1400,EOPNOTSUPP);
    if(live||rollback)mtu_control(1500,0);
    puts("NATIVE_DONE");fflush(stdout);check(getchar()=='Q',"remote service barrier");
    puts("PASS: original native IPv4/IPv6 TCP/UDP services");return 0;
}
