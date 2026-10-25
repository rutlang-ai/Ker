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
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <sys/socket.h>
#include <unistd.h>
#ifdef KER_EXCEPTION_SERVICES_SIGNAL_TEST
#include <sched.h>
#include <time.h>
#endif
_Static_assert(ATOMIC_INT_LOCK_FREE==2,"signal handlers require lock-free integer atomics");
static atomic_int stop_requested;
static atomic_int udp_trigger_requested;
static atomic_int signal_wakeup_error;
static atomic_int signal_wakeup_fd=-1;
#ifdef KER_EXCEPTION_SERVICES_SIGNAL_TEST
static atomic_int signal_test_handler_tid;
static void (*signal_test_before_wait)(void);
static pthread_t signal_test_target;
static atomic_int signal_test_target_tid;
static atomic_int signal_test_target_ready;
static atomic_int signal_test_target_exit;
static atomic_int signal_test_mode;
static atomic_int signal_test_fill_pipe;
static int signal_test_target_stop_fd=-1;
#endif
static void queue_signal_wakeup(char event)
{
    int saved_errno=errno;
    if(signal_wakeup_fd>=0){
        long amount=syscall(SYS_write,(int)signal_wakeup_fd,&event,1);
        if(amount<0&&(errno==EAGAIN||errno==EWOULDBLOCK)){
            /* A full pipe is already readable; the atomic request flag is
             * authoritative when the main thread drains that wakeup. */
        } else if(amount!=1)signal_wakeup_error=1;
    }
    errno=saved_errno;
}
static void request_stop(int number)
{
    (void)number;stop_requested=1;queue_signal_wakeup('T');
}
static void request_udp_trigger(int number)
{
    (void)number;udp_trigger_requested=1;
#ifdef KER_EXCEPTION_SERVICES_SIGNAL_TEST
    signal_test_handler_tid=(sig_atomic_t)syscall(SYS_gettid);
#endif
    queue_signal_wakeup('U');
}
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

static int setup_udp_trigger_signals(int wake_fds[2])
{
    if(syscall(SYS_pipe2,wake_fds,O_NONBLOCK|O_CLOEXEC)<0)return -errno;
    signal_wakeup_fd=wake_fds[1];
    struct sigaction action={.sa_handler=request_stop};sigemptyset(&action.sa_mask);
    if(sigaction(SIGTERM,&action,NULL)<0)return -errno;
    struct sigaction trigger_action={.sa_handler=request_udp_trigger};sigemptyset(&trigger_action.sa_mask);
    if(sigaction(SIGUSR1,&trigger_action,NULL)<0)return -errno;
    struct sigaction pipe_action={.sa_handler=SIG_IGN};sigemptyset(&pipe_action.sa_mask);
    if(sigaction(SIGPIPE,&pipe_action,NULL)<0)return -errno;
    return 0;
}

static int wait_for_udp_trigger(int wake_fd)
{
    for(;;){
        if(stop_requested)return 0;
        if(signal_wakeup_error)return -EIO;
        if(atomic_exchange(&udp_trigger_requested,0))return 1;
#ifdef KER_EXCEPTION_SERVICES_SIGNAL_TEST
        if(signal_test_before_wait)signal_test_before_wait();
#endif
        struct pollfd event={.fd=wake_fd,.events=POLLIN};
        int result=(int)syscall(SYS_poll,&event,1,-1);
        if(result<0&&errno==EINTR)continue;
        if(result<0)return -errno;
        if(result!=1||event.revents&(POLLERR|POLLHUP|POLLNVAL))return -EIO;
        char notifications[256];
        for(;;){
            ssize_t amount=syscall(SYS_read,wake_fd,notifications,sizeof(notifications));
            if(amount>0)continue;
            if(amount<0&&(errno==EINTR))continue;
            if(amount<0&&(errno==EAGAIN||errno==EWOULDBLOCK))break;
            return amount<0?-errno:-EPIPE;
        }
        if(stop_requested)return 0;
        if(signal_wakeup_error)return -EIO;
        if(atomic_exchange(&udp_trigger_requested,0))return 1;
    }
}

static int wait_for_application_termination(int wake_fd)
{
    for(;;){
        if(stop_requested)return 1;
        if(signal_wakeup_error)return -EIO;
        struct pollfd event={.fd=wake_fd,.events=POLLIN};
        int result=(int)syscall(SYS_poll,&event,1,-1);
        if(result<0&&errno==EINTR)continue;
        if(result<0)return -errno;
        if(result!=1||event.revents&(POLLERR|POLLHUP|POLLNVAL))return -EIO;
        char notifications[64];
        ssize_t amount=syscall(SYS_read,wake_fd,notifications,sizeof(notifications));
        if(amount<0&&(errno==EINTR||errno==EAGAIN||errno==EWOULDBLOCK))continue;
        if(amount<=0)return amount<0?-errno:-EPIPE;
        if(stop_requested)return 1;
        if(signal_wakeup_error)return -EIO;
        if(atomic_exchange(&udp_trigger_requested,0))return -EOVERFLOW;
        (void)notifications;
    }
}

#ifdef KER_EXCEPTION_SERVICES_SIGNAL_TEST
static void *signal_test_target_main(void *unused)
{
    (void)unused;
    signal_test_target_tid=(sig_atomic_t)syscall(SYS_gettid);
    signal_test_target_ready=1;
    while(!signal_test_target_exit){
        struct pollfd event={.fd=signal_test_target_stop_fd,.events=POLLIN};
        int result=(int)syscall(SYS_poll,&event,1,-1);
        if(result<0&&errno==EINTR)continue;
        if(result<=0)break;
        char byte;
        if(syscall(SYS_read,signal_test_target_stop_fd,&byte,1)==1)break;
    }
    return NULL;
}

static int signal_test_wait_flag(atomic_int *flag)
{
    struct timespec start,now;
    if(clock_gettime(CLOCK_MONOTONIC,&start)<0)return -errno;
    do {
        if(*flag)return 0;
        if(clock_gettime(CLOCK_MONOTONIC,&now)<0)return -errno;
        if(now.tv_sec-start.tv_sec>2)return -ETIMEDOUT;
        sched_yield();
    } while(1);
}

static void signal_test_fire_between_check_and_wait(void)
{
    int mode=signal_test_mode;
    signal_test_before_wait=NULL;
    if(mode==2&&signal_test_fill_pipe){
        char bytes[256]={0};
        for(;;){
            long amount=syscall(SYS_write,(int)signal_wakeup_fd,bytes,sizeof(bytes));
            if(amount>0)continue;
            if(errno==EAGAIN||errno==EWOULDBLOCK)break;
            signal_wakeup_error=1;return;
        }
    }
    if(pthread_kill(signal_test_target,SIGUSR1)!=0||
        signal_test_wait_flag(&udp_trigger_requested)) {
        signal_wakeup_error=1;
        return;
    }
    if(mode==2&&(pthread_kill(signal_test_target,SIGTERM)!=0||
        signal_test_wait_flag(&stop_requested)))signal_wakeup_error=1;
}

static int run_signal_wakeup_selftest(void)
{
    int wake_fds[2]={-1,-1};
    int target_stop_fds[2]={-1,-1};
    if(setup_udp_trigger_signals(wake_fds)<0||
        syscall(SYS_pipe2,target_stop_fds,O_NONBLOCK|O_CLOEXEC)<0)return 1;
    signal_test_target_stop_fd=target_stop_fds[0];
    if(pthread_create(&signal_test_target,NULL,signal_test_target_main,NULL)!=0)return 1;
    if(signal_test_wait_flag(&signal_test_target_ready))return 1;
    signal_test_mode=1;
    signal_test_before_wait=signal_test_fire_between_check_and_wait;
    int result=wait_for_udp_trigger(wake_fds[0]);
    if(result!=1||signal_test_handler_tid!=signal_test_target_tid) {
        fprintf(stderr,"signal wakeup test lost a trigger handled by another thread\n");return 1;
    }
    stop_requested=0;udp_trigger_requested=0;signal_wakeup_error=0;
    signal_test_mode=2;
    signal_test_fill_pipe=1;
    signal_test_before_wait=signal_test_fire_between_check_and_wait;
    result=wait_for_udp_trigger(wake_fds[0]);
    if(result!=0||!stop_requested||signal_wakeup_error) {
        fprintf(stderr,"SIGTERM did not take priority over a queued UDP trigger\n");return 1;
    }
    signal_test_target_exit=1;
    if(syscall(SYS_write,target_stop_fds[1],"X",1)!=1||pthread_join(signal_test_target,NULL)!=0)return 1;
    atomic_store(&signal_wakeup_fd,-1);
    close(wake_fds[0]);close(wake_fds[1]);close(target_stop_fds[0]);close(target_stop_fds[1]);
    puts("PASS: cross-thread signal wakeup and SIGTERM priority");
    return 0;
}
#endif

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

static int handoff_udp_trigger(int control_fd,int udp_fd,int wake_fd)
{
    /* Excluding the NUL, requests are exactly
     * "KER-A09-HANDOFF-UDP seq=1\n" and "KER-A09-HANDOFF-UDP seq=2\n". */
    static const char payloads[2][32]={
        "KER-A09-HANDOFF-UDP seq=1\n",
        "KER-A09-HANDOFF-UDP seq=2\n"
    };
    struct sockaddr_in destination={.sin_family=AF_INET,.sin_port=htons(45001)};
    check(inet_pton(AF_INET,"198.18.0.1",&destination.sin_addr)==1,"handoff UDP destination");

    for(unsigned sequence=0;sequence<2;sequence++){
        int trigger=wait_for_udp_trigger(wake_fd);
        if(trigger<0){errno=-trigger;perror("wait for UDP trigger");return 1;}
        if(trigger==0)return 128+SIGTERM;
        udp_trigger_requested=0;

        /* Signal handlers wake this thread through a host pipe even when the
         * LKL-created threads receive the process-directed signal. */
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
        if(stop_requested)return 128+SIGTERM;
    }

    for(;;){
        int terminating=wait_for_application_termination(wake_fd);
        if(terminating==1)return 128+SIGTERM;
        errno=terminating<0?-terminating:EIO;
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
#ifdef KER_EXCEPTION_SERVICES_SIGNAL_TEST
    if(argc==2&&!strcmp(argv[1],"--signal-wakeup-selftest"))return run_signal_wakeup_selftest();
#endif
    int signal_ready=argc==2&&!strcmp(argv[1],"--signal-ready");
    int udp_trigger=argc==2&&!strcmp(argv[1],"--handoff-udp-trigger");
    int fixed=argc==2&&!strcmp(argv[1],"--fixed-mtu");
    int live=argc==2&&!strcmp(argv[1],"--live-mtu");
    int rollback=argc==2&&!strcmp(argv[1],"--rollback-mtu");
    check(argc==1||signal_ready||udp_trigger||fixed||live||rollback,"service test arguments");
    struct sigaction action={.sa_handler=request_stop};sigemptyset(&action.sa_mask);
    int wake_fds[2]={-1,-1};
    if(udp_trigger)check(setup_udp_trigger_signals(wake_fds)==0,"install UDP trigger signal wakeup");
    else check(!sigaction(SIGTERM,&action,NULL),"install application SIGTERM handler");
    if(udp_trigger){
        check(wake_fds[0]>=0&&wake_fds[1]>=0,"create UDP trigger signal wakeup pipe");
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
        int result=handoff_udp_trigger(startup_fd,sockets[0][0],wake_fds[0]);
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
