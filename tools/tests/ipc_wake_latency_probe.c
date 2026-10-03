/* SPDX-License-Identifier: MPL-2.0 */
/* Freestanding Linux ABI probe: 32 futex and 32 epoll/pipe round trips. */
typedef unsigned long u64;
typedef long i64;
struct timespec { i64 sec, nsec; };
struct timeval { i64 sec, usec; };
struct itimerval { struct timeval interval, value; };
#if defined(__x86_64__)
enum { N_read=0, N_write=1, N_close=3, N_mmap=9, N_setitimer=38,
       N_clone=56, N_exit=60, N_wait4=61, N_futex=202, N_clock=228,
       N_epoll_wait=232, N_epoll_ctl=233, N_epoll_create=291, N_pipe=293 };
struct event { unsigned events; u64 data; } __attribute__((packed));
static i64 call(i64 n,i64 a,i64 b,i64 c,i64 d,i64 e,i64 f) {
    register i64 r10 __asm__("r10")=d, r8 __asm__("r8")=e, r9 __asm__("r9")=f;
    i64 r; __asm__ volatile("syscall":"=a"(r):"a"(n),"D"(a),"S"(b),"d"(c),
                           "r"(r10),"r"(r8),"r"(r9):"rcx","r11","memory"); return r;
}
__asm__(".global _start\n_start:\n xor %rbp,%rbp\n and $-16,%rsp\n call probe_main\n ud2\n");
#else
enum { N_read=63, N_write=64, N_close=57, N_mmap=222, N_setitimer=103,
       N_clone=220, N_exit=93, N_wait4=260, N_futex=98, N_clock=113,
       N_epoll_wait=22, N_epoll_ctl=21, N_epoll_create=20, N_pipe=59 };
struct event { unsigned events; u64 data; };
static i64 call(i64 n,i64 a,i64 b,i64 c,i64 d,i64 e,i64 f) {
    register i64 x8 __asm__("x8")=n, x0 __asm__("x0")=a, x1 __asm__("x1")=b;
    register i64 x2 __asm__("x2")=c, x3 __asm__("x3")=d;
    register i64 x4 __asm__("x4")=e, x5 __asm__("x5")=f;
    __asm__ volatile("svc #0":"+r"(x0):"r"(x8),"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5):"memory"); return x0;
}
__asm__(".global _start\n_start:\n mov x29,xzr\n bl probe_main\n brk #0\n");
#endif
static void text(const char *s) { u64 n=0; while(s[n])++n; call(N_write,1,(i64)s,n,0,0,0); }
static void number(u64 v) { char b[24]; unsigned n=0; do { b[n++]=(char)('0'+v%10); v/=10; } while(v); while(n)call(N_write,1,(i64)&b[--n],1,0,0,0); }
__attribute__((noreturn)) static void finish(int code) { call(N_exit,code,0,0,0,0,0); for(;;){} }
static i64 check(i64 r) { if(r<0) { text("probe syscall failed errno=");number((u64)-r);text("\n");finish(1); } return r; }
static u64 clock_ns(int id) { struct timespec t; check(call(N_clock,id,(i64)&t,0,0,0,0));return (u64)t.sec*1000000000ul+t.nsec; }
static void bound(void) { struct itimerval t={{0,0},{5,0}};check(call(N_setitimer,0,(i64)&t,0,0,0,0)); }
struct shared { unsigned turn; u64 received_ns, child_cpu_ns; };
static void wait_turn(struct shared *s,unsigned value) {
    while(__atomic_load_n(&s->turn,__ATOMIC_ACQUIRE)!=value) {
        unsigned old=__atomic_load_n(&s->turn,__ATOMIC_ACQUIRE);
        if(old==value)break;
        i64 r=call(N_futex,(i64)&s->turn,0,old,0,0,0);
        if(r!=-11 && r!=-4)check(r);
    }
}
static void set_turn(struct shared *s,unsigned value) {
    __atomic_store_n(&s->turn,value,__ATOMIC_RELEASE);
    check(call(N_futex,(i64)&s->turn,1,1,0,0,0));
}
static void byte_io(int fd,int write) {
    char c=1; i64 r;
    do { r=call(write?N_write:N_read,fd,(i64)&c,1,0,0,0); } while(r==-4);
    if(check(r)!=1)finish(2);
}
static void stats(const char *name,u64 *v) {
    for(unsigned i=1;i<32;++i) { u64 x=v[i];unsigned j=i;while(j && v[j-1]>x){v[j]=v[j-1];--j;}v[j]=x; }
    text(name);text("_ns p50=");number(v[15]);text(" p95=");number(v[30]);text(" max=");number(v[31]);text("\n");
}
static void run(int pipes) {
    struct shared *s=(struct shared *)check(call(N_mmap,0,4096,3,0x21,-1,0));
    int a[2],b[2],ep=-1;
    struct event ev={1,1};
    if(pipes) {
        check(call(N_pipe,(i64)a,0,0,0,0,0));check(call(N_pipe,(i64)b,0,0,0,0,0));
        ep=(int)check(call(N_epoll_create,0,0,0,0,0,0));
        check(call(N_epoll_ctl,ep,1,b[0],(i64)&ev,0,0));
    }
    i64 pid=check(call(N_clone,17,0,0,0,0,0));
    if(!pid) {
        bound(); u64 cpu=clock_ns(2);
        for(unsigned i=0;i<32;++i) {
            if(pipes)byte_io(a[0],0);else wait_turn(s,1);
            s->received_ns=clock_ns(1);
            if(i==31)s->child_cpu_ns=clock_ns(2)-cpu;
            if(pipes)byte_io(b[1],1);else set_turn(s,0);
        }
        finish(0);
    }
    u64 rtt[32],forward[32],wall=clock_ns(1),cpu=clock_ns(2);
    for(unsigned i=0;i<32;++i) {
        u64 begin=clock_ns(1);
        if(pipes) {
            byte_io(a[1],1);
            i64 r;do { r=call(N_epoll_wait,ep,(i64)&ev,1,1000,0,0); } while(r==-4);
            if(check(r)!=1) { text("epoll timeout\n");finish(3); }
            byte_io(b[0],0);
        } else { set_turn(s,1);wait_turn(s,0); }
        rtt[i]=clock_ns(1)-begin;forward[i]=s->received_ns-begin;
    }
    cpu=clock_ns(2)-cpu;wall=clock_ns(1)-wall;
    int status=0;check(call(N_wait4,pid,(i64)&status,0,0,0,0));
    if(status) { text("child failed\n");finish(4); }
    text(pipes?"mode=epoll_pipe ":"mode=futex ");text("rounds=32 wall_ns=");number(wall);
    text(" parent_cpu_ns=");number(cpu);text(" child_cpu_ns=");number(s->child_cpu_ns);text("\n");
    stats("roundtrip",rtt);stats("send_to_child_receive",forward);
    if(pipes) { for(int i=0;i<2;++i){check(call(N_close,a[i],0,0,0,0,0));check(call(N_close,b[i],0,0,0,0,0));}check(call(N_close,ep,0,0,0,0,0)); }
}
void probe_main(void) { bound();run(0);run(1);text("IPC_WAKE_PASS\n");finish(0); }
