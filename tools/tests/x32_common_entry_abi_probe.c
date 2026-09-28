/* SPDX-License-Identifier: MPL-2.0 */
/* Linux x32 common-entry layout probe. */

#include <stdint.h>

#define START_ATTRIBUTES __attribute__((noreturn, force_align_arg_pointer))
#define X32_BIT UINT64_C(0x40000000)
#define SYS_write 1
#define SYS_exit 60
#define X32_close 3
#define X32_poll 7
#define X32_mmap 9
#define X32_mprotect 10
#define X32_munmap 11
#define X32_mincore 27
#define X32_madvise 28
#define X32_getrlimit 97
#define X32_sysinfo 99
#define X32_futex 202
#define X32_epoll_wait 232
#define X32_epoll_ctl 233
#define X32_eventfd2 290
#define X32_epoll_create1 291
#define X32_prlimit64 302
#define PROT_READ 1
#define PROT_WRITE 2
#define MAP_PRIVATE 2
#define MAP_ANONYMOUS 0x20
#define MADV_NORMAL 0
#define FUTEX_WAIT 0
#define EAGAIN 11
#define RLIMIT_NOFILE 7
#define EPOLL_CTL_ADD 1
#define EPOLLIN 1
#define O_CLOEXEC 02000000

struct pollfd {
    int32_t descriptor;
    int16_t events;
    int16_t returned_events;
};

struct epoll_event {
    uint32_t events;
    uint64_t data;
} __attribute__((packed));

struct rlimit64 {
    uint64_t current;
    uint64_t maximum;
};

static struct pollfd poll_descriptor;
static struct epoll_event event;
static struct epoll_event returned_event;
static struct rlimit64 limit;
static uint8_t system_information[112];
static uint32_t futex_word;
static uint64_t event_value = 1;
static uint8_t residency;

static long call(long number, long a0, long a1, long a2,
                 long a3, long a4, long a5) {
    register long r10 __asm__("r10") = a3;
    register long r8 __asm__("r8") = a4;
    register long r9 __asm__("r9") = a5;
    long result;
    __asm__ volatile("syscall" : "=a"(result) : "a"(number), "D"(a0),
                     "S"(a1), "d"(a2), "r"(r10), "r"(r8), "r"(r9)
                     : "rcx", "r11", "memory");
    return result;
}

static long x32(long number, long a0, long a1, long a2,
                long a3, long a4, long a5) {
    return call((long)(X32_BIT | (uint64_t)number),
                a0, a1, a2, a3, a4, a5);
}

static unsigned long text_length(const char *text) {
    unsigned long length = 0;
    while (text[length]) ++length;
    return length;
}

static void print_text(const char *text) {
    call(SYS_write, 1, (long)text, (long)text_length(text), 0, 0, 0);
}

static int expect(const char *name, long actual, long expected) {
    if (actual == expected) return 0;
    print_text("FAIL "); print_text(name); print_text("\n");
    return 1;
}

START_ATTRIBUTES void _start(void) {
    long mapping;
    long eventfd;
    long epollfd;
    int failures = 0;

    mapping = x32(X32_mmap, 0, 4096, PROT_READ | PROT_WRITE,
                  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mapping < 0) {
        failures += expect("mmap", mapping, 0);
    } else {
        *(volatile uint32_t *)(uintptr_t)mapping = UINT32_C(0x12345678);
        failures += expect("mincore", x32(
            X32_mincore, mapping, 4096, (long)&residency, 0, 0, 0), 0);
        failures += expect("madvise", x32(
            X32_madvise, mapping, 4096, MADV_NORMAL, 0, 0, 0), 0);
        failures += expect("mprotect", x32(
            X32_mprotect, mapping, 4096, PROT_READ, 0, 0, 0), 0);
        failures += expect("munmap", x32(
            X32_munmap, mapping, 4096, 0, 0, 0, 0), 0);
    }

    failures += expect("getrlimit", x32(
        X32_getrlimit, RLIMIT_NOFILE, (long)&limit, 0, 0, 0, 0), 0);
    failures += expect("prlimit64", x32(
        X32_prlimit64, 0, RLIMIT_NOFILE, 0, (long)&limit, 0, 0), 0);
    failures += expect("sysinfo", x32(
        X32_sysinfo, (long)system_information, 0, 0, 0, 0, 0), 0);
    failures += expect("futex-mismatch", x32(
        X32_futex, (long)&futex_word, FUTEX_WAIT, 1, 0, 0, 0), -EAGAIN);
    failures += expect("empty-poll", x32(
        X32_poll, 0, 0, 0, 0, 0, 0), 0);

    eventfd = x32(X32_eventfd2, 0, O_CLOEXEC, 0, 0, 0, 0);
    epollfd = x32(X32_epoll_create1, O_CLOEXEC, 0, 0, 0, 0, 0);
    if (eventfd < 0 || epollfd < 0) {
        failures += expect("descriptor-create", -1, 0);
    } else {
        poll_descriptor.descriptor = (int32_t)eventfd;
        poll_descriptor.events = EPOLLIN;
        failures += expect("poll-empty", x32(
            X32_poll, (long)&poll_descriptor, 1, 0, 0, 0, 0), 0);
        event.events = EPOLLIN;
        event.data = UINT64_C(0x1122334455667788);
        failures += expect("epoll-add", x32(
            X32_epoll_ctl, epollfd, EPOLL_CTL_ADD, eventfd,
            (long)&event, 0, 0), 0);
        failures += expect("eventfd-write", x32(
            SYS_write, eventfd, (long)&event_value, sizeof(event_value),
            0, 0, 0), sizeof(event_value));
        failures += expect("epoll-wait", x32(
            X32_epoll_wait, epollfd, (long)&returned_event, 1,
            0, 0, 0), 1);
        failures += expect("epoll-data",
                           (long)returned_event.data, (long)event.data);
    }
    if (eventfd >= 0) x32(X32_close, eventfd, 0, 0, 0, 0, 0);
    if (epollfd >= 0) x32(X32_close, epollfd, 0, 0, 0, 0, 0);

    if (failures) {
        print_text("X32_COMMON_ENTRY_ABI_PROBE_FAIL\n");
        call(SYS_exit, 1, 0, 0, 0, 0, 0);
    }
    print_text("X32_COMMON_ENTRY_ABI_PROBE_PASS\n");
    call(SYS_exit, 0, 0, 0, 0, 0, 0);
    __builtin_unreachable();
}
