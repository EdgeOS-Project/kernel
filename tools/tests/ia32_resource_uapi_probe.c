/* SPDX-License-Identifier: MPL-2.0 */
/* Freestanding Linux i386 resource and filesystem-stat UAPI probe. */

#include <stdint.h>

#define SYS_exit 1
#define SYS_fork 2
#define SYS_write 4
#define SYS_open 5
#define SYS_close 6
#define SYS_times 43
#define SYS_ustat 62
#define SYS_setrlimit 75
#define SYS_getrlimit 76
#define SYS_getrusage 77
#define SYS_statfs 99
#define SYS_fstatfs 100
#define SYS_wait4 114
#define SYS_sysinfo 116
#define SYS_ugetrlimit 191
#define SYS_statfs64 268
#define SYS_fstatfs64 269
#define SYS_waitid 284

#define RLIMIT_CORE 4
#define RUSAGE_SELF 0
#define P_PID 1
#define WEXITED 4
#define EINVAL 22
#define O_RDONLY 0
#define GUARD 0xa55a3cc3u

struct rlimit32 {
    uint32_t current;
    uint32_t maximum;
};

struct timeval32 {
    int32_t seconds;
    int32_t microseconds;
};

struct rusage32 {
    struct timeval32 user_time;
    struct timeval32 system_time;
    int32_t values[14];
};

struct tms32 {
    int32_t user_time;
    int32_t system_time;
    int32_t children_user_time;
    int32_t children_system_time;
};

struct sysinfo32 {
    int32_t uptime;
    uint32_t loads[3];
    uint32_t totalram;
    uint32_t freeram;
    uint32_t sharedram;
    uint32_t bufferram;
    uint32_t totalswap;
    uint32_t freeswap;
    uint16_t processes;
    uint16_t padding;
    uint32_t totalhigh;
    uint32_t freehigh;
    uint32_t memory_unit;
    uint8_t reserved[8];
};

struct statfs32 {
    uint32_t type;
    uint32_t block_size;
    uint32_t blocks;
    uint32_t free_blocks;
    uint32_t available_blocks;
    uint32_t files;
    uint32_t free_files;
    int32_t filesystem_id[2];
    uint32_t name_length;
    uint32_t fragment_size;
    uint32_t flags;
    uint32_t spare[4];
};

struct __attribute__((packed, aligned(4))) statfs64_compat {
    uint32_t type;
    uint32_t block_size;
    uint64_t blocks;
    uint64_t free_blocks;
    uint64_t available_blocks;
    uint64_t files;
    uint64_t free_files;
    int32_t filesystem_id[2];
    uint32_t name_length;
    uint32_t fragment_size;
    uint32_t flags;
    uint32_t spare[4];
};

struct guarded_rusage {
    struct rusage32 value;
    uint32_t guard;
};

struct guarded_tms {
    struct tms32 value;
    uint32_t guard;
};

struct guarded_sysinfo {
    struct sysinfo32 value;
    uint32_t guard;
};

struct guarded_statfs32 {
    struct statfs32 value;
    uint32_t guard;
};

struct guarded_statfs64 {
    struct statfs64_compat value;
    uint32_t guard;
};

struct guarded_siginfo {
    uint8_t value[128];
    uint32_t guard;
};

void *memset(void *destination, int value, uint32_t size) {
    volatile uint8_t *output = (volatile uint8_t *)destination;
    for (uint32_t index = 0; index < size; ++index)
        output[index] = (uint8_t)value;
    return destination;
}

__attribute__((naked)) static long raw_call6(
        long number, long a0, long a1, long a2,
        long a3, long a4, long a5) {
    __asm__ volatile(
        "pushl %ebp\n"
        "pushl %edi\n"
        "pushl %esi\n"
        "pushl %ebx\n"
        "movl 20(%esp), %eax\n"
        "movl 24(%esp), %ebx\n"
        "movl 28(%esp), %ecx\n"
        "movl 32(%esp), %edx\n"
        "movl 36(%esp), %esi\n"
        "movl 40(%esp), %edi\n"
        "movl 44(%esp), %ebp\n"
        "int $0x80\n"
        "popl %ebx\n"
        "popl %esi\n"
        "popl %edi\n"
        "popl %ebp\n"
        "ret\n");
}

#define call6(number, a0, a1, a2, a3, a4, a5) \
    raw_call6((number), \
              (long)(uintptr_t)(a0), (long)(uintptr_t)(a1), \
              (long)(uintptr_t)(a2), (long)(uintptr_t)(a3), \
              (long)(uintptr_t)(a4), (long)(uintptr_t)(a5))

static uint32_t text_length(const char *text) {
    uint32_t length = 0;
    while (text[length]) ++length;
    return length;
}

static void print_text(const char *text) {
    call6(SYS_write, 1, text, text_length(text), 0, 0, 0);
}

static void fail(const char *name) {
    print_text("IA32_RESOURCE_UAPI_PROBE_FAIL ");
    print_text(name);
    print_text("\n");
    call6(SYS_exit, 1, 0, 0, 0, 0, 0);
    __builtin_unreachable();
}

static void test_resource_limits(void) {
    struct rlimit32 normal = {0, 0};
    struct rlimit32 legacy = {0, 0};
    struct rlimit32 infinity = {UINT32_MAX, UINT32_MAX};

    if (call6(SYS_setrlimit, RLIMIT_CORE, &infinity, 0, 0, 0, 0) != 0)
        fail("setrlimit");
    if (call6(SYS_ugetrlimit, RLIMIT_CORE, &normal, 0, 0, 0, 0) != 0)
        fail("ugetrlimit");
    if (normal.current != UINT32_MAX || normal.maximum != UINT32_MAX)
        fail("ugetrlimit-infinity");
    if (call6(SYS_getrlimit, RLIMIT_CORE, &legacy, 0, 0, 0, 0) != 0)
        fail("getrlimit");
    if (legacy.current != INT32_MAX || legacy.maximum != INT32_MAX)
        fail("getrlimit-old-infinity");
}

static void test_accounting(void) {
    struct guarded_rusage usage;
    struct guarded_tms times;

    memset(&usage, 0, sizeof(usage));
    usage.guard = GUARD;
    if (call6(SYS_getrusage, RUSAGE_SELF, &usage.value, 0, 0, 0, 0) != 0)
        fail("getrusage");
    if (usage.guard != GUARD || usage.value.user_time.microseconds < 0 ||
        usage.value.user_time.microseconds >= 1000000)
        fail("getrusage-layout");
    memset(&times, 0, sizeof(times));
    times.guard = GUARD;
    if (call6(SYS_times, &times.value, 0, 0, 0, 0, 0) < 0)
        fail("times");
    if (times.guard != GUARD) fail("times-layout");
}

static void test_system_and_filesystem(void) {
    struct guarded_sysinfo information;
    struct guarded_statfs32 filesystem;
    struct guarded_statfs32 descriptor_filesystem;
    struct guarded_statfs64 filesystem64;
    struct guarded_statfs64 descriptor_filesystem64;
    long descriptor;

    memset(&information, 0, sizeof(information));
    information.guard = GUARD;
    if (call6(SYS_sysinfo, &information.value, 0, 0, 0, 0, 0) != 0)
        fail("sysinfo");
    if (information.guard != GUARD || !information.value.memory_unit ||
        !information.value.processes)
        fail("sysinfo-layout");
    memset(&filesystem, 0, sizeof(filesystem));
    filesystem.guard = GUARD;
    if (call6(SYS_statfs, "/", &filesystem.value, 0, 0, 0, 0) != 0)
        fail("statfs");
    if (filesystem.guard != GUARD || !filesystem.value.type ||
        !filesystem.value.block_size)
        fail("statfs-layout");
    memset(&filesystem64, 0, sizeof(filesystem64));
    filesystem64.guard = GUARD;
    if (call6(SYS_statfs64, "/", sizeof(filesystem64.value),
              &filesystem64.value, 0, 0, 0) != 0)
        fail("statfs64");
    if (filesystem64.guard != GUARD || !filesystem64.value.type ||
        !filesystem64.value.block_size)
        fail("statfs64-layout");
    if (call6(SYS_statfs64, "/", sizeof(filesystem64.value) - 1u,
              &filesystem64.value, 0, 0, 0) != -EINVAL)
        fail("statfs64-size");
    descriptor = call6(SYS_open, "/init", O_RDONLY, 0, 0, 0, 0);
    if (descriptor < 0) fail("open");
    memset(&descriptor_filesystem, 0, sizeof(descriptor_filesystem));
    descriptor_filesystem.guard = GUARD;
    if (call6(SYS_fstatfs, descriptor, &descriptor_filesystem.value,
              0, 0, 0, 0) != 0)
        fail("fstatfs");
    if (descriptor_filesystem.guard != GUARD)
        fail("fstatfs-layout");
    memset(&descriptor_filesystem64, 0, sizeof(descriptor_filesystem64));
    descriptor_filesystem64.guard = GUARD;
    if (call6(SYS_fstatfs64, descriptor,
              sizeof(descriptor_filesystem64.value),
              &descriptor_filesystem64.value, 0, 0, 0) != 0)
        fail("fstatfs64");
    if (descriptor_filesystem64.guard != GUARD)
        fail("fstatfs64-layout");
    if (call6(SYS_close, descriptor, 0, 0, 0, 0, 0) != 0)
        fail("close");
    if (call6(SYS_ustat, 0, &filesystem.value, 0, 0, 0, 0) >= 0)
        fail("ustat-invalid-device");
}

static void test_wait_accounting(void) {
    struct guarded_rusage usage;
    struct guarded_siginfo information;
    int32_t status = 0;
    long child = call6(SYS_fork, 0, 0, 0, 0, 0, 0);

    if (child < 0) fail("fork-wait4");
    if (!child) {
        call6(SYS_exit, 42, 0, 0, 0, 0, 0);
        __builtin_unreachable();
    }
    memset(&usage, 0, sizeof(usage));
    usage.guard = GUARD;
    if (call6(SYS_wait4, child, &status, 0, &usage.value, 0, 0) != child)
        fail("wait4");
    if (status != (42 << 8) || usage.guard != GUARD)
        fail("wait4-layout");

    child = call6(SYS_fork, 0, 0, 0, 0, 0, 0);
    if (child < 0) fail("fork-waitid");
    if (!child) {
        call6(SYS_exit, 7, 0, 0, 0, 0, 0);
        __builtin_unreachable();
    }
    memset(&usage, 0, sizeof(usage));
    memset(&information, 0, sizeof(information));
    usage.guard = GUARD;
    information.guard = GUARD;
    if (call6(SYS_waitid, P_PID, child, &information.value,
              WEXITED, &usage.value, 0) != 0)
        fail("waitid");
    if (usage.guard != GUARD || information.guard != GUARD)
        fail("waitid-layout");
}

__attribute__((noreturn)) void _start(void) {
    test_resource_limits();
    test_accounting();
    test_system_and_filesystem();
    test_wait_accounting();
    print_text("IA32_RESOURCE_UAPI_PROBE_PASS\n");
    call6(SYS_exit, 0, 0, 0, 0, 0, 0);
    __builtin_unreachable();
}
