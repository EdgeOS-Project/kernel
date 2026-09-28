/* SPDX-License-Identifier: MPL-2.0 */
/* Freestanding Linux i386 NUMA, AIO, and quota compatibility ABI probe. */

#include <stdint.h>

#define SYS_exit 1
#define SYS_write 4
#define SYS_quotactl 131
#define SYS_io_setup 245
#define SYS_io_destroy 246
#define SYS_mbind 274
#define SYS_get_mempolicy 275
#define SYS_set_mempolicy 276
#define SYS_migrate_pages 294
#define SYS_arch_prctl 384
#define SYS_io_pgetevents 385
#define SYS_io_pgetevents_time64 416

#define ENOSYS 38
#define EINVAL 22
#define ENODEV 19
#define Q_SYNC UINT32_C(0x800001)
#define USRQUOTA 0
#define QCMD(command, type) (((command) << 8) | (type))
#define ARCH_GET_FS 0x1003
#define ARCH_GET_CPUID 0x1011
#define ARCH_SET_CPUID 0x1012
#define ARCH_GET_XCOMP_SUPP 0x1021
#define ARCH_GET_XCOMP_PERM 0x1022
#define ARCH_REQ_XCOMP_PERM 0x1023

struct timespec32 {
    int32_t seconds;
    int32_t nanoseconds;
};

struct timespec64 {
    int64_t seconds;
    int64_t nanoseconds;
};

struct aio_sigset32 {
    uint32_t mask;
    uint32_t size;
};

struct mask_result {
    uint32_t mask;
    uint32_t sentinel;
};

static int32_t policy_mode;
static struct mask_result policy_mask;
static uint32_t source_nodes = 1;
static uint32_t target_nodes = 1;
static uint32_t aio_context;
static uint64_t signal_mask;
static uint64_t xcomp_mask;
static struct aio_sigset32 aio_sigset;
static struct timespec32 timeout32;
static struct timespec64 timeout64;

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

static void print_hex(uint32_t value) {
    static const char digits[] = "0123456789abcdef";
    char output[10];
    output[0] = '0';
    output[1] = 'x';
    for (uint32_t index = 0; index < 8; ++index)
        output[index + 2] = digits[(value >> ((7u - index) * 4u)) & 15u];
    call6(SYS_write, 1, output, sizeof(output), 0, 0, 0);
}

static void record(const char *name, long result) {
    print_text(name);
    print_text("=");
    print_hex((uint32_t)result);
    print_text("\n");
    if (result == -ENOSYS) {
        print_text("IA32_NUMA_AIO_QUOTA_UAPI_PROBE_FAIL\n");
        call6(SYS_exit, 1, 0, 0, 0, 0, 0);
    }
}

static void record_mask(const char *name, long result, uint64_t value) {
    record(name, result);
    print_text(name);
    print_text("_lo=");
    print_hex((uint32_t)value);
    print_text("\n");
    print_text(name);
    print_text("_hi=");
    print_hex((uint32_t)(value >> 32));
    print_text("\n");
}

static void require_result(long result, long expected) {
    if (result != expected) {
        print_text("IA32_NUMA_AIO_QUOTA_UAPI_PROBE_FAIL result\n");
        call6(SYS_exit, 1, 0, 0, 0, 0, 0);
    }
}

__attribute__((noreturn)) void _start(void) {
    long result;

    policy_mask.mask = UINT32_C(0xaaaaaaaa);
    policy_mask.sentinel = UINT32_C(0x5a17c0de);
    result = call6(SYS_get_mempolicy, &policy_mode, &policy_mask.mask,
                   1, 0, 0, 0);
    record("get_mempolicy", result);
    require_result(result, 0);
    if (policy_mask.sentinel != UINT32_C(0x5a17c0de)) {
        print_text("IA32_NUMA_AIO_QUOTA_UAPI_PROBE_FAIL mask-width\n");
        call6(SYS_exit, 1, 0, 0, 0, 0, 0);
    }
    result = call6(SYS_set_mempolicy, 0, 0, 0, 0, 0, 0);
    record("set_mempolicy", result);
    require_result(result, 0);
    result = call6(SYS_mbind, 0, 0, 0, 0, 0, 0);
    record("mbind", result);
    require_result(result, 0);
    result = call6(SYS_migrate_pages, 0, 1, &source_nodes,
                   &target_nodes, 0, 0);
    record("migrate_pages", result);
    require_result(result, -EINVAL);
    result = call6(SYS_quotactl, QCMD(Q_SYNC, USRQUOTA), 0, 0, 0, 0, 0);
    record("quotactl", result);
    require_result(result, 0);
    result = call6(SYS_arch_prctl, ARCH_GET_CPUID, 0, 0, 0, 0, 0);
    record("arch_prctl_get_cpuid", result);
    require_result(result, 1);
    result = call6(SYS_arch_prctl, ARCH_GET_FS, &policy_mask.mask,
                   0, 0, 0, 0);
    record("arch_prctl_get_fs", result);
    require_result(result, -EINVAL);
    result = call6(SYS_arch_prctl, ARCH_SET_CPUID, 1, 0, 0, 0, 0);
    record("arch_prctl_set_cpuid_enabled", result);
    if (result != 0 && result != -ENODEV)
        require_result(result, -ENODEV);
    xcomp_mask = 0;
    result = call6(SYS_arch_prctl, ARCH_GET_XCOMP_SUPP, &xcomp_mask,
                   0, 0, 0, 0);
    record_mask("arch_prctl_get_xcomp_supp", result, xcomp_mask);
    require_result(result, 0);
    if ((xcomp_mask & UINT64_C(3)) != UINT64_C(3))
        require_result(-1, 0);
    xcomp_mask = 0;
    result = call6(SYS_arch_prctl, ARCH_GET_XCOMP_PERM, &xcomp_mask,
                   0, 0, 0, 0);
    record_mask("arch_prctl_get_xcomp_perm", result, xcomp_mask);
    require_result(result, 0);
    if ((xcomp_mask & UINT64_C(3)) != UINT64_C(3))
        require_result(-1, 0);
    result = call6(SYS_arch_prctl, ARCH_REQ_XCOMP_PERM, 63, 0, 0, 0, 0);
    record("arch_prctl_req_xcomp_perm_invalid", result);
    require_result(result, -EINVAL);

    result = call6(SYS_io_setup, 1, &aio_context, 0, 0, 0, 0);
    record("io_setup", result);
    require_result(result, 0);
    if (result == 0) {
        aio_sigset.mask = (uint32_t)(uintptr_t)&signal_mask;
        aio_sigset.size = sizeof(signal_mask);
        result = call6(SYS_io_pgetevents, aio_context, 0, 0, 0,
                       &timeout32, &aio_sigset);
        record("io_pgetevents_time32", result);
        require_result(result, 0);
        result = call6(SYS_io_pgetevents_time64, aio_context, 0, 0, 0,
                       &timeout64, &aio_sigset);
        record("io_pgetevents_time64", result);
        require_result(result, 0);
        result = call6(SYS_io_destroy, aio_context, 0, 0, 0, 0, 0);
        record("io_destroy", result);
        require_result(result, 0);
    }
    print_text("IA32_NUMA_AIO_QUOTA_UAPI_PROBE_PASS\n");
    call6(SYS_exit, 0, 0, 0, 0, 0, 0);
    __builtin_unreachable();
}
