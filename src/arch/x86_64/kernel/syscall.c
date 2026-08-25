/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS x86-64 hardware syscall entry setup.
 *
 * Linux x86-64 userspace issues the SYSCALL instruction.  The processor does
 * not switch stacks for SYSCALL, so each CPU keeps its current ring-0 stack in
 * GS-relative entry data.  User GS is held in IA32_KERNEL_GS_BASE while the
 * kernel is active and is exchanged by SWAPGS at every privilege transition.
 */

#include "arch/x86_64/syscall.h"
#include "arch/x86_64/linux_abi.h"

#include <stddef.h>

#include "kernel/linux_errno.h"
#include "stdio.h"
#include "sys/scheduler.h"
#include "sys/user_exec.h"

#define IA32_EFER_MSR           0xC0000080u
#define IA32_STAR_MSR           0xC0000081u
#define IA32_LSTAR_MSR          0xC0000082u
#define IA32_FMASK_MSR          0xC0000084u
#define IA32_FS_BASE_MSR        0xC0000100u
#define IA32_GS_BASE_MSR        0xC0000101u
#define IA32_KERNEL_GS_BASE_MSR 0xC0000102u

#define EFER_SCE (1ull << 0)

#define X86_RFLAGS_TF   (1ull << 8)
#define X86_RFLAGS_IF   (1ull << 9)
#define X86_RFLAGS_DF   (1ull << 10)
#define X86_RFLAGS_IOPL (3ull << 12)
#define X86_RFLAGS_NT   (1ull << 14)
#define X86_RFLAGS_AC   (1ull << 18)

extern void edgeos_x86_64_syscall_entry(void);

static edgeos_x86_64_syscall_cpu_t
    g_syscall_cpu[SCHED_MAX_CPUS] __attribute__((aligned(64)));
static volatile uint32_t g_syscall_identity_ready;

_Static_assert(offsetof(edgeos_x86_64_syscall_cpu_t, kernel_rsp) == 0,
               "syscall entry kernel_rsp offset");
_Static_assert(offsetof(edgeos_x86_64_syscall_cpu_t, user_rsp) == 8,
               "syscall entry user_rsp offset");
_Static_assert(offsetof(edgeos_x86_64_syscall_cpu_t, logical_id) == 48,
               "syscall entry logical_id offset");

int edge_x86_64_linux_stat_to_user(
    void *context, edge_linux_copy_to_user_fn copy_to_user,
    uint64_t user_destination, const kernel_file_metadata_t *metadata) {
    edge_x86_64_linux_stat_t result = {0};
    if (!copy_to_user || !user_destination || !metadata)
        return -EDGE_LINUX_EFAULT;
    if (metadata->size > INT64_MAX || metadata->blocks > INT64_MAX)
        return -EDGE_LINUX_EOVERFLOW;
    result.st_dev = metadata->device;
    result.st_ino = metadata->inode;
    result.st_nlink = metadata->links;
    result.st_mode = metadata->mode;
    result.st_uid = metadata->uid;
    result.st_gid = metadata->gid;
    result.st_rdev = metadata->rdev;
    result.st_size = (int64_t)metadata->size;
    result.st_blksize = metadata->block_size;
    result.st_blocks = (int64_t)metadata->blocks;
    result.st_atim.tv_sec = metadata->access_time.seconds;
    result.st_atim.tv_nsec = metadata->access_time.nanoseconds;
    result.st_mtim.tv_sec =
        metadata->modification_time.seconds;
    result.st_mtim.tv_nsec =
        metadata->modification_time.nanoseconds;
    result.st_ctim.tv_sec = metadata->change_time.seconds;
    result.st_ctim.tv_nsec = metadata->change_time.nanoseconds;
    return copy_to_user(context, user_destination, &result, sizeof(result)) < 0 ?
           -EDGE_LINUX_EFAULT : 0;
}

int edge_ia32_linux_stat64_to_user(
    void *context, edge_linux_copy_to_user_fn copy_to_user,
    uint64_t user_destination, const kernel_file_metadata_t *metadata) {
    edge_ia32_linux_stat64_t result = {0};

    if (!copy_to_user || !user_destination || !metadata)
        return -EDGE_LINUX_EFAULT;
    if (metadata->size > INT64_MAX || metadata->blocks > INT64_MAX ||
        metadata->access_time.seconds > UINT32_MAX ||
        metadata->modification_time.seconds > UINT32_MAX ||
        metadata->change_time.seconds > UINT32_MAX)
        return -EDGE_LINUX_EOVERFLOW;
    result.st_dev = metadata->device;
    result.legacy_ino = (uint32_t)metadata->inode;
    result.st_mode = metadata->mode;
    result.st_nlink = metadata->links;
    result.st_uid = metadata->uid;
    result.st_gid = metadata->gid;
    result.st_rdev = metadata->rdev;
    result.st_size = (int64_t)metadata->size;
    result.st_blksize = metadata->block_size;
    result.st_blocks = metadata->blocks;
    result.st_atime = (uint32_t)metadata->access_time.seconds;
    result.st_atime_nsec = metadata->access_time.nanoseconds;
    result.st_mtime = (uint32_t)metadata->modification_time.seconds;
    result.st_mtime_nsec = metadata->modification_time.nanoseconds;
    result.st_ctime = (uint32_t)metadata->change_time.seconds;
    result.st_ctime_nsec = metadata->change_time.nanoseconds;
    result.st_ino = metadata->inode;
    return copy_to_user(context, user_destination, &result, sizeof(result)) < 0 ?
        -EDGE_LINUX_EFAULT : 0;
}

static uint64_t x86_rdmsr(uint32_t msr) {
    uint32_t lo;
    uint32_t hi;

    __asm__ __volatile__("rdmsr" : "=a"(lo), "=d"(hi) : "c"(msr));
    return ((uint64_t)hi << 32) | lo;
}

static void x86_wrmsr(uint32_t msr, uint64_t value) {
    __asm__ __volatile__("wrmsr"
                         :
                         : "c"(msr), "a"((uint32_t)value),
                           "d"((uint32_t)(value >> 32))
                         : "memory");
}

static int x86_has_syscall(void) {
    uint32_t eax;
    uint32_t ebx;
    uint32_t ecx;
    uint32_t edx;

    eax = 0x80000000u;
    __asm__ __volatile__("cpuid"
                         : "+a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx));
    if (eax < 0x80000001u) return 0;

    eax = 0x80000001u;
    __asm__ __volatile__("cpuid"
                         : "+a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx));
    return (edx & (1u << 11)) != 0;
}

static uint32_t x86_entry_cpu_id(void) {
    uint32_t cpu = scheduler_cpu_id();

    return cpu < SCHED_MAX_CPUS ? cpu : 0;
}

void edgeos_x86_64_syscall_set_kernel_rsp(uint64_t rsp) {
    g_syscall_cpu[x86_entry_cpu_id()].kernel_rsp = rsp;
}

void edgeos_x86_64_set_fs_base(uint64_t base) {
    edgeos_x86_64_syscall_cpu_t *cpu =
        &g_syscall_cpu[x86_entry_cpu_id()];

    if (cpu->fs_base_valid && cpu->fs_base == base) return;
    x86_wrmsr(IA32_FS_BASE_MSR, base);
    cpu->fs_base = base;
    cpu->fs_base_valid = 1;
}

void edgeos_x86_64_set_user_gs_base(uint64_t base) {
    edgeos_x86_64_syscall_cpu_t *cpu =
        &g_syscall_cpu[x86_entry_cpu_id()];

    /*
     * Ring-0 GS addresses entry data.  SWAPGS will install this shadow value
     * as the user GS base immediately before IRETQ.
     */
    if (cpu->user_gs_base_valid && cpu->user_gs_base == base) return;
    x86_wrmsr(IA32_KERNEL_GS_BASE_MSR, base);
    cpu->user_gs_base = base;
    cpu->user_gs_base_valid = 1;
}

int edgeos_x86_64_syscall_identity_ready(void) {
    return __atomic_load_n(&g_syscall_identity_ready,
                           __ATOMIC_ACQUIRE) != 0u;
}

uint32_t edgeos_x86_64_syscall_cpu_id(void) {
    uint64_t logical_id;

    __asm__ __volatile__("movq %%gs:%c1, %0"
                         : "=r"(logical_id)
                         : "i"(offsetof(edgeos_x86_64_syscall_cpu_t,
                                        logical_id)));
    return logical_id < SCHED_MAX_CPUS ? (uint32_t)logical_id : 0u;
}

void edgeos_x86_64_syscall_init_cpu(uint32_t cpu) {
    uint64_t efer;
    uint64_t fmask;
    uint64_t star;

    if (cpu >= SCHED_MAX_CPUS) cpu = 0u;
    g_syscall_cpu[cpu].kernel_rsp = 0;
    g_syscall_cpu[cpu].user_rsp = 0;
    g_syscall_cpu[cpu].fs_base = 0;
    g_syscall_cpu[cpu].fs_base_valid = 0;
    g_syscall_cpu[cpu].user_gs_base = 0;
    g_syscall_cpu[cpu].user_gs_base_valid = 0;
    g_syscall_cpu[cpu].logical_id = cpu;

    /* Kernel GS is active until the first return to ring 3. */
    x86_wrmsr(IA32_GS_BASE_MSR,
              (uint64_t)(uintptr_t)&g_syscall_cpu[cpu]);
    x86_wrmsr(IA32_KERNEL_GS_BASE_MSR, 0);
    g_syscall_cpu[cpu].user_gs_base_valid = 1;
    if (cpu == 0u)
        __atomic_store_n(&g_syscall_identity_ready, 1u,
                         __ATOMIC_RELEASE);

    if (!x86_has_syscall()) {
        printf("[x86_64] CPU lacks SYSCALL/SYSRET; using #UD compatibility entry\n");
        return;
    }

    /*
     * SYSCALL loads CS=KERNEL_CS and SS=KERNEL_CS+8.  EdgeOS deliberately
     * returns through IRETQ, so STAR's SYSRET selector half is unused until
     * the GDT gains a SYSRET-compatible user descriptor ordering.
     */
    star = (uint64_t)KERNEL_CS << 32;
    fmask = X86_RFLAGS_TF | X86_RFLAGS_IF | X86_RFLAGS_DF |
            X86_RFLAGS_IOPL | X86_RFLAGS_NT | X86_RFLAGS_AC;
    x86_wrmsr(IA32_STAR_MSR, star);
    x86_wrmsr(IA32_LSTAR_MSR,
              (uint64_t)(uintptr_t)edgeos_x86_64_syscall_entry);
    x86_wrmsr(IA32_FMASK_MSR, fmask);

    efer = x86_rdmsr(IA32_EFER_MSR);
    x86_wrmsr(IA32_EFER_MSR, efer | EFER_SCE);
    printf("[x86_64] hardware SYSCALL entry enabled\n");
}

void edgeos_x86_64_syscall_init(void) {
    edgeos_x86_64_syscall_init_cpu(x86_entry_cpu_id());
}
