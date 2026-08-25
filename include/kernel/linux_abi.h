/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS Linux userspace ABI layouts.
 * Copyright (c) EdgeOS Contributors.
 *
 * These structures are shared by every 64-bit architecture.  Architecture
 * code may provide a different syscall number or trap-frame convention, but
 * it must not grow a private copy of an architecture-independent Linux UAPI
 * layout.
 */

#ifndef EDGEOS_KERNEL_LINUX_ABI_H
#define EDGEOS_KERNEL_LINUX_ABI_H

#include <stddef.h>
#include <stdint.h>

#include "kernel/linux_time.h"
#include "kernel/scheduler_policy.h"

#define EDGE_LINUX_XATTR_NAME_MAX 255u
#define EDGE_LINUX_XATTR_VALUE_MAX 65536u

#define EDGE_LINUX_SS_ONSTACK 1u
#define EDGE_LINUX_SS_DISABLE 2u
#define EDGE_LINUX_SS_AUTODISARM 0x80000000u

#define EDGE_LINUX_AT_FDCWD (-100)
#define EDGE_LINUX_AT_EACCESS 0x0200u
#define EDGE_LINUX_AT_SYMLINK_NOFOLLOW 0x0100u
#define EDGE_LINUX_AT_REMOVEDIR 0x0200u
#define EDGE_LINUX_AT_SYMLINK_FOLLOW 0x0400u
#define EDGE_LINUX_AT_NO_AUTOMOUNT 0x0800u
#define EDGE_LINUX_AT_EMPTY_PATH 0x1000u
#define EDGE_LINUX_AT_STATX_FORCE_SYNC 0x2000u
#define EDGE_LINUX_AT_STATX_DONT_SYNC 0x4000u
#define EDGE_LINUX_AT_STATX_SYNC_TYPE 0x6000u
#define EDGE_LINUX_AT_RECURSIVE 0x8000u
#define EDGE_LINUX_AT_HANDLE_MNT_ID_UNIQUE 0x0001u
#define EDGE_LINUX_AT_HANDLE_CONNECTABLE 0x0002u
#define EDGE_LINUX_AT_HANDLE_FID 0x0200u

#define EDGE_LINUX_UTIME_NOW  1073741823LL
#define EDGE_LINUX_UTIME_OMIT 1073741822LL

#define EDGE_LINUX_RENAME_NOREPLACE 0x01u
#define EDGE_LINUX_RENAME_EXCHANGE 0x02u
#define EDGE_LINUX_RENAME_WHITEOUT 0x04u

#define EDGE_LINUX_STATX_RESERVED 0x80000000u
#define EDGE_LINUX_STATX_ATTR_IMMUTABLE 0x00000010u
#define EDGE_LINUX_STATX_ATTR_APPEND    0x00000020u
#define EDGE_LINUX_STATX_ATTR_NODUMP    0x00000040u
#define EDGE_LINUX_STATX_ATTR_MOUNT_ROOT 0x00002000u

struct edge_linux_mount_attr {
    uint64_t attr_set;
    uint64_t attr_clear;
    uint64_t propagation;
    uint64_t user_namespace_fd;
};

_Static_assert(sizeof(struct edge_linux_mount_attr) == 32,
               "Linux mount_attr size mismatch");

/* Linux clone flags shared by every supported 64-bit architecture. */
#define EDGE_LINUX_CLONE_NEWTIME         0x00000080ULL
#define EDGE_LINUX_CLONE_VM              0x00000100ULL
#define EDGE_LINUX_CLONE_FS              0x00000200ULL
#define EDGE_LINUX_CLONE_FILES           0x00000400ULL
#define EDGE_LINUX_CLONE_SIGHAND         0x00000800ULL
#define EDGE_LINUX_CLONE_PIDFD           0x00001000ULL
#define EDGE_LINUX_CLONE_PTRACE          0x00002000ULL
#define EDGE_LINUX_CLONE_VFORK           0x00004000ULL
#define EDGE_LINUX_CLONE_PARENT          0x00008000ULL
#define EDGE_LINUX_CLONE_THREAD          0x00010000ULL
#define EDGE_LINUX_CLONE_NEWNS           0x00020000ULL
#define EDGE_LINUX_CLONE_SYSVSEM         0x00040000ULL
#define EDGE_LINUX_CLONE_SETTLS          0x00080000ULL
#define EDGE_LINUX_CLONE_PARENT_SETTID   0x00100000ULL
#define EDGE_LINUX_CLONE_CHILD_CLEARTID  0x00200000ULL
#define EDGE_LINUX_CLONE_DETACHED        0x00400000ULL
#define EDGE_LINUX_CLONE_UNTRACED        0x00800000ULL
#define EDGE_LINUX_CLONE_CHILD_SETTID    0x01000000ULL
#define EDGE_LINUX_CLONE_NEWCGROUP       0x02000000ULL
#define EDGE_LINUX_CLONE_NEWUTS          0x04000000ULL
#define EDGE_LINUX_CLONE_NEWIPC          0x08000000ULL
#define EDGE_LINUX_CLONE_NEWUSER         0x10000000ULL
#define EDGE_LINUX_CLONE_NEWPID          0x20000000ULL
#define EDGE_LINUX_CLONE_NEWNET          0x40000000ULL
#define EDGE_LINUX_CLONE_IO              0x80000000ULL
#define EDGE_LINUX_CLONE_CLEAR_SIGHAND   0x100000000ULL
#define EDGE_LINUX_CLONE_INTO_CGROUP     0x200000000ULL

#define EDGE_LINUX_CLONE_NAMESPACE_FLAGS \
    (EDGE_LINUX_CLONE_NEWTIME | EDGE_LINUX_CLONE_NEWNS | \
     EDGE_LINUX_CLONE_NEWCGROUP | EDGE_LINUX_CLONE_NEWUTS | \
     EDGE_LINUX_CLONE_NEWIPC | EDGE_LINUX_CLONE_NEWUSER | \
     EDGE_LINUX_CLONE_NEWPID | EDGE_LINUX_CLONE_NEWNET)

#define EDGE_LINUX_LISTNS_CURRENT_USER UINT64_MAX
#define EDGE_LINUX_NS_ID_REQ_SIZE_VER0 32u

struct edge_linux_ns_id_req {
    uint32_t size;
    uint32_t spare;
    uint64_t ns_id;
    uint32_t ns_type;
    uint32_t spare2;
    uint64_t user_ns_id;
};

_Static_assert(sizeof(struct edge_linux_ns_id_req) ==
                   EDGE_LINUX_NS_ID_REQ_SIZE_VER0,
               "Linux ns_id_req ABI size mismatch");

#define EDGE_LINUX_CLONE_SUPPORTED_FLAGS \
    (EDGE_LINUX_CLONE_VM | EDGE_LINUX_CLONE_FS | \
     EDGE_LINUX_CLONE_FILES | EDGE_LINUX_CLONE_SIGHAND | \
     EDGE_LINUX_CLONE_PIDFD | EDGE_LINUX_CLONE_PTRACE | \
     EDGE_LINUX_CLONE_VFORK | EDGE_LINUX_CLONE_PARENT | \
     EDGE_LINUX_CLONE_THREAD | EDGE_LINUX_CLONE_SYSVSEM | \
     EDGE_LINUX_CLONE_SETTLS | EDGE_LINUX_CLONE_PARENT_SETTID | \
     EDGE_LINUX_CLONE_CHILD_CLEARTID | EDGE_LINUX_CLONE_DETACHED | \
     EDGE_LINUX_CLONE_UNTRACED | EDGE_LINUX_CLONE_CHILD_SETTID | \
     EDGE_LINUX_CLONE_IO | EDGE_LINUX_CLONE_CLEAR_SIGHAND | \
     EDGE_LINUX_CLONE_INTO_CGROUP | EDGE_LINUX_CLONE_NAMESPACE_FLAGS)

/* Architecture-independent Linux futex UAPI values. */
#define EDGE_LINUX_FUTEX_WAIT 0u
#define EDGE_LINUX_FUTEX_WAKE 1u
#define EDGE_LINUX_FUTEX_REQUEUE 3u
#define EDGE_LINUX_FUTEX_CMP_REQUEUE 4u
#define EDGE_LINUX_FUTEX_WAKE_OP 5u
#define EDGE_LINUX_FUTEX_LOCK_PI 6u
#define EDGE_LINUX_FUTEX_UNLOCK_PI 7u
#define EDGE_LINUX_FUTEX_TRYLOCK_PI 8u
#define EDGE_LINUX_FUTEX_WAIT_BITSET 9u
#define EDGE_LINUX_FUTEX_WAKE_BITSET 10u
#define EDGE_LINUX_FUTEX_WAIT_REQUEUE_PI 11u
#define EDGE_LINUX_FUTEX_CMP_REQUEUE_PI 12u
#define EDGE_LINUX_FUTEX_LOCK_PI2 13u
#define EDGE_LINUX_FUTEX_PRIVATE_FLAG 128u
#define EDGE_LINUX_FUTEX_CLOCK_REALTIME 256u
#define EDGE_LINUX_FUTEX_ROBUST_UNLOCK 512u
#define EDGE_LINUX_FUTEX_ROBUST_LIST32 1024u
#define EDGE_LINUX_FUTEX_CMD_MASK \
    (~(EDGE_LINUX_FUTEX_PRIVATE_FLAG | EDGE_LINUX_FUTEX_CLOCK_REALTIME | \
       EDGE_LINUX_FUTEX_ROBUST_UNLOCK | EDGE_LINUX_FUTEX_ROBUST_LIST32))
#define EDGE_LINUX_FUTEX_WAITERS 0x80000000u
#define EDGE_LINUX_FUTEX_OWNER_DIED 0x40000000u
#define EDGE_LINUX_FUTEX_TID_MASK 0x3fffffffu
#define EDGE_LINUX_FUTEX2_SIZE_MASK 0x03u
#define EDGE_LINUX_FUTEX_32 0x02u
#define EDGE_LINUX_FUTEX_BITSET_MATCH_ANY UINT32_MAX
#define EDGE_LINUX_FUTEX_WAITV_MAX 128u

/* Linux time discipline UAPI. */
#define EDGE_LINUX_ADJ_OFFSET 0x0001u
#define EDGE_LINUX_ADJ_FREQUENCY 0x0002u
#define EDGE_LINUX_ADJ_MAXERROR 0x0004u
#define EDGE_LINUX_ADJ_ESTERROR 0x0008u
#define EDGE_LINUX_ADJ_STATUS 0x0010u
#define EDGE_LINUX_ADJ_TIMECONST 0x0020u
#define EDGE_LINUX_ADJ_TAI 0x0080u
#define EDGE_LINUX_ADJ_SETOFFSET 0x0100u
#define EDGE_LINUX_ADJ_MICRO 0x1000u
#define EDGE_LINUX_ADJ_NANO 0x2000u
#define EDGE_LINUX_ADJ_TICK 0x4000u
#define EDGE_LINUX_ADJ_ADJTIME 0x8000u
#define EDGE_LINUX_ADJ_OFFSET_READONLY 0x2000u
#define EDGE_LINUX_ADJ_OFFSET_SINGLESHOT 0x8001u
#define EDGE_LINUX_ADJ_OFFSET_SS_READ 0xa001u

#define EDGE_LINUX_STA_PLL 0x0001u
#define EDGE_LINUX_STA_PPSFREQ 0x0002u
#define EDGE_LINUX_STA_PPSTIME 0x0004u
#define EDGE_LINUX_STA_FLL 0x0008u
#define EDGE_LINUX_STA_INS 0x0010u
#define EDGE_LINUX_STA_DEL 0x0020u
#define EDGE_LINUX_STA_UNSYNC 0x0040u
#define EDGE_LINUX_STA_FREQHOLD 0x0080u
#define EDGE_LINUX_STA_PPSSIGNAL 0x0100u
#define EDGE_LINUX_STA_PPSJITTER 0x0200u
#define EDGE_LINUX_STA_PPSWANDER 0x0400u
#define EDGE_LINUX_STA_PPSERROR 0x0800u
#define EDGE_LINUX_STA_CLOCKERR 0x1000u
#define EDGE_LINUX_STA_NANO 0x2000u
#define EDGE_LINUX_STA_MODE 0x4000u
#define EDGE_LINUX_STA_CLK 0x8000u
#define EDGE_LINUX_STA_READONLY \
    (EDGE_LINUX_STA_PPSSIGNAL | EDGE_LINUX_STA_PPSJITTER | \
     EDGE_LINUX_STA_PPSWANDER | EDGE_LINUX_STA_PPSERROR | \
     EDGE_LINUX_STA_CLOCKERR | EDGE_LINUX_STA_NANO | \
     EDGE_LINUX_STA_MODE | EDGE_LINUX_STA_CLK)

#define EDGE_LINUX_TIME_OK 0
#define EDGE_LINUX_TIME_INS 1
#define EDGE_LINUX_TIME_DEL 2
#define EDGE_LINUX_TIME_ERROR 5

typedef struct edge_linux_timex_timeval {
    int64_t tv_sec;
    int64_t tv_usec;
} edge_linux_timex_timeval_t;

typedef struct edge_linux_timex {
    uint32_t modes;
    uint32_t padding0;
    int64_t offset;
    int64_t frequency;
    int64_t maximum_error;
    int64_t estimated_error;
    int32_t status;
    uint32_t padding1;
    int64_t constant;
    int64_t precision;
    int64_t tolerance;
    edge_linux_timex_timeval_t time;
    int64_t tick;
    int64_t pps_frequency;
    int64_t jitter;
    int32_t shift;
    uint32_t padding2;
    int64_t stability;
    int64_t jitter_count;
    int64_t calibration_count;
    int64_t error_count;
    int64_t stability_count;
    int32_t tai;
    uint32_t padding3[11];
} edge_linux_timex_t;

typedef struct edge_linux_timex32 {
    uint32_t modes;
    int32_t offset;
    int32_t frequency;
    int32_t maximum_error;
    int32_t estimated_error;
    int32_t status;
    int32_t constant;
    int32_t precision;
    int32_t tolerance;
    int32_t time_seconds;
    int32_t time_microseconds;
    int32_t tick;
    int32_t pps_frequency;
    int32_t jitter;
    int32_t shift;
    int32_t stability;
    int32_t jitter_count;
    int32_t calibration_count;
    int32_t error_count;
    int32_t stability_count;
    int32_t tai;
    int32_t padding[11];
} edge_linux_timex32_t;

_Static_assert(sizeof(edge_linux_timex_t) == 208u,
               "Linux timex ABI size mismatch");
_Static_assert(sizeof(edge_linux_timex32_t) == 128u,
               "Linux i386 timex ABI size mismatch");

#define EDGE_LINUX_EXT_SUPER_MAGIC 0x0000ef53u
#define EDGE_LINUX_PROC_SUPER_MAGIC 0x00009fa0u
#define EDGE_LINUX_SYSFS_MAGIC 0x62656572u
#define EDGE_LINUX_TMPFS_MAGIC 0x01021994u
#define EDGE_LINUX_CGROUP2_SUPER_MAGIC 0x63677270u
#define EDGE_LINUX_MSDOS_SUPER_MAGIC 0x00004d44u
#define EDGE_LINUX_ISOFS_SUPER_MAGIC 0x00009660u
#define EDGE_LINUX_NTFS_SB_MAGIC 0x5346544eu
#define EDGE_LINUX_EXFAT_SUPER_MAGIC 0x2011bab0u
#define EDGE_LINUX_UDF_SUPER_MAGIC 0x15013346u
#define EDGE_LINUX_OVERLAYFS_SUPER_MAGIC 0x794c7630u
#define EDGE_LINUX_DEVPTS_SUPER_MAGIC 0x00001cd1u
#define EDGE_LINUX_PIPEFS_MAGIC 0x50495045u
#define EDGE_LINUX_SOCKFS_MAGIC 0x534f434bu
#define EDGE_LINUX_ANON_INODE_FS_MAGIC 0x09041934u
#define EDGE_LINUX_NSFS_MAGIC 0x6e736673u
#define EDGE_LINUX_BPF_FS_MAGIC 0xcafe4a11u

#define EDGE_LINUX_ST_RDONLY 0x0001u
#define EDGE_LINUX_ST_NOSUID 0x0002u
#define EDGE_LINUX_ST_NODEV 0x0004u
#define EDGE_LINUX_ST_NOEXEC 0x0008u
#define EDGE_LINUX_ST_SYNCHRONOUS 0x0010u
#define EDGE_LINUX_ST_VALID 0x0020u
#define EDGE_LINUX_ST_NOATIME 0x0400u
#define EDGE_LINUX_ST_NODIRATIME 0x0800u
#define EDGE_LINUX_ST_RELATIME 0x1000u
#define EDGE_LINUX_ST_NOSYMFOLLOW 0x2000u

typedef int (*edge_linux_copy_from_user_fn)(void *context,
                                            void *kernel_destination,
                                            uint64_t user_source,
                                            uint64_t size);
typedef int (*edge_linux_copy_to_user_fn)(void *context,
                                          uint64_t user_destination,
                                          const void *kernel_source,
                                          uint64_t size);

/* Sixth pselect6 argument used by every 64-bit Linux architecture. */
struct edge_linux_pselect_sigset {
    uint64_t sigmask_u;
    uint64_t sigsetsize;
};

_Static_assert(sizeof(struct edge_linux_pselect_sigset) == 16,
               "Linux pselect signal argument size mismatch");
_Static_assert(offsetof(struct edge_linux_pselect_sigset, sigsetsize) == 8,
               "Linux pselect signal size offset mismatch");

/*
 * Linux siginfo_t has a common 16-byte header and a 112-byte tagged payload
 * on both supported 64-bit ABIs.  Queueing syscalls must preserve the payload
 * byte-for-byte while the kernel replaces si_signo with the syscall argument.
 */
struct edge_linux_siginfo {
    int32_t signal_number;
    int32_t error;
    int32_t code;
    uint32_t padding;
    uint8_t payload[112];
};

/* waitid() child-state payload shared by both supported 64-bit ABIs. */
struct edge_linux_siginfo_child {
    int32_t signal_number;
    int32_t error;
    int32_t code;
    uint32_t padding;
    int32_t pid;
    uint32_t uid;
    int32_t status;
    uint32_t child_padding;
    int64_t user_time;
    int64_t system_time;
    uint8_t reserved[80];
};

/* x32 keeps siginfo_t at 128 bytes but starts its tagged union at byte 12. */
struct edge_linux_compat_siginfo {
    int32_t signal_number;
    int32_t error;
    int32_t code;
    uint8_t payload[116];
} __attribute__((aligned(8)));

void edge_linux_compat_siginfo_to_native(
    const struct edge_linux_compat_siginfo *compat,
    struct edge_linux_siginfo *native);
void edge_linux_native_siginfo_to_compat(
    const struct edge_linux_siginfo *native,
    struct edge_linux_compat_siginfo *compat);

#define EDGE_LINUX_WAIT_P_ALL 0u
#define EDGE_LINUX_WAIT_P_PID 1u
#define EDGE_LINUX_WAIT_P_PGID 2u
#define EDGE_LINUX_WAIT_P_PIDFD 3u

#define EDGE_LINUX_WNOHANG 0x00000001u
#define EDGE_LINUX_WUNTRACED 0x00000002u
#define EDGE_LINUX_WEXITED 0x00000004u
#define EDGE_LINUX_WCONTINUED 0x00000008u
#define EDGE_LINUX_WNOWAIT 0x01000000u
#define EDGE_LINUX___WNOTHREAD 0x20000000u
#define EDGE_LINUX___WALL 0x40000000u
#define EDGE_LINUX___WCLONE 0x80000000u

#define EDGE_LINUX_CLD_EXITED 1
#define EDGE_LINUX_CLD_KILLED 2
#define EDGE_LINUX_CLD_DUMPED 3
#define EDGE_LINUX_CLD_TRAPPED 4
#define EDGE_LINUX_CLD_STOPPED 5
#define EDGE_LINUX_CLD_CONTINUED 6

/* stack_t has this layout on both supported 64-bit Linux ABIs. */
struct edge_linux_stack64 {
    uint64_t sp;
    int32_t flags;
    uint32_t padding;
    uint64_t size;
};

struct edge_linux_stack32 {
    uint32_t sp;
    int32_t flags;
    uint32_t size;
};

struct edge_linux_compat_sigaction {
    uint32_t handler;
    uint32_t flags;
    uint32_t restorer;
    uint32_t mask[2];
};

_Static_assert(sizeof(struct edge_linux_siginfo) == 128,
               "Linux siginfo size mismatch");
_Static_assert(sizeof(struct edge_linux_siginfo_child) == 128,
               "Linux child siginfo size mismatch");
_Static_assert(offsetof(struct edge_linux_siginfo_child, pid) == 16,
               "Linux child siginfo PID offset mismatch");
_Static_assert(offsetof(struct edge_linux_siginfo_child, status) == 24,
               "Linux child siginfo status offset mismatch");
_Static_assert(offsetof(struct edge_linux_siginfo_child, user_time) == 32,
               "Linux child siginfo user-time offset mismatch");
_Static_assert(offsetof(struct edge_linux_siginfo, code) == 8,
               "Linux siginfo code offset mismatch");
_Static_assert(offsetof(struct edge_linux_siginfo, payload) == 16,
               "Linux siginfo payload offset mismatch");
_Static_assert(sizeof(struct edge_linux_compat_siginfo) == 128,
               "Linux x32 siginfo size mismatch");
_Static_assert(offsetof(struct edge_linux_compat_siginfo, payload) == 12,
               "Linux x32 siginfo payload offset mismatch");
_Static_assert(sizeof(struct edge_linux_stack64) == 24,
               "Linux stack_t size mismatch");
_Static_assert(offsetof(struct edge_linux_stack64, flags) == 8,
               "Linux stack_t flags offset mismatch");
_Static_assert(offsetof(struct edge_linux_stack64, size) == 16,
               "Linux stack_t size offset mismatch");
_Static_assert(sizeof(struct edge_linux_stack32) == 12,
               "Linux compat stack_t size mismatch");
_Static_assert(offsetof(struct edge_linux_stack32, flags) == 4,
               "Linux compat stack_t flags offset mismatch");
_Static_assert(offsetof(struct edge_linux_stack32, size) == 8,
               "Linux compat stack_t size offset mismatch");
_Static_assert(sizeof(struct edge_linux_compat_sigaction) == 20,
               "Linux compat rt_sigaction size mismatch");
_Static_assert(offsetof(struct edge_linux_compat_sigaction, mask) == 12,
               "Linux compat rt_sigaction mask offset mismatch");

/* Linux signalfd_siginfo is identical on all 64-bit Linux architectures. */
struct edge_linux_signalfd_siginfo {
    uint32_t ssi_signo;
    int32_t ssi_errno;
    int32_t ssi_code;
    uint32_t ssi_pid;
    uint32_t ssi_uid;
    int32_t ssi_fd;
    uint32_t ssi_tid;
    uint32_t ssi_band;
    uint32_t ssi_overrun;
    uint32_t ssi_trapno;
    int32_t ssi_status;
    int32_t ssi_int;
    uint64_t ssi_ptr;
    uint64_t ssi_utime;
    uint64_t ssi_stime;
    uint64_t ssi_addr;
    uint16_t ssi_addr_lsb;
    uint16_t padding0;
    int32_t ssi_syscall;
    uint64_t ssi_call_addr;
    uint32_t ssi_arch;
    uint8_t padding1[28];
};

_Static_assert(sizeof(struct edge_linux_signalfd_siginfo) == 128,
               "Linux signalfd_siginfo size mismatch");
_Static_assert(offsetof(struct edge_linux_signalfd_siginfo, ssi_pid) == 12,
               "Linux signalfd_siginfo PID offset mismatch");
_Static_assert(offsetof(struct edge_linux_signalfd_siginfo, ssi_ptr) == 48,
               "Linux signalfd_siginfo value offset mismatch");
_Static_assert(offsetof(struct edge_linux_signalfd_siginfo, ssi_syscall) == 84,
               "Linux signalfd_siginfo syscall offset mismatch");
_Static_assert(offsetof(struct edge_linux_signalfd_siginfo, ssi_call_addr) == 88,
               "Linux signalfd_siginfo call address offset mismatch");

/* seccomp user-notification discovery uses common 64-bit UAPI layouts. */
struct edge_linux_seccomp_data {
    int32_t nr;
    uint32_t arch;
    uint64_t instruction_pointer;
    uint64_t arguments[6];
};

struct edge_linux_seccomp_notif {
    uint64_t id;
    uint32_t pid;
    uint32_t flags;
    struct edge_linux_seccomp_data data;
};

struct edge_linux_seccomp_notif_resp {
    uint64_t id;
    int64_t value;
    int32_t error;
    uint32_t flags;
};

struct edge_linux_seccomp_notif_addfd {
    uint64_t id;
    uint32_t flags;
    uint32_t source_descriptor;
    uint32_t new_descriptor;
    uint32_t new_descriptor_flags;
};

struct edge_linux_seccomp_notif_sizes {
    uint16_t seccomp_notif;
    uint16_t seccomp_notif_resp;
    uint16_t seccomp_data;
};

_Static_assert(sizeof(struct edge_linux_seccomp_data) == 64,
               "Linux seccomp_data size mismatch");
_Static_assert(offsetof(struct edge_linux_seccomp_data, arguments) == 16,
               "Linux seccomp_data argument offset mismatch");
_Static_assert(sizeof(struct edge_linux_seccomp_notif) == 80,
               "Linux seccomp_notif size mismatch");
_Static_assert(offsetof(struct edge_linux_seccomp_notif, data) == 16,
               "Linux seccomp_notif data offset mismatch");
_Static_assert(sizeof(struct edge_linux_seccomp_notif_resp) == 24,
               "Linux seccomp_notif_resp size mismatch");
_Static_assert(sizeof(struct edge_linux_seccomp_notif_addfd) == 24,
               "Linux seccomp_notif_addfd size mismatch");
_Static_assert(sizeof(struct edge_linux_seccomp_notif_sizes) == 6,
               "Linux seccomp_notif_sizes size mismatch");

/* The 64-bit Linux struct flock layout is shared by x86_64 and AArch64. */
struct edge_linux_flock64 {
    int16_t l_type;
    int16_t l_whence;
    int32_t padding0;
    int64_t l_start;
    int64_t l_len;
    int32_t l_pid;
    int32_t padding1;
};

_Static_assert(sizeof(struct edge_linux_flock64) == 32,
               "Linux flock size mismatch");
_Static_assert(offsetof(struct edge_linux_flock64, l_start) == 8,
               "Linux flock start offset mismatch");
_Static_assert(offsetof(struct edge_linux_flock64, l_len) == 16,
               "Linux flock length offset mismatch");
_Static_assert(offsetof(struct edge_linux_flock64, l_pid) == 24,
               "Linux flock pid offset mismatch");

/* SysV IPC metadata is shared by the supported 64-bit Linux ABIs. */
struct edge_linux_ipc_perm64 {
    int32_t key;
    uint32_t uid;
    uint32_t gid;
    uint32_t cuid;
    uint32_t cgid;
    uint32_t mode;
    int32_t sequence;
    int64_t reserved1;
    int64_t reserved2;
};

struct edge_linux_shmid_ds64 {
    struct edge_linux_ipc_perm64 shm_perm;
    uint64_t shm_segsz;
    int64_t shm_atime;
    int64_t shm_dtime;
    int64_t shm_ctime;
    int32_t shm_cpid;
    int32_t shm_lpid;
    uint64_t shm_nattch;
    uint64_t reserved1;
    uint64_t reserved2;
};

struct edge_linux_sembuf {
    uint16_t sem_num;
    int16_t sem_op;
    int16_t sem_flg;
};

struct edge_linux_semid_ds_x86_64 {
    struct edge_linux_ipc_perm64 sem_perm;
    int64_t sem_otime;
    uint64_t unused1;
    int64_t sem_ctime;
    uint64_t unused2;
    uint64_t sem_nsems;
    uint64_t unused3;
    uint64_t unused4;
};

struct edge_linux_semid_ds_aarch64 {
    struct edge_linux_ipc_perm64 sem_perm;
    int64_t sem_otime;
    int64_t sem_ctime;
    uint64_t sem_nsems;
    uint64_t unused3;
    uint64_t unused4;
};

struct edge_linux_seminfo {
    int32_t semmap;
    int32_t semmni;
    int32_t semmns;
    int32_t semmnu;
    int32_t semmsl;
    int32_t semopm;
    int32_t semume;
    int32_t semusz;
    int32_t semvmx;
    int32_t semaem;
};

struct edge_linux_msqid_ds64 {
    struct edge_linux_ipc_perm64 msg_perm;
    int64_t msg_stime;
    int64_t msg_rtime;
    int64_t msg_ctime;
    uint64_t msg_cbytes;
    uint64_t msg_qnum;
    uint64_t msg_qbytes;
    int32_t msg_lspid;
    int32_t msg_lrpid;
    uint64_t unused4;
    uint64_t unused5;
};

struct edge_linux_msginfo {
    int32_t msgpool;
    int32_t msgmap;
    int32_t msgmax;
    int32_t msgmnb;
    int32_t msgmni;
    int32_t msgssz;
    int32_t msgtql;
    uint16_t msgseg;
    uint16_t padding;
};

struct edge_linux_mq_attr {
    int64_t mq_flags;
    int64_t mq_maxmsg;
    int64_t mq_msgsize;
    int64_t mq_curmsgs;
};

struct edge_linux_mq_attr32 {
    int32_t mq_flags;
    int32_t mq_maxmsg;
    int32_t mq_msgsize;
    int32_t mq_curmsgs;
    int32_t reserved[4];
};

/* Legacy Linux native asynchronous I/O UAPI shared by 64-bit targets. */
struct edge_linux_io_event {
    uint64_t data;
    uint64_t object;
    int64_t result;
    int64_t result2;
};

struct edge_linux_iocb {
    uint64_t data;
    uint32_t key;
    uint32_t rw_flags;
    uint16_t opcode;
    int16_t request_priority;
    uint32_t descriptor;
    uint64_t buffer;
    uint64_t byte_count;
    int64_t offset;
    uint64_t reserved2;
    uint32_t flags;
    uint32_t result_descriptor;
};

struct edge_linux_aio_sigset {
    uint64_t signal_mask;
    uint64_t signal_set_size;
};

/* Linux io_uring UAPI layouts shared by x86_64 and AArch64. */
struct edge_linux_io_uring_sqe {
    uint8_t opcode;
    uint8_t flags;
    uint16_t ioprio;
    int32_t descriptor;
    uint64_t offset;
    uint64_t address;
    uint32_t length;
    uint32_t operation_flags;
    uint64_t user_data;
    uint16_t buffer_index;
    uint16_t personality;
    int32_t splice_descriptor;
    uint64_t address3;
    uint64_t reserved2;
};

struct edge_linux_io_uring_cqe {
    uint64_t user_data;
    int32_t result;
    uint32_t flags;
};

struct edge_linux_io_sqring_offsets {
    uint32_t head;
    uint32_t tail;
    uint32_t ring_mask;
    uint32_t ring_entries;
    uint32_t flags;
    uint32_t dropped;
    uint32_t array;
    uint32_t reserved1;
    uint64_t user_address;
};

struct edge_linux_io_cqring_offsets {
    uint32_t head;
    uint32_t tail;
    uint32_t ring_mask;
    uint32_t ring_entries;
    uint32_t overflow;
    uint32_t cqes;
    uint32_t flags;
    uint32_t reserved1;
    uint64_t user_address;
};

struct edge_linux_io_uring_params {
    uint32_t sq_entries;
    uint32_t cq_entries;
    uint32_t flags;
    uint32_t sq_thread_cpu;
    uint32_t sq_thread_idle;
    uint32_t features;
    uint32_t workqueue_descriptor;
    uint32_t reserved[3];
    struct edge_linux_io_sqring_offsets sq_off;
    struct edge_linux_io_cqring_offsets cq_off;
};

struct edge_linux_io_uring_probe_op {
    uint8_t opcode;
    uint8_t reserved;
    uint16_t flags;
    uint32_t reserved2;
};

struct edge_linux_io_uring_probe {
    uint8_t last_opcode;
    uint8_t operation_count;
    uint16_t reserved;
    uint32_t reserved2[3];
};

struct edge_linux_io_uring_query_header {
    uint64_t next_entry;
    uint64_t query_data;
    uint32_t query_opcode;
    uint32_t size;
    int32_t result;
    uint32_t reserved[3];
};

struct edge_linux_io_uring_query_opcodes {
    uint32_t request_opcode_count;
    uint32_t register_opcode_count;
    uint64_t feature_flags;
    uint64_t setup_flags;
    uint64_t enter_flags;
    uint64_t sqe_flags;
    uint32_t query_opcode_count;
    uint32_t padding;
};

struct edge_linux_io_uring_sync_cancel_reg {
    uint64_t address;
    int32_t descriptor;
    uint32_t flags;
    int64_t timeout_seconds;
    int64_t timeout_nanoseconds;
    uint8_t opcode;
    uint8_t padding[7];
    uint64_t padding2[3];
};

struct edge_linux_io_uring_restriction {
    uint16_t opcode;
    uint8_t operation;
    uint8_t reserved;
    uint32_t reserved2[3];
};

struct edge_linux_io_uring_task_restriction {
    uint16_t flags;
    uint16_t restriction_count;
    uint32_t reserved[3];
};

struct edge_linux_io_uring_clone_buffers {
    uint32_t source_descriptor;
    uint32_t flags;
    uint32_t source_offset;
    uint32_t destination_offset;
    uint32_t count;
    uint32_t padding[3];
};

struct edge_linux_io_uring_getevents_arg {
    uint64_t signal_mask;
    uint32_t signal_mask_size;
    uint32_t minimum_wait_microseconds;
    uint64_t timeout;
};

struct edge_linux_io_uring_region_desc {
    uint64_t user_address;
    uint64_t size;
    uint32_t flags;
    uint32_t id;
    uint64_t mmap_offset;
    uint64_t reserved[4];
};

struct edge_linux_io_uring_mem_region_reg {
    uint64_t region;
    uint64_t flags;
    uint64_t reserved[2];
};

struct edge_linux_io_uring_reg_wait {
    int64_t timeout_seconds;
    int64_t timeout_nanoseconds;
    uint32_t minimum_wait_microseconds;
    uint32_t flags;
    uint64_t signal_mask;
    uint32_t signal_mask_size;
    uint32_t padding[3];
    uint64_t padding2[2];
};

struct edge_linux_io_uring_files_update {
    uint32_t offset;
    uint32_t reserved;
    uint64_t descriptors;
};

struct edge_linux_io_uring_resource_update {
    uint32_t offset;
    uint32_t reserved;
    uint64_t data;
};

struct edge_linux_io_uring_resource_register {
    uint32_t count;
    uint32_t flags;
    uint64_t reserved;
    uint64_t data;
    uint64_t tags;
};

struct edge_linux_io_uring_resource_update2 {
    uint32_t offset;
    uint32_t reserved;
    uint64_t data;
    uint64_t tags;
    uint32_t count;
    uint32_t reserved2;
};

struct edge_linux_io_uring_file_index_range {
    uint32_t offset;
    uint32_t length;
    uint64_t reserved;
};

struct edge_linux_io_uring_clock_register {
    uint32_t clock_id;
    uint32_t reserved[3];
};

struct edge_linux_io_uring_napi {
    uint32_t busy_poll_to;
    uint8_t prefer_busy_poll;
    uint8_t opcode;
    uint8_t padding[2];
    uint32_t operation_parameter;
    uint32_t reserved;
};

struct edge_linux_io_uring_buf {
    uint64_t address;
    uint32_t length;
    uint16_t id;
    uint16_t reserved;
};

struct edge_linux_io_uring_buf_reg {
    uint64_t ring_address;
    uint32_t ring_entries;
    uint16_t group_id;
    uint16_t flags;
    uint32_t minimum_left;
    uint32_t reserved[5];
};

struct edge_linux_io_uring_buf_status {
    uint32_t buffer_group;
    uint32_t head;
    uint32_t reserved[8];
};

_Static_assert(sizeof(struct edge_linux_ipc_perm64) == 48,
               "Linux ipc_perm size mismatch");
_Static_assert(offsetof(struct edge_linux_ipc_perm64, mode) == 20,
               "Linux ipc_perm mode offset mismatch");
_Static_assert(sizeof(struct edge_linux_shmid_ds64) == 112,
               "Linux shmid_ds size mismatch");
_Static_assert(offsetof(struct edge_linux_shmid_ds64, shm_segsz) == 48,
               "Linux shmid_ds size offset mismatch");
_Static_assert(offsetof(struct edge_linux_shmid_ds64, shm_cpid) == 80,
               "Linux shmid_ds creator PID offset mismatch");
_Static_assert(offsetof(struct edge_linux_shmid_ds64, shm_nattch) == 88,
               "Linux shmid_ds attachment offset mismatch");
_Static_assert(sizeof(struct edge_linux_sembuf) == 6,
               "Linux sembuf size mismatch");
_Static_assert(sizeof(struct edge_linux_semid_ds_x86_64) == 104,
               "Linux x86_64 semid_ds size mismatch");
_Static_assert(sizeof(struct edge_linux_semid_ds_aarch64) == 88,
               "Linux AArch64 semid_ds size mismatch");
_Static_assert(sizeof(struct edge_linux_seminfo) == 40,
               "Linux seminfo size mismatch");
_Static_assert(sizeof(struct edge_linux_msqid_ds64) == 120,
               "Linux 64-bit msqid_ds size mismatch");
_Static_assert(offsetof(struct edge_linux_msqid_ds64, msg_cbytes) == 72,
               "Linux msqid_ds byte-count offset mismatch");
_Static_assert(sizeof(struct edge_linux_msginfo) == 32,
               "Linux msginfo size mismatch");
_Static_assert(sizeof(struct edge_linux_mq_attr) == 32,
               "Linux mq_attr size mismatch");
_Static_assert(sizeof(struct edge_linux_mq_attr32) == 32,
               "Linux i386 mq_attr size mismatch");
_Static_assert(sizeof(struct edge_linux_io_event) == 32,
               "Linux io_event size mismatch");
_Static_assert(sizeof(struct edge_linux_iocb) == 64,
               "Linux iocb size mismatch");
_Static_assert(offsetof(struct edge_linux_iocb, opcode) == 16,
               "Linux iocb opcode offset mismatch");
_Static_assert(offsetof(struct edge_linux_iocb, buffer) == 24,
               "Linux iocb buffer offset mismatch");
_Static_assert(offsetof(struct edge_linux_iocb, flags) == 56,
               "Linux iocb flags offset mismatch");
_Static_assert(sizeof(struct edge_linux_aio_sigset) == 16,
               "Linux aio sigset size mismatch");
_Static_assert(sizeof(struct edge_linux_io_uring_sqe) == 64,
               "Linux io_uring SQE size mismatch");
_Static_assert(offsetof(struct edge_linux_io_uring_sqe, user_data) == 32,
               "Linux io_uring SQE user_data offset mismatch");
_Static_assert(sizeof(struct edge_linux_io_uring_cqe) == 16,
               "Linux io_uring CQE size mismatch");
_Static_assert(sizeof(struct edge_linux_io_sqring_offsets) == 40,
               "Linux io_uring SQ offset size mismatch");
_Static_assert(sizeof(struct edge_linux_io_cqring_offsets) == 40,
               "Linux io_uring CQ offset size mismatch");
_Static_assert(sizeof(struct edge_linux_io_uring_params) == 120,
               "Linux io_uring params size mismatch");
_Static_assert(sizeof(struct edge_linux_io_uring_probe_op) == 8,
               "Linux io_uring probe operation size mismatch");
_Static_assert(sizeof(struct edge_linux_io_uring_probe) == 16,
               "Linux io_uring probe header size mismatch");
_Static_assert(sizeof(struct edge_linux_io_uring_query_header) == 40,
               "Linux io_uring query header size mismatch");
_Static_assert(sizeof(struct edge_linux_io_uring_query_opcodes) == 48,
               "Linux io_uring opcode query size mismatch");
_Static_assert(sizeof(struct edge_linux_io_uring_sync_cancel_reg) == 64,
               "Linux io_uring synchronous cancel size mismatch");
_Static_assert(sizeof(struct edge_linux_io_uring_restriction) == 16,
               "Linux io_uring restriction size mismatch");
_Static_assert(sizeof(struct edge_linux_io_uring_task_restriction) == 16,
               "Linux io_uring task restriction size mismatch");
_Static_assert(sizeof(struct edge_linux_io_uring_clone_buffers) == 32,
               "Linux io_uring clone buffers size mismatch");
_Static_assert(sizeof(struct edge_linux_io_uring_getevents_arg) == 24,
               "Linux io_uring getevents argument size mismatch");
_Static_assert(sizeof(struct edge_linux_io_uring_region_desc) == 64,
               "Linux io_uring region descriptor size mismatch");
_Static_assert(sizeof(struct edge_linux_io_uring_mem_region_reg) == 32,
               "Linux io_uring memory region registration size mismatch");
_Static_assert(sizeof(struct edge_linux_io_uring_reg_wait) == 64,
               "Linux io_uring registered wait size mismatch");
_Static_assert(sizeof(struct edge_linux_io_uring_files_update) == 16,
               "Linux io_uring files update size mismatch");
_Static_assert(sizeof(struct edge_linux_io_uring_resource_update) == 16,
               "Linux io_uring resource update size mismatch");
_Static_assert(sizeof(struct edge_linux_io_uring_resource_register) == 32,
               "Linux io_uring resource registration size mismatch");
_Static_assert(sizeof(struct edge_linux_io_uring_resource_update2) == 32,
               "Linux io_uring resource update size mismatch");
_Static_assert(sizeof(struct edge_linux_io_uring_file_index_range) == 16,
               "Linux io_uring file allocation range size mismatch");
_Static_assert(sizeof(struct edge_linux_io_uring_clock_register) == 16,
               "Linux io_uring clock registration size mismatch");
_Static_assert(sizeof(struct edge_linux_io_uring_napi) == 16,
               "Linux io_uring NAPI registration size mismatch");
_Static_assert(sizeof(struct edge_linux_io_uring_buf) == 16,
               "Linux io_uring provided buffer size mismatch");
_Static_assert(sizeof(struct edge_linux_io_uring_buf_reg) == 40,
               "Linux io_uring buffer ring registration size mismatch");
_Static_assert(sizeof(struct edge_linux_io_uring_buf_status) == 40,
               "Linux io_uring buffer ring status size mismatch");

/* statx is an architecture-independent Linux UAPI layout on 64-bit ports. */
struct edge_linux_statx_timestamp {
    int64_t tv_sec;
    uint32_t tv_nsec;
    int32_t __reserved;
};

struct edge_linux_statx {
    uint32_t stx_mask;
    uint32_t stx_blksize;
    uint64_t stx_attributes;
    uint32_t stx_nlink;
    uint32_t stx_uid;
    uint32_t stx_gid;
    uint16_t stx_mode;
    uint16_t __spare0;
    uint64_t stx_ino;
    uint64_t stx_size;
    uint64_t stx_blocks;
    uint64_t stx_attributes_mask;
    struct edge_linux_statx_timestamp stx_atime;
    struct edge_linux_statx_timestamp stx_btime;
    struct edge_linux_statx_timestamp stx_ctime;
    struct edge_linux_statx_timestamp stx_mtime;
    uint32_t stx_rdev_major;
    uint32_t stx_rdev_minor;
    uint32_t stx_dev_major;
    uint32_t stx_dev_minor;
    uint64_t stx_mnt_id;
    uint32_t stx_dio_mem_align;
    uint32_t stx_dio_offset_align;
    uint64_t stx_subvol;
    uint32_t stx_atomic_write_unit_min;
    uint32_t stx_atomic_write_unit_max;
    uint32_t stx_atomic_write_segments_max;
    uint32_t stx_dio_read_offset_align;
    uint32_t stx_atomic_write_unit_max_opt;
    uint32_t __spare2[1];
    uint64_t __spare3[8];
};

_Static_assert(sizeof(struct edge_linux_statx_timestamp) == 16,
               "Linux statx timestamp size mismatch");
_Static_assert(sizeof(struct edge_linux_statx) == 256,
               "Linux statx size mismatch");
_Static_assert(offsetof(struct edge_linux_statx, stx_ino) == 32,
               "Linux statx inode offset mismatch");
_Static_assert(offsetof(struct edge_linux_statx, stx_atime) == 64,
               "Linux statx atime offset mismatch");
_Static_assert(offsetof(struct edge_linux_statx, stx_mnt_id) == 144,
               "Linux statx mount ID offset mismatch");
_Static_assert(offsetof(struct edge_linux_statx, stx_subvol) == 160,
               "Linux statx subvolume offset mismatch");

struct edge_linux_statfs64 {
    int64_t f_type;
    int64_t f_bsize;
    uint64_t f_blocks;
    uint64_t f_bfree;
    uint64_t f_bavail;
    uint64_t f_files;
    uint64_t f_ffree;
    int32_t f_fsid[2];
    int64_t f_namelen;
    int64_t f_frsize;
    int64_t f_flags;
    int64_t f_spare[4];
};

struct edge_linux_statfs32 {
    uint32_t f_type;
    uint32_t f_bsize;
    uint32_t f_blocks;
    uint32_t f_bfree;
    uint32_t f_bavail;
    uint32_t f_files;
    uint32_t f_ffree;
    int32_t f_fsid[2];
    uint32_t f_namelen;
    uint32_t f_frsize;
    uint32_t f_flags;
    uint32_t f_spare[4];
};

struct __attribute__((packed, aligned(4))) edge_linux_statfs64_compat {
    uint32_t f_type;
    uint32_t f_bsize;
    uint64_t f_blocks;
    uint64_t f_bfree;
    uint64_t f_bavail;
    uint64_t f_files;
    uint64_t f_ffree;
    int32_t f_fsid[2];
    uint32_t f_namelen;
    uint32_t f_frsize;
    uint32_t f_flags;
    uint32_t f_spare[4];
};

struct edge_linux_ustat {
    int32_t f_tfree;
    uint32_t __padding;
    uint64_t f_tinode;
    char f_fname[6];
    char f_fpack[6];
    uint32_t __tail_padding;
};

struct edge_linux_ustat32 {
    int32_t f_tfree;
    uint32_t f_tinode;
    char f_fname[6];
    char f_fpack[6];
};

_Static_assert(sizeof(struct edge_linux_ustat) == 32u,
               "Linux x86_64 ustat size mismatch");
_Static_assert(offsetof(struct edge_linux_ustat, f_tinode) == 8u,
               "Linux x86_64 ustat inode offset mismatch");
_Static_assert(sizeof(struct edge_linux_ustat32) == 20u,
               "Linux compat ustat size mismatch");

#define EDGE_LINUX_SOL_PACKET 263u
#define EDGE_LINUX_PACKET_ADD_MEMBERSHIP 1u
#define EDGE_LINUX_PACKET_DROP_MEMBERSHIP 2u
#define EDGE_LINUX_PACKET_RX_RING 5u
#define EDGE_LINUX_PACKET_STATISTICS 6u
#define EDGE_LINUX_PACKET_AUXDATA 8u
#define EDGE_LINUX_PACKET_VERSION 10u
#define EDGE_LINUX_PACKET_HDRLEN 11u
#define EDGE_LINUX_PACKET_RESERVE 12u
#define EDGE_LINUX_PACKET_LOSS 14u
#define EDGE_LINUX_PACKET_QDISC_BYPASS 20u
#define EDGE_LINUX_PACKET_IGNORE_OUTGOING 23u

#define EDGE_LINUX_PACKET_MR_MULTICAST 0u
#define EDGE_LINUX_PACKET_MR_PROMISC 1u
#define EDGE_LINUX_PACKET_MR_ALLMULTI 2u
#define EDGE_LINUX_PACKET_MR_UNICAST 3u

#define EDGE_LINUX_TPACKET_V1 0u
#define EDGE_LINUX_TPACKET_V2 1u
#define EDGE_LINUX_TPACKET_V3 2u
#define EDGE_LINUX_TP_STATUS_KERNEL 0u
#define EDGE_LINUX_TP_STATUS_USER (1u << 0)
#define EDGE_LINUX_TP_STATUS_COPY (1u << 1)
#define EDGE_LINUX_TP_STATUS_LOSING (1u << 2)

#define EDGE_LINUX_PACKET_HOST 0u
#define EDGE_LINUX_PACKET_BROADCAST 1u
#define EDGE_LINUX_PACKET_MULTICAST 2u
#define EDGE_LINUX_PACKET_OTHERHOST 3u
#define EDGE_LINUX_PACKET_OUTGOING 4u

#define EDGE_LINUX_ARPHRD_ETHER 1u
#define EDGE_LINUX_ARPHRD_LOOPBACK 772u
#define EDGE_LINUX_AF_UNIX 1u
#define EDGE_LINUX_AF_INET 2u
#define EDGE_LINUX_AF_INET6 10u
#define EDGE_LINUX_AF_NETLINK 16u
#define EDGE_LINUX_AF_PACKET 17u

#define EDGE_LINUX_NETLINK_ROUTE 0u
#define EDGE_LINUX_NETLINK_NETFILTER 12u
#define EDGE_LINUX_NETLINK_KOBJECT_UEVENT 15u
#define EDGE_LINUX_NETLINK_KOBJECT_UEVENT_GROUP 1u
#define EDGE_LINUX_NETLINK_KOBJECT_USER_GROUP 2u
#define EDGE_LINUX_SOL_NETLINK 270u
#define EDGE_LINUX_NETLINK_ADD_MEMBERSHIP 1u
#define EDGE_LINUX_NETLINK_DROP_MEMBERSHIP 2u
#define EDGE_LINUX_NETLINK_PACKET_INFO 3u
#define EDGE_LINUX_NETLINK_LIST_MEMBERSHIPS 9u
#define EDGE_LINUX_SOCK_TYPE_MASK 0x0fu
#define EDGE_LINUX_SOCK_STREAM 1u
#define EDGE_LINUX_SOCK_DGRAM 2u
#define EDGE_LINUX_SOCK_RAW 3u
#define EDGE_LINUX_SOCK_SEQPACKET 5u
#define EDGE_LINUX_SOCK_NONBLOCK 0x00000800u
#define EDGE_LINUX_SOCK_CLOEXEC 0x00080000u
#define EDGE_LINUX_MSG_PEEK 0x00000002u
#define EDGE_LINUX_MSG_CTRUNC 0x00000008u
#define EDGE_LINUX_MSG_TRUNC 0x00000020u
#define EDGE_LINUX_MSG_DONTWAIT 0x00000040u
#define EDGE_LINUX_MSG_EOR 0x00000080u
#define EDGE_LINUX_MSG_WAITFORONE 0x00010000u
#define EDGE_LINUX_MSG_NOSIGNAL 0x00004000u
#define EDGE_LINUX_MSG_CMSG_CLOEXEC 0x40000000u
#define EDGE_LINUX_ROBUST_LIST_HEAD_SIZE 24u
#define EDGE_LINUX_COMPAT_ROBUST_LIST_HEAD_SIZE 12u
#define EDGE_LINUX_SIGNAL_MAX 64u
#define EDGE_LINUX_SIGHUP 1u
#define EDGE_LINUX_SIGINT 2u
#define EDGE_LINUX_SIGQUIT 3u
#define EDGE_LINUX_SIGILL 4u
#define EDGE_LINUX_SIGTRAP 5u
#define EDGE_LINUX_SIGABRT 6u
#define EDGE_LINUX_SIGBUS 7u
#define EDGE_LINUX_SIGFPE 8u
#define EDGE_LINUX_SIGKILL 9u
#define EDGE_LINUX_SIGUSR1 10u
#define EDGE_LINUX_SIGSEGV 11u
#define EDGE_LINUX_SIGUSR2 12u
#define EDGE_LINUX_SIGPIPE 13u
#define EDGE_LINUX_SIGALRM 14u
#define EDGE_LINUX_SIGTERM 15u
#define EDGE_LINUX_SIGSTKFLT 16u
#define EDGE_LINUX_SIGCHLD 17u
#define EDGE_LINUX_SIGCONT 18u
#define EDGE_LINUX_SIGSTOP 19u
#define EDGE_LINUX_SIGTSTP 20u
#define EDGE_LINUX_SIGTTIN 21u
#define EDGE_LINUX_SIGTTOU 22u
#define EDGE_LINUX_SIGURG 23u
#define EDGE_LINUX_SIGXCPU 24u
#define EDGE_LINUX_SIGXFSZ 25u
#define EDGE_LINUX_SIGVTALRM 26u
#define EDGE_LINUX_SIGPROF 27u
#define EDGE_LINUX_SIGWINCH 28u
#define EDGE_LINUX_SIGIO 29u
#define EDGE_LINUX_SIGPWR 30u
#define EDGE_LINUX_SIGSYS 31u
#define EDGE_LINUX_SIGRTMIN_KERNEL 32u
#define EDGE_LINUX_SIG_DFL 0u
#define EDGE_LINUX_SIG_IGN 1u
#define EDGE_LINUX_SA_NOCLDSTOP 0x00000001u
#define EDGE_LINUX_SA_NOCLDWAIT 0x00000002u
#define EDGE_LINUX_SA_SIGINFO 0x00000004u
#define EDGE_LINUX_SA_RESTORER 0x04000000u
#define EDGE_LINUX_SA_ONSTACK 0x08000000u
#define EDGE_LINUX_SA_RESTART 0x10000000u
#define EDGE_LINUX_SA_NODEFER 0x40000000u
#define EDGE_LINUX_SA_RESETHAND 0x80000000u
#define EDGE_LINUX_SIGNAL_UNBLOCKABLE_MASK \
    ((UINT64_C(1) << (EDGE_LINUX_SIGKILL - 1u)) | \
     (UINT64_C(1) << (EDGE_LINUX_SIGSTOP - 1u)))
#define EDGE_LINUX_SI_USER 0
#define EDGE_LINUX_SI_QUEUE (-1)
#define EDGE_LINUX_SI_TKILL (-6)
#define EDGE_LINUX_PIDFD_THREAD 0x00000080u
#define EDGE_LINUX_PIDFD_NONBLOCK 0x00000800u
#define EDGE_LINUX_PIDFD_SIGNAL_THREAD (1u << 0)
#define EDGE_LINUX_PIDFD_SIGNAL_THREAD_GROUP (1u << 1)
#define EDGE_LINUX_PIDFD_SIGNAL_PROCESS_GROUP (1u << 2)
#define EDGE_LINUX_PIDFD_SIGNAL_SCOPE_MASK \
    (EDGE_LINUX_PIDFD_SIGNAL_THREAD | \
     EDGE_LINUX_PIDFD_SIGNAL_THREAD_GROUP | \
     EDGE_LINUX_PIDFD_SIGNAL_PROCESS_GROUP)
#define EDGE_LINUX_MEMBARRIER_CMD_QUERY 0u
#define EDGE_LINUX_MEMBARRIER_CMD_GLOBAL (1u << 0)
#define EDGE_LINUX_MEMBARRIER_CMD_GLOBAL_EXPEDITED (1u << 1)
#define EDGE_LINUX_MEMBARRIER_CMD_REGISTER_GLOBAL_EXPEDITED (1u << 2)
#define EDGE_LINUX_MEMBARRIER_CMD_PRIVATE_EXPEDITED (1u << 3)
#define EDGE_LINUX_MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED (1u << 4)
#define EDGE_LINUX_MEMBARRIER_CMD_PRIVATE_EXPEDITED_SYNC_CORE (1u << 5)
#define EDGE_LINUX_MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_SYNC_CORE (1u << 6)
#define EDGE_LINUX_MEMBARRIER_CMD_PRIVATE_EXPEDITED_RSEQ (1u << 7)
#define EDGE_LINUX_MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_RSEQ (1u << 8)
#define EDGE_LINUX_MEMBARRIER_CMD_GET_REGISTRATIONS (1u << 9)
#define EDGE_LINUX_MEMBARRIER_CMD_FLAG_CPU (1u << 0)
#define EDGE_LINUX_IPPROTO_ICMP 1u
#define EDGE_LINUX_IPPROTO_TCP 6u
#define EDGE_LINUX_IPPROTO_UDP 17u
#define EDGE_LINUX_IPPROTO_ICMPV6 58u
#define EDGE_LINUX_IPPROTO_RAW 255u
#define EDGE_LINUX_ICMP6_FILTER 1u
#define EDGE_LINUX_SOL_IP 0u
#define EDGE_LINUX_SOL_SOCKET 1u
#define EDGE_LINUX_SOL_TCP 6u
#define EDGE_LINUX_SOL_IPV6 41u
#define EDGE_LINUX_SO_REUSEADDR 2u
#define EDGE_LINUX_SO_TYPE 3u
#define EDGE_LINUX_SO_ERROR 4u
#define EDGE_LINUX_SO_BROADCAST 6u
#define EDGE_LINUX_SO_SNDBUF 7u
#define EDGE_LINUX_SO_RCVBUF 8u
#define EDGE_LINUX_SO_KEEPALIVE 9u
#define EDGE_LINUX_SO_OOBINLINE 10u
#define EDGE_LINUX_SO_NO_CHECK 11u
#define EDGE_LINUX_SO_PRIORITY 12u
#define EDGE_LINUX_SO_LINGER 13u
#define EDGE_LINUX_SO_REUSEPORT 15u
#define EDGE_LINUX_SO_PASSCRED 16u
#define EDGE_LINUX_SO_PEERCRED 17u
#define EDGE_LINUX_SO_RCVLOWAT 18u
#define EDGE_LINUX_SO_SNDLOWAT 19u
#define EDGE_LINUX_SO_RCVTIMEO 20u
#define EDGE_LINUX_SO_SNDTIMEO 21u
#define EDGE_LINUX_SO_BINDTODEVICE 25u
#define EDGE_LINUX_SO_ATTACH_FILTER 26u
#define EDGE_LINUX_SO_DETACH_FILTER 27u
#define EDGE_LINUX_SO_TIMESTAMP 29u
#define EDGE_LINUX_SO_ACCEPTCONN 30u
#define EDGE_LINUX_SO_PEERSEC 31u
#define EDGE_LINUX_SO_SNDBUFFORCE 32u
#define EDGE_LINUX_SO_RCVBUFFORCE 33u
#define EDGE_LINUX_SO_TIMESTAMPNS 35u
#define EDGE_LINUX_SO_MARK 36u
#define EDGE_LINUX_SO_PROTOCOL 38u
#define EDGE_LINUX_SO_DOMAIN 39u
#define EDGE_LINUX_SO_PEERGROUPS 59u
#define EDGE_LINUX_SO_TIMESTAMP_NEW 63u
#define EDGE_LINUX_SO_TIMESTAMPNS_NEW 64u
#define EDGE_LINUX_SO_RCVTIMEO_NEW 66u
#define EDGE_LINUX_SO_SNDTIMEO_NEW 67u
#define EDGE_LINUX_SO_PASSPIDFD 76u
#define EDGE_LINUX_SO_PEERPIDFD 77u
#define EDGE_LINUX_IP_TOS 1u
#define EDGE_LINUX_IP_TTL 2u
#define EDGE_LINUX_IP_HDRINCL 3u
#define EDGE_LINUX_IP_PKTINFO 8u
#define EDGE_LINUX_IP_MTU_DISCOVER 10u
#define EDGE_LINUX_IP_RECVERR 11u
#define EDGE_LINUX_IP_RECVTTL 12u
#define EDGE_LINUX_IP_MTU 14u
#define EDGE_LINUX_IP_FREEBIND 15u
#define EDGE_LINUX_IP_MULTICAST_IF 32u
#define EDGE_LINUX_IP_MULTICAST_TTL 33u
#define EDGE_LINUX_IP_MULTICAST_LOOP 34u
#define EDGE_LINUX_IP_ADD_MEMBERSHIP 35u
#define EDGE_LINUX_IP_DROP_MEMBERSHIP 36u
#define EDGE_LINUX_IPT_SO_GET_REVISION_MATCH 66u
#define EDGE_LINUX_IPT_SO_GET_REVISION_TARGET 67u
#define EDGE_LINUX_XT_EXTENSION_MAXNAMELEN 29u
#define EDGE_LINUX_IP_PMTUDISC_DONT 0
#define EDGE_LINUX_IP_PMTUDISC_WANT 1
#define EDGE_LINUX_IP_PMTUDISC_DO 2
#define EDGE_LINUX_IP_PMTUDISC_PROBE 3
#define EDGE_LINUX_IP_PMTUDISC_INTERFACE 4
#define EDGE_LINUX_IP_PMTUDISC_OMIT 5

struct edge_linux_xt_get_revision {
    char name[EDGE_LINUX_XT_EXTENSION_MAXNAMELEN];
    uint8_t revision;
};
#define EDGE_LINUX_IPV6_CHECKSUM 7u
#define EDGE_LINUX_IPV6_UNICAST_HOPS 16u
#define EDGE_LINUX_IPV6_MULTICAST_IF 17u
#define EDGE_LINUX_IPV6_MULTICAST_HOPS 18u
#define EDGE_LINUX_IPV6_MULTICAST_LOOP 19u
#define EDGE_LINUX_IPV6_ADD_MEMBERSHIP 20u
#define EDGE_LINUX_IPV6_DROP_MEMBERSHIP 21u
#define EDGE_LINUX_IPV6_RECVERR 25u
#define EDGE_LINUX_IPV6_V6ONLY 26u
#define EDGE_LINUX_IPV6_RECVPKTINFO 49u
#define EDGE_LINUX_IPV6_PKTINFO 50u
#define EDGE_LINUX_IPV6_RECVHOPLIMIT 51u
#define EDGE_LINUX_IPV6_HOPLIMIT 52u
#define EDGE_LINUX_IPV6_RECVTCLASS 66u
#define EDGE_LINUX_IPV6_TCLASS 67u
#define EDGE_LINUX_TCP_NODELAY 1u
#define EDGE_LINUX_TCP_KEEPIDLE 4u
#define EDGE_LINUX_TCP_KEEPINTVL 5u
#define EDGE_LINUX_TCP_KEEPCNT 6u
#define EDGE_LINUX_ETH_P_ALL 0x0003u
#define EDGE_LINUX_SOCKADDR_STORAGE_SIZE 128u

struct edge_linux_sockaddr {
    uint16_t sa_family;
    uint8_t sa_data[14];
};

struct edge_linux_sockaddr_in {
    uint16_t sin_family;
    uint16_t sin_port;
    uint32_t sin_addr;
    uint8_t sin_zero[8];
};

struct edge_linux_sockaddr_in6 {
    uint16_t sin6_family;
    uint16_t sin6_port;
    uint32_t sin6_flowinfo;
    uint8_t sin6_addr[16];
    uint32_t sin6_scope_id;
};

struct edge_linux_ip_mreqn {
    uint32_t imr_multiaddr;
    uint32_t imr_address;
    int32_t imr_ifindex;
};

struct edge_linux_ipv6_mreq {
    uint8_t ipv6mr_multiaddr[16];
    int32_t ipv6mr_ifindex;
};

struct edge_linux_in_pktinfo {
    int32_t ipi_ifindex;
    uint32_t ipi_spec_dst;
    uint32_t ipi_addr;
};

struct edge_linux_in6_pktinfo {
    uint8_t ipi6_addr[16];
    uint32_t ipi6_ifindex;
};

struct edge_linux_sockaddr_un {
    uint16_t sun_family;
    uint8_t sun_path[108];
};

struct edge_linux_sockaddr_nl {
    uint16_t nl_family;
    uint16_t nl_pad;
    uint32_t nl_pid;
    uint32_t nl_groups;
};

struct edge_linux_packet_mreq {
    int32_t mr_ifindex;
    uint16_t mr_type;
    uint16_t mr_alen;
    uint8_t mr_address[8];
};

struct edge_linux_tpacket_req {
    uint32_t tp_block_size;
    uint32_t tp_block_nr;
    uint32_t tp_frame_size;
    uint32_t tp_frame_nr;
};

struct edge_linux_tpacket_req3 {
    uint32_t tp_block_size;
    uint32_t tp_block_nr;
    uint32_t tp_frame_size;
    uint32_t tp_frame_nr;
    uint32_t tp_retire_blk_tov;
    uint32_t tp_sizeof_priv;
    uint32_t tp_feature_req_word;
};

struct edge_linux_tpacket2_hdr {
    uint32_t tp_status;
    uint32_t tp_len;
    uint32_t tp_snaplen;
    uint16_t tp_mac;
    uint16_t tp_net;
    uint32_t tp_sec;
    uint32_t tp_nsec;
    uint16_t tp_vlan_tci;
    uint16_t tp_vlan_tpid;
    uint8_t tp_padding[4];
};

struct edge_linux_sockaddr_ll {
    uint16_t sll_family;
    uint16_t sll_protocol;
    int32_t sll_ifindex;
    uint16_t sll_hatype;
    uint8_t sll_pkttype;
    uint8_t sll_halen;
    uint8_t sll_addr[8];
};

#define EDGE_LINUX_RTA_CACHEINFO 12u

/* Architecture-independent payload of the Linux RTA_CACHEINFO attribute. */
struct edge_linux_rta_cacheinfo {
    uint32_t rta_clntref;
    uint32_t rta_lastuse;
    int32_t rta_expires;
    uint32_t rta_error;
    uint32_t rta_used;
    uint32_t rta_id;
    uint32_t rta_ts;
    uint32_t rta_tsage;
};

struct edge_linux_tpacket_stats {
    uint32_t tp_packets;
    uint32_t tp_drops;
};

struct edge_linux_sock_filter {
    uint16_t code;
    uint8_t jt;
    uint8_t jf;
    uint32_t k;
};

struct edge_linux_sock_fprog {
    uint16_t len;
    uint64_t filter;
};

struct edge_linux_compat_sock_fprog {
    uint16_t len;
    uint16_t reserved;
    uint32_t filter;
};

struct edge_linux_linger {
    int32_t enabled;
    int32_t seconds;
};

#define EDGE_LINUX_SIOCETHTOOL 0x8946u
#define EDGE_LINUX_ETHTOOL_GSET 0x00000001u
#define EDGE_LINUX_ETHTOOL_GDRVINFO 0x00000003u
#define EDGE_LINUX_ETHTOOL_GLINK 0x0000000au
#define EDGE_LINUX_ETHTOOL_GLINKSETTINGS 0x0000004cu
#define EDGE_LINUX_ETHTOOL_LINK_MODE_WORDS 4
#define EDGE_LINUX_SPEED_UNKNOWN UINT32_MAX
#define EDGE_LINUX_DUPLEX_UNKNOWN 0xffu
#define EDGE_LINUX_PORT_OTHER 0xffu

struct edge_linux_ethtool_value {
    uint32_t cmd;
    uint32_t data;
};

struct edge_linux_ethtool_cmd {
    uint32_t cmd;
    uint32_t supported;
    uint32_t advertising;
    uint16_t speed;
    uint8_t duplex;
    uint8_t port;
    uint8_t phy_address;
    uint8_t transceiver;
    uint8_t autoneg;
    uint8_t mdio_support;
    uint32_t maxtxpkt;
    uint32_t maxrxpkt;
    uint16_t speed_hi;
    uint8_t eth_tp_mdix;
    uint8_t eth_tp_mdix_ctrl;
    uint32_t lp_advertising;
    uint32_t reserved[2];
};

struct edge_linux_ethtool_drvinfo {
    uint32_t cmd;
    char driver[32];
    char version[32];
    char fw_version[32];
    char bus_info[32];
    char erom_version[32];
    char reserved2[12];
    uint32_t n_priv_flags;
    uint32_t n_stats;
    uint32_t testinfo_len;
    uint32_t eedump_len;
    uint32_t regdump_len;
};

struct edge_linux_ethtool_link_settings {
    uint32_t cmd;
    uint32_t speed;
    uint8_t duplex;
    uint8_t port;
    uint8_t phy_address;
    uint8_t autoneg;
    uint8_t mdio_support;
    uint8_t eth_tp_mdix;
    uint8_t eth_tp_mdix_ctrl;
    int8_t link_mode_masks_nwords;
    uint8_t transceiver;
    uint8_t master_slave_cfg;
    uint8_t master_slave_state;
    uint8_t rate_matching;
    uint32_t reserved[7];
};

struct edge_linux_netdev_info {
    const char *driver;
    const char *driver_version;
    const char *bus_info;
    uint32_t link_up;
    uint32_t speed_mbps;
    uint8_t duplex;
    uint8_t port;
    uint8_t phy_address;
    uint8_t autoneg;
};

#define EDGE_LINUX_AT_RSEQ_FEATURE_SIZE 27u
#define EDGE_LINUX_AT_RSEQ_ALIGN 28u
#define EDGE_LINUX_RSEQ_LEGACY_SIZE 32u
#define EDGE_LINUX_RSEQ_FEATURE_SIZE 33u
#define EDGE_LINUX_RSEQ_ALIGN 32u
#define EDGE_LINUX_RSEQ_FLAG_UNREGISTER 1u
#define EDGE_LINUX_RSEQ_FLAG_SLICE_EXT_DEFAULT_ON 2u
#define EDGE_LINUX_RSEQ_CS_FLAG_SLICE_EXT_AVAILABLE (1u << 4)
#define EDGE_LINUX_RSEQ_CS_FLAG_SLICE_EXT_ENABLED (1u << 5)

#define EDGE_LINUX_PR_RSEQ_SLICE_EXTENSION 79u
#define EDGE_LINUX_PR_RSEQ_SLICE_EXTENSION_GET 1u
#define EDGE_LINUX_PR_RSEQ_SLICE_EXTENSION_SET 2u
#define EDGE_LINUX_PR_RSEQ_SLICE_EXT_ENABLE 1u
#define EDGE_LINUX_RSEQ_SLICE_EXTENSION_US 5u

struct edge_linux_sched_param {
    int32_t sched_priority;
};

struct edge_linux_sched_attr {
    uint32_t size;
    uint32_t sched_policy;
    uint64_t sched_flags;
    int32_t sched_nice;
    uint32_t sched_priority;
    uint64_t sched_runtime;
    uint64_t sched_deadline;
    uint64_t sched_period;
    uint32_t sched_util_min;
    uint32_t sched_util_max;
};

_Static_assert(sizeof(struct edge_linux_sched_param) == 4,
               "Linux sched_param ABI size");
_Static_assert(sizeof(struct edge_linux_sched_attr) ==
                   EDGE_LINUX_SCHED_ATTR_SIZE_VER1,
               "Linux sched_attr ABI size");
_Static_assert(offsetof(struct edge_linux_sched_attr, sched_runtime) == 24,
               "Linux sched_attr runtime offset");
_Static_assert(offsetof(struct edge_linux_sched_attr, sched_util_min) == 48,
               "Linux sched_attr utilization offset");

#define EDGE_LINUX_RLIMIT_COUNT 16u
#define EDGE_LINUX_RLIMIT_STACK 3u
#define EDGE_LINUX_RLIMIT_MEMLOCK 8u
#define EDGE_LINUX_RLIMIT_NOFILE 7u
#define EDGE_LINUX_RLIMIT_NICE 13u
#define EDGE_LINUX_RLIMIT_RTPRIO 14u
#define EDGE_LINUX_RLIM_INFINITY UINT64_MAX

#define EDGE_LINUX_RUSAGE_CHILDREN (-1)
#define EDGE_LINUX_RUSAGE_SELF 0
#define EDGE_LINUX_RUSAGE_THREAD 1

struct edge_linux_rlimit64 {
    uint64_t rlim_cur;
    uint64_t rlim_max;
};

struct edge_linux_rlimit32 {
    uint32_t rlim_cur;
    uint32_t rlim_max;
};

struct edge_linux_rusage64 {
    linux_timeval64_t ru_utime;
    linux_timeval64_t ru_stime;
    int64_t ru_maxrss;
    int64_t ru_ixrss;
    int64_t ru_idrss;
    int64_t ru_isrss;
    int64_t ru_minflt;
    int64_t ru_majflt;
    int64_t ru_nswap;
    int64_t ru_inblock;
    int64_t ru_oublock;
    int64_t ru_msgsnd;
    int64_t ru_msgrcv;
    int64_t ru_nsignals;
    int64_t ru_nvcsw;
    int64_t ru_nivcsw;
};

struct edge_linux_rusage32 {
    linux_timeval32_t ru_utime;
    linux_timeval32_t ru_stime;
    int32_t ru_maxrss;
    int32_t ru_ixrss;
    int32_t ru_idrss;
    int32_t ru_isrss;
    int32_t ru_minflt;
    int32_t ru_majflt;
    int32_t ru_nswap;
    int32_t ru_inblock;
    int32_t ru_oublock;
    int32_t ru_msgsnd;
    int32_t ru_msgrcv;
    int32_t ru_nsignals;
    int32_t ru_nvcsw;
    int32_t ru_nivcsw;
};

struct edge_linux_tms64 {
    int64_t tms_utime;
    int64_t tms_stime;
    int64_t tms_cutime;
    int64_t tms_cstime;
};

struct edge_linux_tms32 {
    int32_t tms_utime;
    int32_t tms_stime;
    int32_t tms_cutime;
    int32_t tms_cstime;
};

#define EDGE_LINUX_PRIO_PROCESS 0
#define EDGE_LINUX_PRIO_PGRP 1
#define EDGE_LINUX_PRIO_USER 2

#define EDGE_LINUX_IOPRIO_WHO_PROCESS 1u
#define EDGE_LINUX_IOPRIO_WHO_PGRP 2u
#define EDGE_LINUX_IOPRIO_WHO_USER 3u
#define EDGE_LINUX_IOPRIO_CLASS_SHIFT 13u
#define EDGE_LINUX_IOPRIO_CLASS_NONE 0u
#define EDGE_LINUX_IOPRIO_CLASS_RT 1u
#define EDGE_LINUX_IOPRIO_CLASS_BE 2u
#define EDGE_LINUX_IOPRIO_CLASS_IDLE 3u
#define EDGE_LINUX_IOPRIO_LEVEL_MASK 7u

#define EDGE_LINUX_CAPABILITY_VERSION_1 0x19980330u
#define EDGE_LINUX_CAPABILITY_VERSION_2 0x20071026u
#define EDGE_LINUX_CAPABILITY_VERSION_3 0x20080522u

struct edge_linux_cap_user_header {
    uint32_t version;
    int32_t pid;
};

struct edge_linux_cap_user_data {
    uint32_t effective;
    uint32_t permitted;
    uint32_t inheritable;
};

struct edge_linux_sysinfo64 {
    int64_t uptime;
    uint64_t loads[3];
    uint64_t totalram;
    uint64_t freeram;
    uint64_t sharedram;
    uint64_t bufferram;
    uint64_t totalswap;
    uint64_t freeswap;
    uint16_t procs;
    uint16_t pad;
    uint64_t totalhigh;
    uint64_t freehigh;
    uint32_t mem_unit;
};

struct edge_linux_sysinfo32 {
    int32_t uptime;
    uint32_t loads[3];
    uint32_t totalram;
    uint32_t freeram;
    uint32_t sharedram;
    uint32_t bufferram;
    uint32_t totalswap;
    uint32_t freeswap;
    uint16_t procs;
    uint16_t pad;
    uint32_t totalhigh;
    uint32_t freehigh;
    uint32_t mem_unit;
    char reserved[8];
};

struct edge_linux_open_how {
    uint64_t flags;
    uint64_t mode;
    uint64_t resolve;
};

struct edge_linux_xattr_args {
    uint64_t value;
    uint32_t size;
    uint32_t flags;
};

struct edge_linux_file_attr {
    uint64_t fa_xflags;
    uint32_t fa_extsize;
    uint32_t fa_nextents;
    uint32_t fa_projid;
    uint32_t fa_cowextsize;
};

/* Variable-length getdents64 record prefix shared by every 64-bit ABI. */
struct edge_linux_dirent64 {
    uint64_t d_ino;
    int64_t d_off;
    uint16_t d_reclen;
    uint8_t d_type;
    char d_name[];
};

/* Native 64-bit layout used by the historical getdents syscall. */
struct edge_linux_dirent {
    uint64_t d_ino;
    int64_t d_off;
    uint16_t d_reclen;
    char d_name[];
};

/* Fixed prefix of Linux's variable-length struct file_handle. */
struct edge_linux_file_handle_header {
    uint32_t handle_bytes;
    int32_t handle_type;
};

struct edge_linux_clone_args {
    uint64_t flags;
    uint64_t pidfd;
    uint64_t child_tid;
    uint64_t parent_tid;
    uint64_t exit_signal;
    uint64_t stack;
    uint64_t stack_size;
    uint64_t tls;
    uint64_t set_tid;
    uint64_t set_tid_size;
    uint64_t cgroup;
};

struct edge_linux_iovec {
    union {
        uint64_t iov_base;
        uint64_t base;
    };
    union {
        uint64_t iov_len;
        uint64_t length;
    };
};

struct edge_linux_x32_iovec {
    uint32_t iov_base;
    uint32_t iov_len;
};

struct edge_linux_cmsghdr {
    union {
        uint64_t cmsg_len;
        uint64_t length;
    };
    union {
        int32_t cmsg_level;
        int32_t level;
    };
    union {
        int32_t cmsg_type;
        int32_t type;
    };
};

struct edge_linux_x32_cmsghdr {
    uint32_t cmsg_len;
    int32_t cmsg_level;
    int32_t cmsg_type;
};

struct edge_linux_msghdr {
    union {
        uint64_t msg_name;
        uint64_t name;
    };
    union {
        uint32_t msg_namelen;
        uint32_t name_length;
    };
    uint32_t __pad0;
    union {
        uint64_t msg_iov;
        uint64_t iov;
    };
    union {
        uint64_t msg_iovlen;
        uint64_t iov_length;
    };
    union {
        uint64_t msg_control;
        uint64_t control;
    };
    union {
        uint64_t msg_controllen;
        uint64_t control_length;
    };
    union {
        int32_t msg_flags;
        int32_t flags;
    };
    int32_t __pad3;
};

struct edge_linux_x32_msghdr {
    uint32_t msg_name;
    int32_t msg_namelen;
    uint32_t msg_iov;
    uint32_t msg_iovlen;
    uint32_t msg_control;
    uint32_t msg_controllen;
    int32_t msg_flags;
};

struct edge_linux_mmsghdr {
    struct edge_linux_msghdr msg_hdr;
    uint32_t msg_len;
    uint32_t __pad;
};

struct edge_linux_x32_mmsghdr {
    struct edge_linux_x32_msghdr msg_hdr;
    uint32_t msg_len;
};

struct edge_futex_waitv {
    uint64_t val;
    uint64_t uaddr;
    uint32_t flags;
    uint32_t reserved;
};

struct edge_linux_rseq_cs {
    uint32_t version;
    uint32_t flags;
    uint64_t start_ip;
    uint64_t post_commit_offset;
    uint64_t abort_ip;
} __attribute__((aligned(32)));

struct edge_linux_rseq {
    uint32_t cpu_id_start;
    uint32_t cpu_id;
    uint64_t rseq_cs;
    uint32_t flags;
    uint32_t node_id;
    uint32_t mm_cid;
    uint32_t slice_ctrl;
    uint8_t reserved;
} __attribute__((aligned(32)));

struct edge_linux_rseq_state {
    uint64_t address;
    uint32_t length;
    uint32_t signature;
    uint32_t cpu_id;
    uint32_t node_id;
    uint32_t mm_cid;
    uint64_t slice_expires_us;
    uint8_t ids_valid;
    uint8_t version;
    uint8_t slice_enabled;
    uint8_t slice_granted;
    uint8_t slice_yielded;
};

_Static_assert(sizeof(struct edge_linux_clone_args) == 88,
               "Linux clone_args ABI layout");
_Static_assert(offsetof(struct edge_linux_clone_args, pidfd) == 8,
               "Linux clone_args pidfd offset");
_Static_assert(offsetof(struct edge_linux_clone_args, child_tid) == 16,
               "Linux clone_args child_tid offset");
_Static_assert(offsetof(struct edge_linux_clone_args, parent_tid) == 24,
               "Linux clone_args parent_tid offset");
_Static_assert(offsetof(struct edge_linux_clone_args, exit_signal) == 32,
               "Linux clone_args exit_signal offset");
_Static_assert(offsetof(struct edge_linux_clone_args, stack) == 40,
               "Linux clone_args stack offset");
_Static_assert(offsetof(struct edge_linux_clone_args, tls) == 56,
               "Linux clone_args tls offset");
_Static_assert(offsetof(struct edge_linux_clone_args, cgroup) == 80,
               "Linux clone_args cgroup offset");
_Static_assert(sizeof(struct edge_linux_open_how) == 24,
               "Linux open_how ABI layout");
_Static_assert(sizeof(struct edge_linux_xattr_args) == 16,
               "Linux xattr_args ABI layout");
_Static_assert(sizeof(struct edge_linux_file_attr) == 24,
               "Linux file_attr ABI layout");
_Static_assert(offsetof(struct edge_linux_dirent64, d_name) == 19,
               "Linux dirent64 name offset");
_Static_assert(offsetof(struct edge_linux_dirent, d_name) == 18,
               "Linux native dirent name offset");
_Static_assert(sizeof(struct edge_linux_file_handle_header) == 8,
               "Linux file_handle prefix ABI layout");
_Static_assert(offsetof(struct edge_linux_file_handle_header,
                        handle_type) == 4,
               "Linux file_handle type offset");
_Static_assert(sizeof(struct edge_linux_rlimit64) == 16,
               "Linux 64-bit rlimit ABI layout");
_Static_assert(offsetof(struct edge_linux_rlimit64, rlim_max) == 8,
               "Linux 64-bit rlimit maximum offset");
_Static_assert(sizeof(struct edge_linux_rlimit32) == 8,
               "Linux compat rlimit ABI layout");
_Static_assert(sizeof(struct edge_linux_rusage64) == 144,
               "Linux 64-bit rusage ABI layout");
_Static_assert(offsetof(struct edge_linux_rusage64, ru_maxrss) == 32,
               "Linux 64-bit rusage maxrss offset");
_Static_assert(offsetof(struct edge_linux_rusage64, ru_nivcsw) == 136,
               "Linux 64-bit rusage involuntary switch offset");
_Static_assert(sizeof(struct edge_linux_rusage32) == 72,
               "Linux compat rusage ABI layout");
_Static_assert(offsetof(struct edge_linux_rusage32, ru_maxrss) == 16,
               "Linux compat rusage maxrss offset");
_Static_assert(offsetof(struct edge_linux_rusage32, ru_nivcsw) == 68,
               "Linux compat rusage involuntary switch offset");
_Static_assert(sizeof(struct edge_linux_tms64) == 32,
               "Linux 64-bit tms ABI layout");
_Static_assert(sizeof(struct edge_linux_tms32) == 16,
               "Linux compat tms ABI layout");
_Static_assert(sizeof(struct edge_linux_sysinfo64) == 112,
               "Linux 64-bit sysinfo ABI layout");
_Static_assert(sizeof(struct edge_linux_sysinfo32) == 64,
               "Linux compat sysinfo ABI layout");
_Static_assert(sizeof(struct edge_linux_statfs64) == 120,
               "Linux 64-bit statfs ABI layout");
_Static_assert(sizeof(struct edge_linux_statfs32) == 64,
               "Linux compat statfs ABI layout");
_Static_assert(sizeof(struct edge_linux_statfs64_compat) == 84,
               "Linux i386 statfs64 ABI layout");
_Static_assert(offsetof(struct edge_linux_statfs64, f_fsid) == 56,
               "Linux 64-bit statfs fsid offset");
_Static_assert(offsetof(struct edge_linux_statfs64, f_namelen) == 64,
               "Linux 64-bit statfs name length offset");
_Static_assert(offsetof(struct edge_linux_statfs64, f_flags) == 80,
               "Linux 64-bit statfs flags offset");
_Static_assert(sizeof(struct edge_linux_cap_user_header) == 8,
               "Linux capability header ABI layout");
_Static_assert(sizeof(struct edge_linux_cap_user_data) == 12,
               "Linux capability data ABI layout");
_Static_assert(offsetof(struct edge_linux_sysinfo64, loads) == 8,
               "Linux 64-bit sysinfo loads offset");
_Static_assert(offsetof(struct edge_linux_sysinfo64, totalram) == 32,
               "Linux 64-bit sysinfo total RAM offset");
_Static_assert(offsetof(struct edge_linux_sysinfo64, procs) == 80,
               "Linux 64-bit sysinfo process count offset");
_Static_assert(offsetof(struct edge_linux_sysinfo64, totalhigh) == 88,
               "Linux 64-bit sysinfo high memory offset");
_Static_assert(offsetof(struct edge_linux_sysinfo64, mem_unit) == 104,
               "Linux 64-bit sysinfo memory unit offset");
_Static_assert(sizeof(struct edge_linux_iovec) == 16,
               "Linux iovec ABI layout");
_Static_assert(sizeof(struct edge_linux_x32_iovec) == 8,
               "Linux x32 iovec ABI layout");
_Static_assert(sizeof(struct edge_linux_x32_cmsghdr) == 12,
               "Linux x32 cmsghdr ABI layout");
_Static_assert(sizeof(struct edge_linux_msghdr) == 56,
               "Linux msghdr ABI layout");
_Static_assert(sizeof(struct edge_linux_x32_msghdr) == 28,
               "Linux x32 msghdr ABI layout");
_Static_assert(offsetof(struct edge_linux_x32_msghdr, msg_iov) == 8,
               "Linux x32 msghdr iovec offset");
_Static_assert(offsetof(struct edge_linux_x32_msghdr, msg_control) == 16,
               "Linux x32 msghdr control offset");
_Static_assert(offsetof(struct edge_linux_msghdr, msg_namelen) == 8,
               "Linux msghdr name length offset");
_Static_assert(offsetof(struct edge_linux_msghdr, msg_iov) == 16,
               "Linux msghdr iovec offset");
_Static_assert(offsetof(struct edge_linux_msghdr, msg_iovlen) == 24,
               "Linux msghdr iovec count offset");
_Static_assert(offsetof(struct edge_linux_msghdr, msg_control) == 32,
               "Linux msghdr control offset");
_Static_assert(offsetof(struct edge_linux_msghdr, msg_controllen) == 40,
               "Linux msghdr control length offset");
_Static_assert(offsetof(struct edge_linux_msghdr, msg_flags) == 48,
               "Linux msghdr flags offset");
_Static_assert(sizeof(struct edge_linux_mmsghdr) == 64,
               "Linux mmsghdr ABI layout");
_Static_assert(sizeof(struct edge_linux_x32_mmsghdr) == 32,
               "Linux x32 mmsghdr ABI layout");
_Static_assert(sizeof(struct edge_futex_waitv) == 24,
               "Linux futex_waitv ABI layout");
_Static_assert(offsetof(struct edge_futex_waitv, uaddr) == 8,
               "Linux futex_waitv address offset");
_Static_assert(offsetof(struct edge_futex_waitv, flags) == 16,
               "Linux futex_waitv flags offset");
_Static_assert(sizeof(struct edge_linux_rseq_cs) == 32,
               "Linux rseq_cs ABI layout");
_Static_assert(sizeof(struct edge_linux_rseq) == 64,
               "Linux extensible rseq ABI allocation layout");
_Static_assert(offsetof(struct edge_linux_rseq, cpu_id) == 4,
               "Linux rseq cpu_id offset");
_Static_assert(offsetof(struct edge_linux_rseq, rseq_cs) == 8,
               "Linux rseq critical section offset");
_Static_assert(offsetof(struct edge_linux_rseq, flags) == 16,
               "Linux rseq flags offset");
_Static_assert(offsetof(struct edge_linux_rseq, mm_cid) == 24,
               "Linux rseq mm_cid offset");
_Static_assert(offsetof(struct edge_linux_rseq, slice_ctrl) == 28,
               "Linux rseq slice control offset");
_Static_assert(sizeof(struct edge_linux_ethtool_value) == 8,
               "Linux ethtool_value ABI layout");
_Static_assert(sizeof(struct edge_linux_ethtool_cmd) == 44,
               "Linux ethtool_cmd ABI layout");
_Static_assert(sizeof(struct edge_linux_ethtool_drvinfo) == 196,
               "Linux ethtool_drvinfo ABI layout");
_Static_assert(sizeof(struct edge_linux_ethtool_link_settings) == 48,
               "Linux ethtool_link_settings ABI layout");
_Static_assert(sizeof(struct edge_linux_packet_mreq) == 16,
               "Linux packet_mreq ABI layout");
_Static_assert(sizeof(struct edge_linux_tpacket_req) == 16,
               "Linux tpacket_req ABI layout");
_Static_assert(sizeof(struct edge_linux_tpacket_req3) == 28,
               "Linux tpacket_req3 ABI layout");
_Static_assert(sizeof(struct edge_linux_tpacket2_hdr) == 32,
               "Linux tpacket2_hdr ABI layout");
_Static_assert(offsetof(struct edge_linux_tpacket2_hdr, tp_mac) == 12,
               "Linux tpacket2_hdr MAC offset");
_Static_assert(offsetof(struct edge_linux_tpacket2_hdr, tp_sec) == 16,
               "Linux tpacket2_hdr seconds offset");
_Static_assert(offsetof(struct edge_linux_tpacket2_hdr, tp_vlan_tci) == 24,
               "Linux tpacket2_hdr VLAN offset");
_Static_assert(sizeof(struct edge_linux_sockaddr_ll) == 20,
               "Linux sockaddr_ll ABI layout");
_Static_assert(sizeof(struct edge_linux_rta_cacheinfo) == 32,
               "Linux rta_cacheinfo ABI layout");
_Static_assert(offsetof(struct edge_linux_sockaddr_ll, sll_ifindex) == 4,
               "Linux sockaddr_ll interface offset");
_Static_assert(offsetof(struct edge_linux_sockaddr_ll, sll_pkttype) == 10,
               "Linux sockaddr_ll packet type offset");
_Static_assert(offsetof(struct edge_linux_sockaddr_ll, sll_addr) == 12,
               "Linux sockaddr_ll address offset");
_Static_assert(sizeof(struct edge_linux_sockaddr) == 16,
               "Linux sockaddr ABI layout");
_Static_assert(sizeof(struct edge_linux_sockaddr_in) == 16,
               "Linux sockaddr_in ABI layout");
_Static_assert(offsetof(struct edge_linux_sockaddr_in, sin_addr) == 4,
               "Linux sockaddr_in address offset");
_Static_assert(sizeof(struct edge_linux_sockaddr_in6) == 28,
               "Linux sockaddr_in6 ABI layout");
_Static_assert(offsetof(struct edge_linux_sockaddr_in6, sin6_addr) == 8,
               "Linux sockaddr_in6 address offset");
_Static_assert(sizeof(struct edge_linux_ip_mreqn) == 12,
               "Linux ip_mreqn ABI layout");
_Static_assert(offsetof(struct edge_linux_ip_mreqn, imr_ifindex) == 8,
               "Linux ip_mreqn interface index offset");
_Static_assert(sizeof(struct edge_linux_ipv6_mreq) == 20,
               "Linux ipv6_mreq ABI layout");
_Static_assert(offsetof(struct edge_linux_ipv6_mreq, ipv6mr_ifindex) == 16,
               "Linux ipv6_mreq interface index offset");
_Static_assert(sizeof(struct edge_linux_in_pktinfo) == 12,
               "Linux in_pktinfo ABI layout");
_Static_assert(offsetof(struct edge_linux_in_pktinfo, ipi_addr) == 8,
               "Linux in_pktinfo destination offset");
_Static_assert(sizeof(struct edge_linux_in6_pktinfo) == 20,
               "Linux in6_pktinfo ABI layout");
_Static_assert(offsetof(struct edge_linux_in6_pktinfo, ipi6_ifindex) == 16,
               "Linux in6_pktinfo interface index offset");
_Static_assert(sizeof(struct edge_linux_sockaddr_un) == 110,
               "Linux sockaddr_un ABI layout");
_Static_assert(offsetof(struct edge_linux_sockaddr_un, sun_path) == 2,
               "Linux sockaddr_un path offset");
_Static_assert(sizeof(struct edge_linux_sockaddr_nl) == 12,
               "Linux sockaddr_nl ABI layout");
_Static_assert(sizeof(struct edge_linux_tpacket_stats) == 8,
               "Linux tpacket_stats ABI layout");
_Static_assert(sizeof(struct edge_linux_sock_filter) == 8,
               "Linux sock_filter ABI layout");
_Static_assert(sizeof(struct edge_linux_sock_fprog) == 16,
               "Linux sock_fprog ABI layout");
_Static_assert(sizeof(struct edge_linux_compat_sock_fprog) == 8,
               "Linux compat sock_fprog ABI layout");
_Static_assert(sizeof(struct edge_linux_linger) == 8,
               "Linux linger ABI layout");
_Static_assert(offsetof(struct edge_linux_rseq, reserved) +
                   sizeof(((struct edge_linux_rseq *)0)->reserved) ==
                   EDGE_LINUX_RSEQ_FEATURE_SIZE,
               "Linux rseq feature size");

/*
 * Copy an extensible Linux UAPI structure using copy_struct_from_user(9)
 * semantics.  Older, shorter structures are zero-extended.  Newer structures
 * are accepted only when every unknown trailing byte is zero, which lets old
 * kernels reject newly requested behavior without rejecting compatible
 * callers.
 */
int edge_linux_copy_struct_from_user(
    void *kernel_destination, uint64_t kernel_size, uint64_t minimum_size,
    uint64_t user_source, uint64_t user_size,
    edge_linux_copy_from_user_fn copy_from_user, void *copy_context);

/*
 * Apply Linux access_ok-style address-limit validation.  This deliberately
 * checks only arithmetic and the userspace address window; mapped-page and
 * permission checks belong to copy_{to,from}_user so faults become EFAULT.
 */
int edge_linux_user_range_valid(uint64_t address, uint64_t size,
                                uint64_t minimum, uint64_t limit);

void edge_linux_rseq_state_reset(struct edge_linux_rseq_state *state);
int edge_linux_rseq_register(
    struct edge_linux_rseq_state *state, uint64_t user_address,
    uint64_t user_length, uint64_t flags, uint64_t signature,
    uint32_t cpu_id, uint32_t node_id, uint32_t mm_cid,
    edge_linux_copy_to_user_fn copy_to_user, void *copy_context);
int edge_linux_rseq_prepare_user_return(
    struct edge_linux_rseq_state *state, uint64_t *instruction_pointer,
    uint32_t cpu_id, uint32_t node_id, uint32_t mm_cid,
    edge_linux_copy_from_user_fn copy_from_user,
    edge_linux_copy_to_user_fn copy_to_user, void *copy_context);
int edge_linux_rseq_slice_prctl(
    struct edge_linux_rseq_state *state, uint64_t operation,
    uint64_t value, edge_linux_copy_from_user_fn copy_from_user,
    edge_linux_copy_to_user_fn copy_to_user, void *copy_context);
int edge_linux_rseq_slice_interrupt(
    struct edge_linux_rseq_state *state, uint64_t now_us,
    edge_linux_copy_from_user_fn copy_from_user,
    edge_linux_copy_to_user_fn copy_to_user, void *copy_context);
int edge_linux_rseq_slice_syscall_enter(
    struct edge_linux_rseq_state *state, int slice_yield_syscall,
    int *force_reschedule, edge_linux_copy_from_user_fn copy_from_user,
    edge_linux_copy_to_user_fn copy_to_user, void *copy_context);
int edge_linux_rseq_slice_yield(struct edge_linux_rseq_state *state);

/*
 * Handle the architecture-independent, read-only ethtool queries used by
 * interface discovery and network diagnostics.  The caller resolves the
 * interface and supplies its real state; this helper owns Linux structure
 * layouts, command validation, and user-copy behavior for every architecture.
 */
int edge_linux_ethtool_ioctl(
    uint64_t user_data, const struct edge_linux_netdev_info *device,
    edge_linux_copy_from_user_fn copy_from_user,
    edge_linux_copy_to_user_fn copy_to_user, void *copy_context);

#endif
