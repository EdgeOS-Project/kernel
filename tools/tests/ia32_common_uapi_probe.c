/* SPDX-License-Identifier: MPL-2.0 */
/* Freestanding Linux i386 fixed-layout and scalar UAPI probe. */

#include <stdint.h>

#define SYS_exit 1
#define SYS_read 3
#define SYS_write 4
#define SYS_open 5
#define SYS_close 6
#define SYS_link 9
#define SYS_unlink 10
#define SYS_chmod 15
#define SYS_lseek 19
#define SYS_mount 21
#define SYS_getpid 20
#define SYS_sync 36
#define SYS_rename 38
#define SYS_mkdir 39
#define SYS_rmdir 40
#define SYS_pipe 42
#define SYS_umount2 52
#define SYS_setpgid 57
#define SYS_umask 60
#define SYS_chroot 61
#define SYS_getpgrp 65
#define SYS_setsid 66
#define SYS_sethostname 74
#define SYS_symlink 83
#define SYS_swapon 87
#define SYS_reboot 88
#define SYS_munmap 91
#define SYS_truncate 92
#define SYS_ftruncate 93
#define SYS_fchmod 94
#define SYS_getpriority 96
#define SYS_setpriority 97
#define SYS_syslog 103
#define SYS_vhangup 111
#define SYS_swapoff 115
#define SYS_fsync 118
#define SYS_setdomainname 121
#define SYS_uname 122
#define SYS_init_module 128
#define SYS_delete_module 129
#define SYS_getpgid 132
#define SYS_fchdir 133
#define SYS_sysfs 135
#define SYS_personality 136
#define SYS_flock 143
#define SYS_msync 144
#define SYS_getsid 147
#define SYS_fdatasync 148
#define SYS_mlock 150
#define SYS_munlock 151
#define SYS_mlockall 152
#define SYS_munlockall 153
#define SYS_sched_setparam 154
#define SYS_sched_getparam 155
#define SYS_sched_setscheduler 156
#define SYS_sched_getscheduler 157
#define SYS_sched_get_priority_max 159
#define SYS_sched_get_priority_min 160
#define SYS_capget 184
#define SYS_capset 185
#define SYS_mmap2 192
#define SYS_getgroups32 205
#define SYS_pivot_root 217
#define SYS_getdents64 220
#define SYS_setxattr 226
#define SYS_getxattr 229
#define SYS_listxattr 232
#define SYS_removexattr 235
#define SYS_tkill 238
#define SYS_sched_setaffinity 241
#define SYS_sched_getaffinity 242
#define SYS_remap_file_pages 257
#define SYS_tgkill 270
#define SYS_add_key 286
#define SYS_request_key 287
#define SYS_keyctl 288
#define SYS_ioprio_set 289
#define SYS_ioprio_get 290
#define SYS_inotify_init 291
#define SYS_inotify_add_watch 292
#define SYS_inotify_rm_watch 293
#define SYS_mkdirat 296
#define SYS_mknodat 297
#define SYS_fchownat 298
#define SYS_unlinkat 301
#define SYS_renameat 302
#define SYS_linkat 303
#define SYS_symlinkat 304
#define SYS_fchmodat 306
#define SYS_unshare 310
#define SYS_set_robust_list 311
#define SYS_get_robust_list 312
#define SYS_splice 313
#define SYS_tee 315
#define SYS_getcpu 318
#define SYS_signalfd 321
#define SYS_timerfd_create 322
#define SYS_signalfd4 327
#define SYS_inotify_init1 332
#define SYS_perf_event_open 336
#define SYS_fanotify_init 338
#define SYS_fanotify_mark 339
#define SYS_prlimit64 340
#define SYS_name_to_handle_at 341
#define SYS_open_by_handle_at 342
#define SYS_syncfs 344
#define SYS_setns 346
#define SYS_process_vm_readv 347
#define SYS_process_vm_writev 348
#define SYS_kcmp 349
#define SYS_finit_module 350
#define SYS_sched_setattr 351
#define SYS_sched_getattr 352
#define SYS_renameat2 353
#define SYS_seccomp 354
#define SYS_memfd_create 356
#define SYS_bpf 357
#define SYS_userfaultfd 374
#define SYS_mlock2 376
#define SYS_copy_file_range 377
#define SYS_pkey_mprotect 380
#define SYS_pkey_alloc 381
#define SYS_pkey_free 382

#define ENOSYS 38
#define EOPNOTSUPP 95
#define AT_FDCWD (-100)
#define O_RDONLY 0
#define O_RDWR 2
#define O_CREAT 0100
#define O_TRUNC 01000
#define O_DIRECTORY 0200000
#define O_CLOEXEC 02000000
#define IN_MODIFY 2
#define LOCK_EX 2
#define LOCK_UN 8
#define SCHED_OTHER 0
#define PRIO_PROCESS 0
#define SEEK_SET 0
#define SIGUSR1 10
#define SIG_BLOCK 0
#define SYSLOG_ACTION_SIZE_BUFFER 10
#define SECCOMP_GET_ACTION_AVAIL 2
#define SECCOMP_RET_ALLOW 0x7fff0000u
#define RLIMIT_NOFILE 7
#define MCL_CURRENT 1
#define MCL_FUTURE 2
#define MFD_CLOEXEC 1
#define PROT_READ 1
#define MAP_SHARED 1
#define MAP_PRIVATE 2
#define MAP_ANONYMOUS 0x20
#define PROT_WRITE 2

struct compat_iovec {
    uint32_t base;
    uint32_t length;
};

struct sched_param {
    int32_t priority;
};

struct sched_attr {
    uint32_t size;
    uint32_t policy;
    uint64_t flags;
    int32_t nice;
    uint32_t priority;
    uint64_t runtime;
    uint64_t deadline;
    uint64_t period;
    uint32_t util_min;
    uint32_t util_max;
    int32_t latency_nice;
};

struct capability_header {
    uint32_t version;
    int32_t pid;
};

struct capability_data {
    uint32_t effective;
    uint32_t permitted;
    uint32_t inheritable;
};

struct rlimit64 {
    uint64_t current;
    uint64_t maximum;
};

static const char file_a[] = "/tmp/ia32-common-a";
static const char file_b[] = "/tmp/ia32-common-b";
static const char file_c[] = "/tmp/ia32-common-c";
static const char directory[] = "/tmp/ia32-common-dir";
static const char link_path[] = "/tmp/ia32-common-link";
static const char payload[] = "common-uapi";
static const char xattr_name[] = "user.edgeos";
static const char xattr_value[] = "ia32";
static const char empty[] = "";
static const char pass_text[] = "IA32_COMMON_UAPI_PROBE_PASS\n";
static const char fail_prefix[] = "IA32_COMMON_UAPI_PROBE_FAIL ";
static const char newline[] = "\n";

static uint8_t page[4096] __attribute__((aligned(4096)));
static char buffer[4096];
static int32_t pipes[2];
static int32_t second_pipes[2];
static uint32_t affinity[32];
static uint32_t groups[32];
static uint32_t cpu;
static uint32_t node;
static uint32_t signal_mask[2];
static uint32_t robust_head;
static uint32_t robust_length;
static struct sched_param parameter;
static struct sched_attr attributes;
static struct capability_header capability_header = {0x20080522u, 0};
static struct capability_data capability_data[2];
static struct rlimit64 descriptor_limit;
static struct compat_iovec local_vector;
static struct compat_iovec remote_vector;
static uint32_t seccomp_action = SECCOMP_RET_ALLOW;
static char uts_name[390];
static int running_on_edgeos;

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
    call6(SYS_write, 1, (long)text, text_length(text), 0, 0, 0);
}

static void fail(const char *name) {
    print_text(fail_prefix);
    print_text(name);
    print_text(newline);
    call6(SYS_exit, 1, 0, 0, 0, 0, 0);
    __builtin_unreachable();
}

static void expect_routed(const char *name, long result) {
    if (result == -ENOSYS && running_on_edgeos) fail(name);
}

static void expect_zero(const char *name, long result) {
    if (result != 0) fail(name);
}

static void expect_zero_or_enosys(const char *name, long result) {
    if (result != 0 && result != -ENOSYS) fail(name);
}

static int bytes_equal(const char *left, const char *right, uint32_t length) {
    for (uint32_t index = 0; index < length; ++index)
        if (left[index] != right[index]) return 0;
    return 1;
}

static int result_is_error(long result) {
    return (uint32_t)result >= (uint32_t)-4095;
}

static void close_descriptor(long descriptor) {
    if (descriptor >= 0) call6(SYS_close, descriptor, 0, 0, 0, 0, 0);
}

__attribute__((noreturn)) void _start(void) {
    long descriptor;
    long directory_fd;
    long mapping;
    long result;
    long second;

    if (call6(SYS_uname, uts_name, 0, 0, 0, 0, 0) != 0)
        fail("uname");
    running_on_edgeos = uts_name[0] == 'E' && uts_name[1] == 'd' &&
                        uts_name[2] == 'g' && uts_name[3] == 'e' &&
                        uts_name[4] == 'O' && uts_name[5] == 'S';

    result = call6(SYS_mkdir, "/tmp", 01777, 0, 0, 0, 0);
    if (result != 0 && result != -17) fail("tmp-directory");
    call6(SYS_unlink, file_a, 0, 0, 0, 0, 0);
    call6(SYS_unlink, file_b, 0, 0, 0, 0, 0);
    call6(SYS_unlink, file_c, 0, 0, 0, 0, 0);
    call6(SYS_unlink, link_path, 0, 0, 0, 0, 0);
    call6(SYS_rmdir, directory, 0, 0, 0, 0, 0);

    descriptor = call6(
        SYS_open, file_a, O_CREAT | O_TRUNC | O_RDWR, 0600, 0, 0, 0);
    if (descriptor < 0) fail("open");
    if (call6(SYS_write, descriptor, payload, sizeof(payload) - 1u,
              0, 0, 0) != (long)(sizeof(payload) - 1u))
        fail("write");
    expect_zero("fsync", call6(SYS_fsync, descriptor, 0, 0, 0, 0, 0));
    expect_zero("fdatasync", call6(
        SYS_fdatasync, descriptor, 0, 0, 0, 0, 0));
    expect_zero("fchmod", call6(
        SYS_fchmod, descriptor, 0640, 0, 0, 0, 0));
    expect_zero("ftruncate", call6(
        SYS_ftruncate, descriptor, sizeof(payload) - 1u, 0, 0, 0, 0));
    if (call6(SYS_lseek, descriptor, 0, SEEK_SET, 0, 0, 0) != 0)
        fail("lseek");
    if (call6(SYS_read, descriptor, buffer, sizeof(payload) - 1u,
              0, 0, 0) != (long)(sizeof(payload) - 1u) ||
        !bytes_equal(buffer, payload, sizeof(payload) - 1u))
        fail("file-data");
    expect_zero_or_enosys("flock-lock", call6(
        SYS_flock, descriptor, LOCK_EX, 0, 0, 0, 0));
    expect_zero_or_enosys("flock-unlock", call6(
        SYS_flock, descriptor, LOCK_UN, 0, 0, 0, 0));
    result = call6(
        SYS_setxattr, file_a, xattr_name, xattr_value,
        sizeof(xattr_value) - 1u, 0, 0);
    if (result == 0) {
        if (call6(SYS_getxattr, file_a, xattr_name, buffer,
                  sizeof(buffer), 0, 0) !=
                (long)(sizeof(xattr_value) - 1u))
            fail("getxattr");
        if (call6(SYS_listxattr, file_a, buffer,
                  sizeof(buffer), 0, 0, 0) <= 0)
            fail("listxattr");
        expect_zero("removexattr", call6(
            SYS_removexattr, file_a, xattr_name, 0, 0, 0, 0));
    } else if (result != -ENOSYS && result != -EOPNOTSUPP) {
        fail("setxattr");
    }
    close_descriptor(descriptor);

    expect_zero("chmod", call6(SYS_chmod, file_a, 0600, 0, 0, 0, 0));
    expect_zero("truncate", call6(
        SYS_truncate, file_a, sizeof(payload) - 1u, 0, 0, 0, 0));
    expect_zero("link", call6(SYS_link, file_a, file_b, 0, 0, 0, 0));
    expect_zero("rename", call6(SYS_rename, file_b, file_c, 0, 0, 0, 0));
    expect_zero("symlink", call6(
        SYS_symlink, file_a, link_path, 0, 0, 0, 0));
    expect_zero("mkdir", call6(SYS_mkdir, directory, 0700, 0, 0, 0, 0));
    expect_zero("mkdirat", call6(
        SYS_mkdirat, AT_FDCWD, "/tmp/ia32-common-dir/at", 0700, 0, 0, 0));
    expect_zero("unlinkat-directory", call6(
        SYS_unlinkat, AT_FDCWD, "/tmp/ia32-common-dir/at", 0x200,
        0, 0, 0));

    directory_fd = call6(SYS_open, "/", O_RDONLY | O_DIRECTORY, 0, 0, 0, 0);
    if (directory_fd < 0 ||
        call6(SYS_getdents64, directory_fd, buffer, sizeof(buffer),
              0, 0, 0) <= 0)
        fail("getdents64");
    expect_zero("fchdir", call6(
        SYS_fchdir, directory_fd, 0, 0, 0, 0, 0));

    if (call6(SYS_pipe, pipes, 0, 0, 0, 0, 0) != 0 ||
        call6(SYS_pipe, second_pipes, 0, 0, 0, 0, 0) != 0)
        fail("pipe");
    if (call6(SYS_write, pipes[1], payload, sizeof(payload) - 1u,
              0, 0, 0) != (long)(sizeof(payload) - 1u))
        fail("pipe-write");
    if (call6(SYS_tee, pipes[0], second_pipes[1], sizeof(payload) - 1u,
              0, 0, 0) != (long)(sizeof(payload) - 1u))
        fail("tee");
    if (call6(SYS_read, second_pipes[0], buffer, sizeof(payload) - 1u,
              0, 0, 0) != (long)(sizeof(payload) - 1u) ||
        !bytes_equal(buffer, payload, sizeof(payload) - 1u))
        fail("tee-data");
    descriptor = call6(SYS_open, file_b, O_CREAT | O_TRUNC | O_RDWR,
                       0600, 0, 0, 0);
    if (descriptor < 0 ||
        call6(SYS_splice, pipes[0], 0, descriptor, 0,
              sizeof(payload) - 1u, 0) != (long)(sizeof(payload) - 1u))
        fail("splice");
    expect_zero("syncfs", call6(SYS_syncfs, descriptor, 0, 0, 0, 0, 0));
    close_descriptor(descriptor);

    descriptor = call6(SYS_inotify_init1, O_CLOEXEC, 0, 0, 0, 0, 0);
    if (descriptor >= 0) {
        result = call6(SYS_inotify_add_watch, descriptor, file_a,
                       IN_MODIFY, 0, 0, 0);
        if (result < 0) fail("inotify_add_watch");
        expect_zero("inotify_rm_watch", call6(
            SYS_inotify_rm_watch, descriptor, result, 0, 0, 0, 0));
        close_descriptor(descriptor);
    } else if (descriptor != -ENOSYS) {
        fail("inotify_init1");
    }
    descriptor = call6(SYS_inotify_init, 0, 0, 0, 0, 0, 0);
    if (descriptor >= 0)
        close_descriptor(descriptor);
    else if (descriptor != -ENOSYS)
        fail("inotify_init");

    parameter.priority = 0;
    expect_zero("sched_getparam", call6(
        SYS_sched_getparam, 0, &parameter, 0, 0, 0, 0));
    expect_zero("sched_setparam", call6(
        SYS_sched_setparam, 0, &parameter, 0, 0, 0, 0));
    if (call6(SYS_sched_getscheduler, 0, 0, 0, 0, 0, 0) < 0)
        fail("sched_getscheduler");
    expect_zero("sched_setscheduler", call6(
        SYS_sched_setscheduler, 0, SCHED_OTHER, &parameter, 0, 0, 0));
    if (call6(SYS_sched_get_priority_max, SCHED_OTHER, 0, 0, 0, 0, 0) < 0 ||
        call6(SYS_sched_get_priority_min, SCHED_OTHER, 0, 0, 0, 0, 0) < 0)
        fail("sched-priority");
    result = call6(SYS_sched_getaffinity, 0, sizeof(affinity), affinity,
                   0, 0, 0);
    if (result <= 0) fail("sched_getaffinity");
    expect_zero("sched_setaffinity", call6(
        SYS_sched_setaffinity, 0, result, affinity, 0, 0, 0));
    attributes.size = sizeof(attributes);
    if (call6(SYS_sched_getattr, 0, &attributes, sizeof(attributes),
              0, 0, 0) != 0)
        fail("sched_getattr");
    expect_zero("sched_setattr", call6(
        SYS_sched_setattr, 0, &attributes, 0, 0, 0, 0));
    if (call6(SYS_getpgrp, 0, 0, 0, 0, 0, 0) < 0)
        fail("getpgrp");
    if (call6(SYS_getpgid, 0, 0, 0, 0, 0, 0) < 0)
        fail("getpgid");
    if (call6(SYS_getsid, 0, 0, 0, 0, 0, 0) < 0)
        fail("getsid");
    expect_zero("setpgid", call6(SYS_setpgid, 0, 0, 0, 0, 0, 0));
    if (call6(SYS_getcpu, &cpu, &node, 0, 0, 0, 0) != 0)
        fail("getcpu");
    result = call6(SYS_getgroups32, 32, groups, 0, 0, 0, 0);
    if (result < 0 && result != -ENOSYS)
        fail("getgroups32");

    expect_zero_or_enosys("capget", call6(
        SYS_capget, &capability_header, capability_data, 0, 0, 0, 0));
    result = call6(SYS_prlimit64, 0, RLIMIT_NOFILE, 0,
                   &descriptor_limit, 0, 0);
    if (result != 0 || descriptor_limit.current == 0)
        fail("prlimit64");
    if (call6(SYS_personality, -1, 0, 0, 0, 0, 0) < 0)
        fail("personality");
    if (call6(SYS_getpriority, PRIO_PROCESS, 0, 0, 0, 0, 0) < 0)
        fail("getpriority");
    expect_zero("setpriority", call6(
        SYS_setpriority, PRIO_PROCESS, 0, 0, 0, 0, 0));
    result = call6(SYS_ioprio_get, 1, 0, 0, 0, 0, 0);
    if (result < 0 && result != -ENOSYS)
        fail("ioprio_get");
    result = call6(SYS_ioprio_set, 1, 0, 0, 0, 0, 0);
    if (result != 0 && result != -ENOSYS)
        fail("ioprio_set");

    mapping = call6(SYS_mmap2, 0, sizeof(page), PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (result_is_error(mapping)) fail("mlock-mmap");
    *(volatile uint32_t *)(uintptr_t)mapping = 0x32c0ffeeu;
    expect_zero("mlock", call6(
        SYS_mlock, mapping, sizeof(page), 0, 0, 0, 0));
    expect_zero("munlock", call6(
        SYS_munlock, mapping, sizeof(page), 0, 0, 0, 0));
    expect_routed("mlock2", call6(
        SYS_mlock2, mapping, sizeof(page), 0, 0, 0, 0));
    expect_routed("mlockall", call6(
        SYS_mlockall, MCL_CURRENT, 0, 0, 0, 0, 0));
    expect_routed("munlockall", call6(
        SYS_munlockall, 0, 0, 0, 0, 0, 0));
    expect_routed("msync", call6(
        SYS_msync, mapping, sizeof(page), 4, 0, 0, 0));
    expect_zero("mlock-munmap", call6(
        SYS_munmap, mapping, sizeof(page), 0, 0, 0, 0));

    descriptor = call6(SYS_memfd_create, "ia32-common", MFD_CLOEXEC,
                       0, 0, 0, 0);
    if (descriptor < 0) fail("memfd_create");
    if (call6(SYS_write, descriptor, payload, sizeof(payload) - 1u,
              0, 0, 0) != (long)(sizeof(payload) - 1u))
        fail("memfd-write");
    close_descriptor(descriptor);
    descriptor = call6(SYS_open, file_c, O_RDONLY, 0, 0, 0, 0);
    second = call6(SYS_open, file_b, O_CREAT | O_TRUNC | O_RDWR,
                   0600, 0, 0, 0);
    if (descriptor < 0 || second < 0) fail("copy-open");
    if (call6(SYS_copy_file_range, descriptor, 0, second, 0,
              sizeof(payload) - 1u, 0) < 0)
        fail("copy_file_range");
    close_descriptor(second);
    close_descriptor(descriptor);

    local_vector.base = (uint32_t)(uintptr_t)payload;
    local_vector.length = sizeof(payload) - 1u;
    remote_vector.base = (uint32_t)(uintptr_t)buffer;
    remote_vector.length = sizeof(payload) - 1u;
    result = call6(SYS_process_vm_readv, call6(
        SYS_getpid, 0, 0, 0, 0, 0, 0), &remote_vector, 1,
        &local_vector, 1, 0);
    if (result != (long)(sizeof(payload) - 1u) ||
        !bytes_equal(buffer, payload, sizeof(payload) - 1u))
        fail("process_vm_readv");

    robust_head = 0;
    robust_length = 0;
    expect_zero("get_robust_list", call6(
        SYS_get_robust_list, 0, &robust_head, &robust_length, 0, 0, 0));
    if (robust_length == 0) fail("robust-length");
    expect_routed("set_robust_list", call6(
        SYS_set_robust_list, page, robust_length, 0, 0, 0, 0));

    signal_mask[0] = 1u << (SIGUSR1 - 1);
    descriptor = call6(SYS_signalfd4, -1, signal_mask,
                       sizeof(signal_mask), O_CLOEXEC, 0, 0);
    if (descriptor >= 0)
        close_descriptor(descriptor);
    else if (descriptor != -ENOSYS)
        fail("signalfd4");
    descriptor = call6(SYS_timerfd_create, 1, O_CLOEXEC, 0, 0, 0, 0);
    if (descriptor >= 0)
        close_descriptor(descriptor);
    else if (descriptor != -ENOSYS)
        fail("timerfd_create");

    expect_routed("syslog", call6(
        SYS_syslog, SYSLOG_ACTION_SIZE_BUFFER, 0, 0, 0, 0, 0));
    expect_routed("seccomp", call6(
        SYS_seccomp, SECCOMP_GET_ACTION_AVAIL, 0, &seccomp_action,
        0, 0, 0));
    expect_routed("perf_event_open", call6(
        SYS_perf_event_open, 0, 0, -1, -1, 0, 0));
    expect_routed("fanotify_init", call6(
        SYS_fanotify_init, 0xffffffffu, 0, 0, 0, 0, 0));
    expect_routed("userfaultfd", call6(
        SYS_userfaultfd, 0xffffffffu, 0, 0, 0, 0, 0));
    expect_routed("bpf", call6(SYS_bpf, -1, 0, 0, 0, 0, 0));
    expect_routed("pkey_alloc", call6(
        SYS_pkey_alloc, 0xffffffffu, 0, 0, 0, 0, 0));
    expect_routed("add_key", call6(
        SYS_add_key, empty, empty, 0, 0, -1, 0));
    expect_routed("request_key", call6(
        SYS_request_key, empty, empty, 0, -1, 0, 0));
    expect_routed("keyctl", call6(SYS_keyctl, -1, 0, 0, 0, 0, 0));
    expect_routed("unshare", call6(
        SYS_unshare, 0x80000000u, 0, 0, 0, 0, 0));
    expect_routed("setns", call6(SYS_setns, -1, 0, 0, 0, 0, 0));
    expect_routed("kcmp", call6(
        SYS_kcmp, call6(SYS_getpid, 0, 0, 0, 0, 0, 0),
        call6(SYS_getpid, 0, 0, 0, 0, 0, 0), 0, -1, -1, 0));
    expect_routed("name_to_handle_at", call6(
        SYS_name_to_handle_at, AT_FDCWD, file_a, 0, 0, 0, 0));
    expect_routed("open_by_handle_at", call6(
        SYS_open_by_handle_at, -1, 0, 0, 0, 0, 0));
    expect_routed("init_module", call6(
        SYS_init_module, 0, 0, empty, 0, 0, 0));
    expect_routed("finit_module", call6(
        SYS_finit_module, -1, empty, 0, 0, 0, 0));
    expect_routed("delete_module", call6(
        SYS_delete_module, empty, 0, 0, 0, 0, 0));
    expect_routed("mount", call6(
        SYS_mount, empty, empty, empty, 0xffffffffu, 0, 0));
    expect_routed("umount2", call6(
        SYS_umount2, empty, 0xffffffffu, 0, 0, 0, 0));
    expect_routed("pivot_root", call6(
        SYS_pivot_root, empty, empty, 0, 0, 0, 0));
    expect_routed("swapon", call6(
        SYS_swapon, empty, 0xffffffffu, 0, 0, 0, 0));
    expect_routed("swapoff", call6(
        SYS_swapoff, empty, 0, 0, 0, 0, 0));
    expect_routed("reboot", call6(
        SYS_reboot, 0, 0, 0, 0, 0, 0));
    expect_routed("sethostname", call6(
        SYS_sethostname, 0, 1, 0, 0, 0, 0));
    expect_routed("setdomainname", call6(
        SYS_setdomainname, 0, 1, 0, 0, 0, 0));
    expect_routed("chroot", call6(SYS_chroot, 0, 0, 0, 0, 0, 0));
    expect_routed("vhangup", call6(SYS_vhangup, 0, 0, 0, 0, 0, 0));
    expect_routed("sysfs", call6(SYS_sysfs, -1, 0, 0, 0, 0, 0));

    call6(SYS_sync, 0, 0, 0, 0, 0, 0);
    close_descriptor(directory_fd);
    for (uint32_t index = 0; index < 2; ++index) {
        close_descriptor(pipes[index]);
        close_descriptor(second_pipes[index]);
    }
    call6(SYS_unlink, file_a, 0, 0, 0, 0, 0);
    call6(SYS_unlink, file_b, 0, 0, 0, 0, 0);
    call6(SYS_unlink, file_c, 0, 0, 0, 0, 0);
    call6(SYS_unlink, link_path, 0, 0, 0, 0, 0);
    call6(SYS_rmdir, directory, 0, 0, 0, 0, 0);

    print_text(pass_text);
    call6(SYS_exit, 0, 0, 0, 0, 0, 0);
    __builtin_unreachable();
}
