/* SPDX-License-Identifier: MPL-2.0 */
/* Freestanding Linux i386 modern fixed-layout UAPI probe. */

#include <stdint.h>

#define SYS_exit 1
#define SYS_write 4
#define SYS_close 6
#define SYS_unlink 10
#define SYS_getpid 20
#define SYS_munmap 91
#define SYS_mmap2 192
#define SYS_openat 295
#define SYS_pidfd_send_signal 424
#define SYS_open_tree 428
#define SYS_move_mount 429
#define SYS_fsopen 430
#define SYS_fsconfig 431
#define SYS_fsmount 432
#define SYS_fspick 433
#define SYS_pidfd_open 434
#define SYS_clone3 435
#define SYS_pidfd_getfd 438
#define SYS_process_madvise 440
#define SYS_mount_setattr 442
#define SYS_quotactl_fd 443
#define SYS_landlock_create_ruleset 444
#define SYS_landlock_add_rule 445
#define SYS_landlock_restrict_self 446
#define SYS_memfd_secret 447
#define SYS_process_mrelease 448
#define SYS_futex_waitv 449
#define SYS_set_mempolicy_home_node 450
#define SYS_cachestat 451
#define SYS_fchmodat2 452
#define SYS_map_shadow_stack 453
#define SYS_futex_wake 454
#define SYS_futex_wait 455
#define SYS_futex_requeue 456
#define SYS_statmount 457
#define SYS_listmount 458
#define SYS_lsm_get_self_attr 459
#define SYS_lsm_set_self_attr 460
#define SYS_lsm_list_modules 461
#define SYS_mseal 462
#define SYS_setxattrat 463
#define SYS_getxattrat 464
#define SYS_listxattrat 465
#define SYS_removexattrat 466
#define SYS_open_tree_attr 467
#define SYS_file_getattr 468
#define SYS_file_setattr 469
#define SYS_listns 470
#define SYS_rseq_slice_yield 471

#define ENOSYS 38
#define AT_FDCWD (-100)
#define O_RDWR 2
#define O_CREAT 0100
#define PROT_READ 1
#define PROT_WRITE 2
#define MAP_PRIVATE 2
#define MAP_ANONYMOUS 0x20
#define OPEN_TREE_CLONE 1
#define OPEN_TREE_CLOEXEC 0x80000
#define FSOPEN_CLOEXEC 1
#define LANDLOCK_CREATE_RULESET_VERSION 1
#define MADV_DONTNEED 4
#define FUTEX_32 2
#define MNT_ID_REQ_SIZE 32

struct compat_iovec {
    uint32_t base;
    uint32_t length;
};

struct clone_args {
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

struct futex_waitv {
    uint64_t value;
    uint64_t address;
    uint32_t flags;
    uint32_t reserved;
};

struct cachestat_range {
    uint64_t offset;
    uint64_t length;
};

struct cachestat_result {
    uint64_t cached;
    uint64_t dirty;
    uint64_t writeback;
    uint64_t evicted;
    uint64_t recently_evicted;
};

struct xattr_args {
    uint64_t value;
    uint32_t size;
    uint32_t flags;
};

struct file_attr {
    uint64_t flags;
    uint32_t extent_size;
    uint32_t extent_count;
    uint32_t project_id;
    uint32_t cow_extent_size;
};

struct ns_id_req {
    uint32_t size;
    uint32_t spare;
    uint64_t namespace_id;
    uint32_t namespace_type;
    uint32_t spare2;
    uint64_t user_namespace_id;
};

struct mnt_id_req {
    uint32_t size;
    uint32_t namespace_fd;
    uint64_t mount_id;
    uint64_t parameter;
    uint64_t namespace_id;
};

struct lsm_context {
    uint64_t id;
    uint64_t flags;
    uint64_t length;
    uint64_t context_length;
};

static const char path[] = "/ia32-modern-uapi-probe";
static const char root_path[] = "/";
static const char empty_path[] = "";
static const char tmpfs_name[] = "tmpfs";
static const char xattr_name[] = "user.edgeos";
static const char xattr_value[] = "modern";
static const char pass_text[] = "IA32_MODERN_UAPI_PROBE_PASS\n";
static const char fail_prefix[] = "IA32_MODERN_UAPI_PROBE_FAIL ";
static const char newline[] = "\n";

static uint32_t futex_word = 1;
static struct futex_waitv futex_vector[2];
static struct clone_args clone_request;
static struct compat_iovec process_vector;
static struct cachestat_range cache_range;
static struct cachestat_result cache_result;
static struct xattr_args set_xattr;
static struct xattr_args get_xattr;
static struct file_attr attributes;
static struct ns_id_req namespace_request;
static struct mnt_id_req mount_request;
static struct lsm_context lsm_selector;
static uint64_t namespace_ids[4];
static uint64_t module_ids[4];
static uint32_t module_size = sizeof(module_ids);
static char xattr_buffer[32];
static char xattr_list[64];

__attribute__((naked)) static long call6(
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
    if (result == -ENOSYS) fail(name);
}

static int result_is_error(long result) {
    return (uint32_t)result >= (uint32_t)-4095;
}

__attribute__((noreturn)) void _start(void) {
    long descriptor;
    long filesystem;
    long mapping;
    long pidfd;
    long result;
    long tree;

    descriptor = call6(
        SYS_openat, AT_FDCWD, (long)path, O_CREAT | O_RDWR,
        0600, 0, 0);
    if (descriptor < 0) fail("openat");

    pidfd = call6(SYS_pidfd_open, call6(
        SYS_getpid, 0, 0, 0, 0, 0, 0), 0, 0, 0, 0, 0);
    if (pidfd < 0) fail("pidfd_open");
    if (call6(SYS_pidfd_send_signal, pidfd, 0, 0, 0, 0, 0) != 0)
        fail("pidfd_send_signal");
    expect_routed("pidfd_getfd", call6(
        SYS_pidfd_getfd, pidfd, -1, 0, 0, 0, 0));

    tree = call6(
        SYS_open_tree, AT_FDCWD, (long)root_path,
        OPEN_TREE_CLONE | OPEN_TREE_CLOEXEC, 0, 0, 0);
    expect_routed("open_tree", tree);
    if (tree >= 0) call6(SYS_close, tree, 0, 0, 0, 0, 0);
    tree = call6(
        SYS_open_tree_attr, AT_FDCWD, (long)root_path,
        OPEN_TREE_CLONE | OPEN_TREE_CLOEXEC, 0, 0, 0);
    expect_routed("open_tree_attr", tree);
    if (tree >= 0) call6(SYS_close, tree, 0, 0, 0, 0, 0);
    expect_routed("move_mount", call6(
        SYS_move_mount, AT_FDCWD, (long)root_path, AT_FDCWD,
        (long)root_path, 0x80000000u, 0));

    filesystem = call6(
        SYS_fsopen, (long)tmpfs_name, FSOPEN_CLOEXEC, 0, 0, 0, 0);
    expect_routed("fsopen", filesystem);
    expect_routed("fsconfig", call6(
        SYS_fsconfig, filesystem, 7, 0, 0, 0, 0));
    expect_routed("fsmount", call6(
        SYS_fsmount, -1, 0, 0, 0, 0, 0));
    expect_routed("fspick", call6(
        SYS_fspick, AT_FDCWD, (long)root_path, 0, 0, 0, 0));
    if (filesystem >= 0)
        call6(SYS_close, filesystem, 0, 0, 0, 0, 0);

    clone_request.exit_signal = 17;
    result = call6(
        SYS_clone3, (long)&clone_request, sizeof(clone_request),
        0, 0, 0, 0);
    if (result == -ENOSYS) fail("clone3");
    if (result == 0)
        call6(SYS_exit, 0, 0, 0, 0, 0, 0);

    mapping = call6(
        SYS_mmap2, 0, 4096, PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (result_is_error(mapping)) fail("mmap2");
    *(volatile uint32_t *)(uintptr_t)mapping = 1;
    process_vector.base = (uint32_t)mapping;
    process_vector.length = 4096;
    expect_routed("process_madvise", call6(
        SYS_process_madvise, pidfd, (long)&process_vector, 1,
        MADV_DONTNEED, 0, 0));
    expect_routed("mount_setattr", call6(
        SYS_mount_setattr, AT_FDCWD, (long)root_path,
        0x80000000u, 0, 0, 0));
    (void)call6(SYS_quotactl_fd, -1, 0, 0, 0, 0, 0);

    result = call6(
        SYS_landlock_create_ruleset, 0, 0,
        LANDLOCK_CREATE_RULESET_VERSION, 0, 0, 0);
    (void)result;
    (void)call6(SYS_landlock_add_rule, -1, 1, 0, 0, 0, 0);
    (void)call6(SYS_landlock_restrict_self, -1, 0, 0, 0, 0, 0);

    result = call6(SYS_memfd_secret, 0, 0, 0, 0, 0, 0);
    if (result >= 0) call6(SYS_close, result, 0, 0, 0, 0, 0);
    expect_routed("process_mrelease", call6(
        SYS_process_mrelease, pidfd, 1, 0, 0, 0, 0));

    futex_vector[0].value = 0;
    futex_vector[0].address = (uint32_t)(uintptr_t)&futex_word;
    futex_vector[0].flags = FUTEX_32;
    futex_vector[1] = futex_vector[0];
    expect_routed("futex_waitv", call6(
        SYS_futex_waitv, (long)futex_vector, 1, 0, 0, 1, 0));
    expect_routed("futex_wake", call6(
        SYS_futex_wake, (long)&futex_word, 0xffffffffu, 1,
        FUTEX_32, 0, 0));
    expect_routed("futex_wait", call6(
        SYS_futex_wait, (long)&futex_word, 0, 0xffffffffu,
        FUTEX_32, 0, 1));
    expect_routed("futex_requeue", call6(
        SYS_futex_requeue, (long)futex_vector, 0, 0, 0, 0, 0));
    expect_routed("set_mempolicy_home_node", call6(
        SYS_set_mempolicy_home_node, mapping, 4096, 0, 0, 0, 0));

    cache_range.length = 4096;
    (void)call6(SYS_cachestat, descriptor, (long)&cache_range,
                (long)&cache_result, 0, 0, 0);
    if (call6(
            SYS_fchmodat2, AT_FDCWD, (long)path, 0640,
            0, 0, 0) != 0)
        fail("fchmodat2");
    if (call6(SYS_map_shadow_stack, 0, 0, 0, 0, 0, 0) != -ENOSYS)
        fail("map_shadow_stack");

    mount_request.size = MNT_ID_REQ_SIZE;
    expect_routed("statmount", call6(
        SYS_statmount, (long)&mount_request, 0, 0, 0, 0, 0));
    expect_routed("listmount", call6(
        SYS_listmount, (long)&mount_request, 0, 0, 0, 0, 0));
    (void)call6(SYS_lsm_get_self_attr, 1, (long)&lsm_selector,
                (long)&module_size, 0, 0, 0);
    (void)call6(SYS_lsm_set_self_attr, 0, 0, 0, 0, 0, 0);
    (void)call6(SYS_lsm_list_modules, (long)module_ids,
                (long)&module_size, 0, 0, 0, 0);
    expect_routed("mseal", call6(
        SYS_mseal, mapping, 4096, 0, 0, 0, 0));

    set_xattr.value = (uint32_t)(uintptr_t)xattr_value;
    set_xattr.size = sizeof(xattr_value) - 1u;
    result = call6(
        SYS_setxattrat, AT_FDCWD, (long)path, 0,
        (long)xattr_name, (long)&set_xattr, sizeof(set_xattr));
    expect_routed("setxattrat", result);
    get_xattr.value = (uint32_t)(uintptr_t)xattr_buffer;
    get_xattr.size = sizeof(xattr_buffer);
    expect_routed("getxattrat", call6(
        SYS_getxattrat, AT_FDCWD, (long)path, 0,
        (long)xattr_name, (long)&get_xattr, sizeof(get_xattr)));
    expect_routed("listxattrat", call6(
        SYS_listxattrat, AT_FDCWD, (long)path, 0,
        (long)xattr_list, sizeof(xattr_list), 0));
    expect_routed("removexattrat", call6(
        SYS_removexattrat, AT_FDCWD, (long)path, 0,
        (long)xattr_name, 0, 0));

    expect_routed("file_getattr", call6(
        SYS_file_getattr, AT_FDCWD, (long)path,
        (long)&attributes, sizeof(attributes), 0, 0));
    expect_routed("file_setattr", call6(
        SYS_file_setattr, AT_FDCWD, (long)path,
        (long)&attributes, sizeof(attributes), 0, 0));

    namespace_request.size = sizeof(namespace_request);
    expect_routed("listns", call6(
        SYS_listns, (long)&namespace_request, (long)namespace_ids,
        4, 0, 0, 0));
    (void)call6(SYS_rseq_slice_yield, 0, 0, 0, 0, 0, 0);

    call6(SYS_close, pidfd, 0, 0, 0, 0, 0);
    call6(SYS_close, descriptor, 0, 0, 0, 0, 0);
    call6(SYS_munmap, mapping, 4096, 0, 0, 0, 0);
    call6(SYS_unlink, (long)path, 0, 0, 0, 0, 0);
    print_text(pass_text);
    call6(SYS_exit, 0, 0, 0, 0, 0, 0);
    __builtin_unreachable();
}
