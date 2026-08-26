/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS Linux SysV shared-memory ABI test.
 * Copyright (c) EdgeOS Contributors.
 */

#include <stdint.h>

#if defined(__x86_64__)
#define SYS_write 1
#define SYS_shmget 29
#define SYS_shmat 30
#define SYS_shmctl 31
#define SYS_fork 57
#define SYS_exit 60
#define SYS_wait4 61
#define SYS_shmdt 67
#define SYS_getpid 39
#define SYS_setuid 105
#elif defined(__aarch64__)
#define SYS_write 64
#define SYS_exit 93
#define SYS_setuid 146
#define SYS_getpid 172
#define SYS_shmget 194
#define SYS_shmctl 195
#define SYS_shmat 196
#define SYS_shmdt 197
#define SYS_clone 220
#define SYS_wait4 260
#else
#error "sysv_shm_abi_probe requires a Linux 64-bit architecture"
#endif

#define EACCES 13
#define EFAULT 14
#define EEXIST 17
#define ENOENT 2
#define EINVAL 22

#define IPC_CREAT 01000
#define IPC_EXCL 02000
#define IPC_RMID 0
#define IPC_SET 1
#define IPC_STAT 2
#define SHM_DEST 01000
#define SHM_REMAP 040000
#define SIGCHLD 17

struct linux_ipc_perm64 {
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

struct linux_shmid_ds64 {
    struct linux_ipc_perm64 shm_perm;
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

_Static_assert(sizeof(struct linux_shmid_ds64) == 112,
               "Linux shmid_ds ABI size");

static long raw_syscall6(long number, long a0, long a1, long a2,
                         long a3, long a4, long a5) {
#if defined(__x86_64__)
    register long r10 __asm__("r10") = a3;
    register long r8 __asm__("r8") = a4;
    register long r9 __asm__("r9") = a5;
    long result;
    __asm__ volatile("syscall"
                     : "=a"(result)
                     : "a"(number), "D"(a0), "S"(a1), "d"(a2),
                       "r"(r10), "r"(r8), "r"(r9)
                     : "rcx", "r11", "memory");
    return result;
#else
    register long x8 __asm__("x8") = number;
    register long x0 __asm__("x0") = a0;
    register long x1 __asm__("x1") = a1;
    register long x2 __asm__("x2") = a2;
    register long x3 __asm__("x3") = a3;
    register long x4 __asm__("x4") = a4;
    register long x5 __asm__("x5") = a5;
    __asm__ volatile("svc #0"
                     : "+r"(x0)
                     : "r"(x8), "r"(x1), "r"(x2), "r"(x3),
                       "r"(x4), "r"(x5)
                     : "memory", "cc");
    return x0;
#endif
}

static unsigned long string_length(const char *text) {
    unsigned long length = 0;
    while (text[length]) ++length;
    return length;
}

static void bytes_zero(void *destination, unsigned long size) {
    unsigned char *bytes = destination;
    while (size) bytes[--size] = 0;
}

static void print_text(const char *text) {
    (void)raw_syscall6(SYS_write, 1, (long)text,
                       (long)string_length(text), 0, 0, 0);
}

static void print_number(long value) {
    char digits[24];
    unsigned long magnitude;
    int position = (int)sizeof(digits);
    if (value < 0) {
        print_text("-");
        magnitude = (unsigned long)(-(value + 1)) + 1u;
    } else {
        magnitude = (unsigned long)value;
    }
    do {
        digits[--position] = (char)('0' + magnitude % 10u);
        magnitude /= 10u;
    } while (magnitude);
    (void)raw_syscall6(SYS_write, 1, (long)&digits[position],
                       (long)(sizeof(digits) - (unsigned long)position),
                       0, 0, 0);
}

static int expect_result(const char *name, long actual, long expected) {
    if (actual == expected) return 0;
    print_text("FAIL ");
    print_text(name);
    print_text(" actual=");
    print_number(actual);
    print_text(" expected=");
    print_number(expected);
    print_text("\n");
    return 1;
}

static int expect_true(const char *name, int condition) {
    if (condition) return 0;
    print_text("FAIL ");
    print_text(name);
    print_text("\n");
    return 1;
}

static long create_child(void) {
#if defined(__x86_64__)
    return raw_syscall6(SYS_fork, 0, 0, 0, 0, 0, 0);
#else
    return raw_syscall6(SYS_clone, SIGCHLD, 0, 0, 0, 0, 0);
#endif
}

static int run_tests(void) {
    struct linux_shmid_ds64 information;
    volatile uint64_t *shared;
    volatile uint64_t *second;
    volatile uint64_t *middle;
    long pid = raw_syscall6(SYS_getpid, 0, 0, 0, 0, 0, 0);
    int32_t key = (int32_t)(0x45000000u | ((uint32_t)pid & 0xffffu));
    long identifier;
    long replacement_identifier;
    long partial_identifier;
    long child;
    int status = 0;
    int failures = 0;

    failures += expect_result("zero size",
        raw_syscall6(SYS_shmget, 0, 0, IPC_CREAT | 0600, 0, 0, 0),
        -EINVAL);
    failures += expect_result("missing named segment",
        raw_syscall6(SYS_shmget, key, 4096, 0, 0, 0, 0), -ENOENT);
    failures += expect_result("invalid attach identifier",
        raw_syscall6(SYS_shmat, -1, 0, 0, 0, 0, 0), -EINVAL);
    failures += expect_result("invalid detach address",
        raw_syscall6(SYS_shmdt, 0, 0, 0, 0, 0, 0), -EINVAL);

    identifier = raw_syscall6(
        SYS_shmget, key, 8193, IPC_CREAT | IPC_EXCL | 0600, 0, 0, 0);
    failures += expect_true("create named segment", identifier >= 0);
    if (identifier < 0) return failures;
    failures += expect_result("exclusive existing segment",
        raw_syscall6(SYS_shmget, key, 8193,
                     IPC_CREAT | IPC_EXCL | 0600, 0, 0, 0), -EEXIST);
    failures += expect_result("oversized existing request",
        raw_syscall6(SYS_shmget, key, 8194, 0, 0, 0, 0), -EINVAL);
    failures += expect_result("stat null buffer",
        raw_syscall6(SYS_shmctl, identifier, IPC_STAT, 0, 0, 0, 0),
        -EFAULT);

    bytes_zero(&information, sizeof(information));
    failures += expect_result("initial stat",
        raw_syscall6(SYS_shmctl, identifier, IPC_STAT,
                     (long)&information, 0, 0, 0), 0);
    failures += expect_true("initial metadata",
        information.shm_perm.key == key && information.shm_segsz == 8193 &&
        (information.shm_perm.mode & 0777u) == 0600 &&
        information.shm_cpid == pid && information.shm_nattch == 0);

    shared = (volatile uint64_t *)raw_syscall6(
        SYS_shmat, identifier, 0, 0, 0, 0, 0);
    failures += expect_true("attach writable", (long)shared > 0);
    if ((long)shared <= 0) {
        (void)raw_syscall6(SYS_shmctl, identifier, IPC_RMID, 0, 0, 0, 0);
        return failures;
    }
    shared[0] = 0x1122334455667788ull;
    shared[1024] = 0xaabbccddeeff0011ull;
    bytes_zero(&information, sizeof(information));
    failures += expect_result("attached stat",
        raw_syscall6(SYS_shmctl, identifier, IPC_STAT,
                     (long)&information, 0, 0, 0), 0);
    failures += expect_true("attachment count one",
                            information.shm_nattch == 1 &&
                            information.shm_atime > 0);

    child = create_child();
    failures += expect_true("fork child", child >= 0);
    if (child == 0) {
        int child_failures = 0;
        long owned_identifier;
        bytes_zero(&information, sizeof(information));
        child_failures += expect_result("child stat",
            raw_syscall6(SYS_shmctl, identifier, IPC_STAT,
                         (long)&information, 0, 0, 0), 0);
        child_failures += expect_true("fork increments attachments",
                                      information.shm_nattch == 2);
        child_failures += expect_true("fork preserves mapping",
            shared[0] == 0x1122334455667788ull &&
            shared[1024] == 0xaabbccddeeff0011ull);
        shared[0] = 0x8877665544332211ull;
        child_failures += expect_result("child detach inherited mapping",
            raw_syscall6(SYS_shmdt, (long)shared, 0, 0, 0, 0, 0), 0);
        child_failures += expect_result("child drop privilege",
            raw_syscall6(SYS_setuid, 65534, 0, 0, 0, 0, 0), 0);
        child_failures += expect_result("named lookup permission",
            raw_syscall6(SYS_shmget, key, 8193, 0666, 0, 0, 0), -EACCES);
        child_failures += expect_result("attach permission",
            raw_syscall6(SYS_shmat, identifier, 0, 0, 0, 0, 0), -EACCES);
        owned_identifier = raw_syscall6(
            SYS_shmget, 0, 4096, IPC_CREAT | 0600, 0, 0, 0);
        child_failures += expect_true("unprivileged owner create",
                                      owned_identifier >= 0);
        if (owned_identifier >= 0) {
            bytes_zero(&information, sizeof(information));
            child_failures += expect_result("unprivileged owner stat",
                raw_syscall6(SYS_shmctl, owned_identifier, IPC_STAT,
                             (long)&information, 0, 0, 0), 0);
            information.shm_perm.gid = 12345;
            child_failures += expect_result("owner updates group",
                raw_syscall6(SYS_shmctl, owned_identifier, IPC_SET,
                             (long)&information, 0, 0, 0), 0);
            bytes_zero(&information, sizeof(information));
            child_failures += expect_result("owner updated group stat",
                raw_syscall6(SYS_shmctl, owned_identifier, IPC_STAT,
                             (long)&information, 0, 0, 0), 0);
            child_failures += expect_true("owner group persisted",
                                          information.shm_perm.gid == 12345);
            child_failures += expect_result("owner removes segment",
                raw_syscall6(SYS_shmctl, owned_identifier, IPC_RMID,
                             0, 0, 0, 0), 0);
        }
        raw_syscall6(SYS_exit, child_failures ? 1 : 0, 0, 0, 0, 0, 0);
        for (;;) { }
    }
    if (child > 0) {
        failures += expect_result("wait child",
            raw_syscall6(SYS_wait4, child, (long)&status, 0, 0, 0, 0), child);
        failures += expect_true("child passed", status == 0);
        failures += expect_true("shared child write",
                                shared[0] == 0x8877665544332211ull);
        bytes_zero(&information, sizeof(information));
        failures += expect_result("post-fork stat",
            raw_syscall6(SYS_shmctl, identifier, IPC_STAT,
                         (long)&information, 0, 0, 0), 0);
        failures += expect_true("child detach decrements attachments",
                                information.shm_nattch == 1);
    }

    replacement_identifier = raw_syscall6(
        SYS_shmget, 0, 8193, IPC_CREAT | 0600, 0, 0, 0);
    failures += expect_true("create replacement segment",
                            replacement_identifier >= 0);
    if (replacement_identifier >= 0) {
        second = (volatile uint64_t *)raw_syscall6(
            SYS_shmat, replacement_identifier, (long)shared, SHM_REMAP,
            0, 0, 0);
        failures += expect_true("replace complete attachment",
                                second == shared);
        if (second == shared) {
            second[0] = 0x55aa55aa55aa55aaull;
            bytes_zero(&information, sizeof(information));
            failures += expect_result("replaced source stat",
                raw_syscall6(SYS_shmctl, identifier, IPC_STAT,
                             (long)&information, 0, 0, 0), 0);
            failures += expect_true("replacement retires source attachment",
                                    information.shm_nattch == 0);
            bytes_zero(&information, sizeof(information));
            failures += expect_result("replacement stat",
                raw_syscall6(SYS_shmctl, replacement_identifier, IPC_STAT,
                             (long)&information, 0, 0, 0), 0);
            failures += expect_true("replacement attachment counted",
                                    information.shm_nattch == 1);
            second = (volatile uint64_t *)raw_syscall6(
                SYS_shmat, identifier, (long)shared, SHM_REMAP, 0, 0, 0);
            failures += expect_true("restore source attachment",
                                    second == shared);
            if (second == shared) {
                failures += expect_true("source pages survive replacement",
                    shared[0] == 0x8877665544332211ull &&
                    shared[1024] == 0xaabbccddeeff0011ull);
            }
        }
        failures += expect_result("remove replacement segment",
            raw_syscall6(SYS_shmctl, replacement_identifier, IPC_RMID,
                         0, 0, 0, 0), 0);
    }

    partial_identifier = raw_syscall6(
        SYS_shmget, 0, 4096, IPC_CREAT | 0600, 0, 0, 0);
    failures += expect_true("create partial replacement segment",
                            partial_identifier >= 0);
    if (partial_identifier >= 0) {
        middle = (volatile uint64_t *)raw_syscall6(
            SYS_shmat, partial_identifier, (long)shared + 4096,
            SHM_REMAP, 0, 0, 0);
        failures += expect_true("replace middle of attachment",
            middle == (volatile uint64_t *)((long)shared + 4096));
        if (middle == (volatile uint64_t *)((long)shared + 4096)) {
            middle[0] = 0x123456789abcdef0ull;
            bytes_zero(&information, sizeof(information));
            failures += expect_result("partial source stat",
                raw_syscall6(SYS_shmctl, identifier, IPC_STAT,
                             (long)&information, 0, 0, 0), 0);
            failures += expect_true("partial source counts both fragments",
                                    information.shm_nattch == 2);
            status = 0;
            child = create_child();
            failures += expect_true("fork fragmented mappings", child >= 0);
            if (child == 0) {
                int fragment_failures = 0;
                bytes_zero(&information, sizeof(information));
                fragment_failures += expect_result("forked source stat",
                    raw_syscall6(SYS_shmctl, identifier, IPC_STAT,
                                 (long)&information, 0, 0, 0), 0);
                fragment_failures += expect_true("fork clones both fragments",
                                                 information.shm_nattch == 4);
                bytes_zero(&information, sizeof(information));
                fragment_failures += expect_result("forked replacement stat",
                    raw_syscall6(SYS_shmctl, partial_identifier, IPC_STAT,
                                 (long)&information, 0, 0, 0), 0);
                fragment_failures += expect_true("fork clones replacement",
                                                 information.shm_nattch == 2);
                raw_syscall6(SYS_exit, fragment_failures ? 1 : 0,
                             0, 0, 0, 0, 0);
                for (;;) { }
            }
            if (child > 0) {
                failures += expect_result("wait fragmented child",
                    raw_syscall6(SYS_wait4, child, (long)&status,
                                 0, 0, 0, 0), child);
                failures += expect_true("fragmented child passed", status == 0);
                bytes_zero(&information, sizeof(information));
                failures += expect_result("post-fork fragmented stat",
                    raw_syscall6(SYS_shmctl, identifier, IPC_STAT,
                                 (long)&information, 0, 0, 0), 0);
                failures += expect_true("fragment child exit decrements",
                                        information.shm_nattch == 2);
            }
            failures += expect_result("detach fragmented source",
                raw_syscall6(SYS_shmdt, (long)shared, 0, 0, 0, 0, 0), 0);
            failures += expect_true("replacement survives source detach",
                                    middle[0] == 0x123456789abcdef0ull);
            bytes_zero(&information, sizeof(information));
            failures += expect_result("detached source stat",
                raw_syscall6(SYS_shmctl, identifier, IPC_STAT,
                             (long)&information, 0, 0, 0), 0);
            failures += expect_true("fragmented source detached once",
                                    information.shm_nattch == 0);
            failures += expect_result("detach middle replacement",
                raw_syscall6(SYS_shmdt, (long)middle, 0, 0, 0, 0, 0), 0);
            shared = (volatile uint64_t *)raw_syscall6(
                SYS_shmat, identifier, 0, 0, 0, 0, 0);
            failures += expect_true("reattach fragmented source",
                                    (long)shared > 0);
            if ((long)shared > 0)
                failures += expect_true("source data survives partial remap",
                    shared[0] == 0x8877665544332211ull &&
                    shared[1024] == 0xaabbccddeeff0011ull);
        }
        failures += expect_result("remove partial replacement segment",
            raw_syscall6(SYS_shmctl, partial_identifier, IPC_RMID,
                         0, 0, 0, 0), 0);
    }

    information.shm_perm.uid = 0;
    information.shm_perm.gid = 0;
    information.shm_perm.mode = 0640;
    failures += expect_result("set metadata",
        raw_syscall6(SYS_shmctl, identifier, IPC_SET,
                     (long)&information, 0, 0, 0), 0);
    bytes_zero(&information, sizeof(information));
    failures += expect_result("stat updated metadata",
        raw_syscall6(SYS_shmctl, identifier, IPC_STAT,
                     (long)&information, 0, 0, 0), 0);
    failures += expect_true("updated mode",
                            (information.shm_perm.mode & 0777u) == 0640);

    failures += expect_result("mark removed",
        raw_syscall6(SYS_shmctl, identifier, IPC_RMID, 0, 0, 0, 0), 0);
    bytes_zero(&information, sizeof(information));
    failures += expect_result("stat removed while attached",
        raw_syscall6(SYS_shmctl, identifier, IPC_STAT,
                     (long)&information, 0, 0, 0), 0);
    failures += expect_true("removed state visible",
        (information.shm_perm.mode & SHM_DEST) &&
        information.shm_nattch == 1);
    second = (volatile uint64_t *)raw_syscall6(
        SYS_shmat, identifier, 0, 0, 0, 0, 0);
    failures += expect_true("Linux attach after remove", (long)second > 0);
    if ((long)second > 0) {
        failures += expect_true("second attachment data",
                                second[0] == shared[0]);
        failures += expect_result("detach second attachment",
            raw_syscall6(SYS_shmdt, (long)second, 0, 0, 0, 0, 0), 0);
    }
    failures += expect_result("detach final attachment",
        raw_syscall6(SYS_shmdt, (long)shared, 0, 0, 0, 0, 0), 0);
    failures += expect_result("removed identifier destroyed",
        raw_syscall6(SYS_shmctl, identifier, IPC_STAT,
                     (long)&information, 0, 0, 0), -EINVAL);
    return failures;
}

#if defined(__x86_64__)
__attribute__((force_align_arg_pointer))
#endif
void _start(void) {
    int failures = run_tests();
    if (failures) {
        print_text("sysv-shm-abi: FAIL failures=");
        print_number(failures);
        print_text("\n");
    } else {
        print_text("sysv-shm-abi: PASS\n");
    }
    raw_syscall6(SYS_exit, failures ? 1 : 0, 0, 0, 0, 0, 0);
    for (;;) { }
}
