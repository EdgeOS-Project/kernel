/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS Linux SysV semaphore ABI test.
 * Copyright (c) EdgeOS Contributors.
 */

#include <stdint.h>

#if defined(__x86_64__)
#define SYS_write 1
#define SYS_semget 64
#define SYS_semop 65
#define SYS_semctl 66
#define SYS_semtimedop 220
#define SYS_getpid 39
#define SYS_exit 60
#elif defined(__aarch64__)
#define SYS_write 64
#define SYS_exit 93
#define SYS_getpid 172
#define SYS_semget 190
#define SYS_semctl 191
#define SYS_semtimedop 192
#define SYS_semop 193
#else
#error "sysv_sem_abi_probe requires a Linux 64-bit architecture"
#endif

#define E2BIG 7
#define EAGAIN 11
#define EFAULT 14
#define EEXIST 17
#define ENOENT 2
#define EINVAL 22
#define ERANGE 34

#define IPC_CREAT 01000
#define IPC_EXCL 02000
#define IPC_NOWAIT 04000
#define IPC_RMID 0
#define IPC_SET 1
#define IPC_STAT 2
#define GETPID 11
#define GETVAL 12
#define GETALL 13
#define GETNCNT 14
#define GETZCNT 15
#define SETVAL 16
#define SETALL 17

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

#if defined(__x86_64__)
struct linux_semid_ds64 {
    struct linux_ipc_perm64 sem_perm;
    int64_t sem_otime;
    uint64_t unused1;
    int64_t sem_ctime;
    uint64_t unused2;
    uint64_t sem_nsems;
    uint64_t unused3;
    uint64_t unused4;
};
_Static_assert(sizeof(struct linux_semid_ds64) == 104,
               "Linux x86_64 semid_ds ABI size");
#else
struct linux_semid_ds64 {
    struct linux_ipc_perm64 sem_perm;
    int64_t sem_otime;
    int64_t sem_ctime;
    uint64_t sem_nsems;
    uint64_t unused3;
    uint64_t unused4;
};
_Static_assert(sizeof(struct linux_semid_ds64) == 88,
               "Linux AArch64 semid_ds ABI size");
#endif

struct linux_sembuf {
    uint16_t sem_num;
    int16_t sem_op;
    int16_t sem_flg;
};

struct linux_timespec64 {
    int64_t tv_sec;
    int64_t tv_nsec;
};

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

void *memset(void *destination, int value, unsigned long length) {
    unsigned char *bytes = destination;
    while (length) bytes[--length] = (unsigned char)value;
    return destination;
}

static unsigned long string_length(const char *text) {
    unsigned long length = 0;
    while (text[length]) ++length;
    return length;
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

static int run_tests(void) {
    struct linux_semid_ds64 information = {0};
    struct linux_sembuf operation;
    struct linux_timespec64 zero_timeout = {0, 0};
    uint16_t values[3] = {2, 3, 4};
    uint16_t observed[3] = {0, 0, 0};
    long pid = raw_syscall6(SYS_getpid, 0, 0, 0, 0, 0, 0);
    int32_t key = (int32_t)(0x53000000u | ((uint32_t)pid & 0xffffu));
    long identifier;
    int failures = 0;

    failures += expect_result("zero semaphore count",
        raw_syscall6(SYS_semget, 0, 0, IPC_CREAT | 0600, 0, 0, 0),
        -EINVAL);
    failures += expect_result("missing named set",
        raw_syscall6(SYS_semget, key, 1, 0, 0, 0, 0), -ENOENT);
    identifier = raw_syscall6(
        SYS_semget, key, 3, IPC_CREAT | IPC_EXCL | 0600, 0, 0, 0);
    failures += expect_true("create set", identifier >= 0);
    if (identifier < 0) return failures;
    failures += expect_result("exclusive existing set",
        raw_syscall6(SYS_semget, key, 3,
                     IPC_CREAT | IPC_EXCL | 0600, 0, 0, 0), -EEXIST);
    failures += expect_result("initial value",
        raw_syscall6(SYS_semctl, identifier, 0, GETVAL, 0, 0, 0), 0);
    failures += expect_result("set value",
        raw_syscall6(SYS_semctl, identifier, 0, SETVAL, 2, 0, 0), 0);
    failures += expect_result("read value",
        raw_syscall6(SYS_semctl, identifier, 0, GETVAL, 0, 0, 0), 2);

    operation.sem_num = 0;
    operation.sem_op = -1;
    operation.sem_flg = 0;
    failures += expect_result("atomic decrement",
        raw_syscall6(SYS_semop, identifier, (long)&operation, 1, 0, 0, 0), 0);
    failures += expect_result("decremented value",
        raw_syscall6(SYS_semctl, identifier, 0, GETVAL, 0, 0, 0), 1);
    operation.sem_op = -2;
    operation.sem_flg = IPC_NOWAIT;
    failures += expect_result("nonblocking shortage",
        raw_syscall6(SYS_semop, identifier, (long)&operation, 1, 0, 0, 0),
        -EAGAIN);
    operation.sem_flg = 0;
    failures += expect_result("zero timeout shortage",
        raw_syscall6(SYS_semtimedop, identifier, (long)&operation, 1,
                     (long)&zero_timeout, 0, 0), -EAGAIN);

    failures += expect_result("set all",
        raw_syscall6(SYS_semctl, identifier, 0, SETALL,
                     (long)values, 0, 0), 0);
    failures += expect_result("get all",
        raw_syscall6(SYS_semctl, identifier, 0, GETALL,
                     (long)observed, 0, 0), 0);
    failures += expect_true("all values round trip",
        observed[0] == 2 && observed[1] == 3 && observed[2] == 4);
    failures += expect_result("set value overflow",
        raw_syscall6(SYS_semctl, identifier, 0, SETVAL, 32768, 0, 0),
        -ERANGE);
    failures += expect_result("stat null",
        raw_syscall6(SYS_semctl, identifier, 0, IPC_STAT, 0, 0, 0),
        -EFAULT);
    failures += expect_result("stat",
        raw_syscall6(SYS_semctl, identifier, 0, IPC_STAT,
                     (long)&information, 0, 0), 0);
    failures += expect_true("stat metadata",
        information.sem_perm.key == key && information.sem_nsems == 3 &&
        (information.sem_perm.mode & 0777u) == 0600);
    failures += expect_result("last operation pid",
        raw_syscall6(SYS_semctl, identifier, 0, GETPID, 0, 0, 0), pid);
    failures += expect_result("remove",
        raw_syscall6(SYS_semctl, identifier, 0, IPC_RMID, 0, 0, 0), 0);
    failures += expect_result("removed identifier",
        raw_syscall6(SYS_semctl, identifier, 0, GETVAL, 0, 0, 0),
        -EINVAL);
    return failures;
}

void _start(void) {
    int failures = run_tests();
    if (failures) {
        print_text("sysv-sem-abi: FAIL failures=");
        print_number(failures);
        print_text("\n");
    } else {
        print_text("sysv-sem-abi: PASS\n");
    }
    (void)raw_syscall6(SYS_exit, failures ? 1 : 0, 0, 0, 0, 0, 0);
    for (;;) { }
}
