/* SPDX-License-Identifier: MPL-2.0 */
/* Linux SysV message queue ABI probe for x86_64 and AArch64. */

#include <stdint.h>

#if defined(__x86_64__)
#define SYS_write 1
#define SYS_getpid 39
#define SYS_msgget 68
#define SYS_msgsnd 69
#define SYS_msgrcv 70
#define SYS_msgctl 71
#define SYS_exit 60
#elif defined(__aarch64__)
#define SYS_write 64
#define SYS_exit 93
#define SYS_getpid 172
#define SYS_msgget 186
#define SYS_msgctl 187
#define SYS_msgrcv 188
#define SYS_msgsnd 189
#else
#error "sysv_msg_abi_probe requires a Linux 64-bit architecture"
#endif

#define E2BIG 7
#define EEXIST 17
#define EINVAL 22
#define ENOENT 2
#define ENOMSG 42

#define IPC_CREAT 01000
#define IPC_EXCL 02000
#define IPC_NOWAIT 04000
#define IPC_RMID 0
#define IPC_STAT 2
#define MSG_NOERROR 010000

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

struct linux_msqid_ds64 {
    struct linux_ipc_perm64 msg_perm;
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

struct test_message {
    int64_t type;
    char text[16];
};

_Static_assert(sizeof(struct linux_msqid_ds64) == 120,
               "Linux 64-bit msqid_ds ABI size");

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
    struct linux_msqid_ds64 information = {0};
    struct test_message sent = {.type = 5, .text = "hello"};
    struct test_message received = {0};
    long pid = raw_syscall6(SYS_getpid, 0, 0, 0, 0, 0, 0);
    int32_t key = (int32_t)(0x4d000000u | ((uint32_t)pid & 0xffffu));
    long identifier;
    int failures = 0;

    failures += expect_result("missing named queue",
        raw_syscall6(SYS_msgget, key, 0, 0, 0, 0, 0), -ENOENT);
    identifier = raw_syscall6(
        SYS_msgget, key, IPC_CREAT | IPC_EXCL | 0600, 0, 0, 0, 0);
    failures += expect_true("create queue", identifier >= 0);
    if (identifier < 0) return failures;
    failures += expect_result("exclusive existing queue",
        raw_syscall6(SYS_msgget, key,
                     IPC_CREAT | IPC_EXCL | 0600, 0, 0, 0, 0), -EEXIST);

    sent.type = 0;
    failures += expect_result("invalid message type",
        raw_syscall6(SYS_msgsnd, identifier, (long)&sent, 5,
                     IPC_NOWAIT, 0, 0), -EINVAL);
    sent.type = 5;
    failures += expect_result("send message",
        raw_syscall6(SYS_msgsnd, identifier, (long)&sent, 5,
                     IPC_NOWAIT, 0, 0), 0);
    failures += expect_result("missing type",
        raw_syscall6(SYS_msgrcv, identifier, (long)&received,
                     sizeof(received.text), 7, IPC_NOWAIT, 0), -ENOMSG);
    failures += expect_result("small receive buffer",
        raw_syscall6(SYS_msgrcv, identifier, (long)&received,
                     3, 5, IPC_NOWAIT, 0), -E2BIG);
    memset(&received, 0, sizeof(received));
    failures += expect_result("truncated receive",
        raw_syscall6(SYS_msgrcv, identifier, (long)&received,
                     3, 5, IPC_NOWAIT | MSG_NOERROR, 0), 3);
    failures += expect_true("receive contents",
        received.type == 5 && received.text[0] == 'h' &&
        received.text[1] == 'e' && received.text[2] == 'l');

    failures += expect_result("stat null",
        raw_syscall6(SYS_msgctl, identifier, IPC_STAT, 0, 0, 0, 0),
        -14);
    failures += expect_result("stat queue",
        raw_syscall6(SYS_msgctl, identifier, IPC_STAT,
                     (long)&information, 0, 0, 0), 0);
    failures += expect_true("stat metadata",
        information.msg_perm.key == key && information.msg_qnum == 0 &&
        information.msg_lspid == pid && information.msg_lrpid == pid &&
        (information.msg_perm.mode & 0777u) == 0600);
    failures += expect_result("remove queue",
        raw_syscall6(SYS_msgctl, identifier, IPC_RMID, 0, 0, 0, 0), 0);
    failures += expect_result("removed identifier",
        raw_syscall6(SYS_msgsnd, identifier, (long)&sent, 5,
                     IPC_NOWAIT, 0, 0), -EINVAL);
    return failures;
}

void _start(void) {
    int failures = run_tests();
    if (failures) {
        print_text("sysv-msg-abi: FAIL failures=");
        print_number(failures);
        print_text("\n");
    } else {
        print_text("sysv-msg-abi: PASS\n");
    }
    raw_syscall6(SYS_exit, failures ? 1 : 0, 0, 0, 0, 0, 0);
    for (;;) {}
}
