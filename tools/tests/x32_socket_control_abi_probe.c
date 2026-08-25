/* SPDX-License-Identifier: MPL-2.0 */
/* Linux x32 ancillary socket data compatibility ABI probe. */

#include <stdint.h>

#if !defined(__x86_64__)
#error "x32_socket_control_abi_probe requires x86_64"
#endif

#define START_ATTRIBUTES __attribute__((noreturn, force_align_arg_pointer))

#define X32_SYSCALL_BIT UINT64_C(0x40000000)
#define SYS_read 0
#define SYS_write 1
#define SYS_close 3
#define SYS_getpid 39
#define SYS_socketpair 53
#define SYS_setsockopt 54
#define SYS_exit 60
#define SYS_getuid 102
#define SYS_getgid 104
#define SYS_pipe2 293
#define X32_SYS_sendmsg 518
#define X32_SYS_recvmsg 519

#define AF_UNIX 1
#define SOCK_STREAM 1
#define SOCK_CLOEXEC 02000000
#define SOL_SOCKET 1
#define SCM_RIGHTS 1
#define SCM_CREDENTIALS 2
#define SO_PASSCRED 16

struct x32_iovec {
    uint32_t base;
    uint32_t length;
};

struct x32_msghdr {
    uint32_t name;
    int32_t name_length;
    uint32_t iov;
    uint32_t iov_length;
    uint32_t control;
    uint32_t control_length;
    int32_t flags;
};

struct x32_cmsghdr {
    uint32_t length;
    int32_t level;
    int32_t type;
};

struct linux_ucred {
    int32_t pid;
    uint32_t uid;
    uint32_t gid;
};

static int sockets[2];
static int pipe_descriptors[2];
static char rights_payload = 'R';
static char credentials_payload = 'C';
static char receive_payload;
static struct x32_iovec send_vector;
static struct x32_iovec receive_vector;
static struct x32_msghdr send_header;
static struct x32_msghdr receive_header;
static uint8_t send_control[32] __attribute__((aligned(8)));
static uint8_t receive_control[64] __attribute__((aligned(8)));

static long raw_syscall6(long number, long a0, long a1, long a2,
                         long a3, long a4, long a5) {
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
}

static long x32_syscall3(long number, long a0, long a1, long a2) {
    return raw_syscall6(
        (long)(X32_SYSCALL_BIT | (uint64_t)number),
        a0, a1, a2, 0, 0, 0);
}

static unsigned long text_length(const char *text) {
    unsigned long length = 0;
    while (text[length]) ++length;
    return length;
}

static void print_text(const char *text) {
    (void)raw_syscall6(
        SYS_write, 1, (long)text, (long)text_length(text), 0, 0, 0);
}

static void print_number(long value) {
    char output[24];
    unsigned long magnitude;
    unsigned long count = 0;

    if (value < 0) {
        print_text("-");
        magnitude = (unsigned long)(-(value + 1)) + 1u;
    } else {
        magnitude = (unsigned long)value;
    }
    do {
        output[count++] = (char)('0' + magnitude % 10u);
        magnitude /= 10u;
    } while (magnitude);
    for (unsigned long left = 0, right = count - 1u; left < right;
         ++left, --right) {
        char temporary = output[left];
        output[left] = output[right];
        output[right] = temporary;
    }
    (void)raw_syscall6(SYS_write, 1, (long)output, (long)count, 0, 0, 0);
}

static int expect_result(const char *name, long actual, long expected) {
    if (actual == expected) return 0;
    print_text("FAIL ");
    print_text(name);
    print_text(" expected=");
    print_number(expected);
    print_text(" actual=");
    print_number(actual);
    print_text("\n");
    return 1;
}

static uint32_t pointer32(const void *pointer) {
    return (uint32_t)(uintptr_t)pointer;
}

static void clear_bytes(void *memory, uint32_t length) {
    uint8_t *bytes = memory;
    for (uint32_t index = 0; index < length; ++index) bytes[index] = 0;
}

static void prepare_message(
    struct x32_msghdr *header, struct x32_iovec *vector,
    char *payload, uint8_t *control, uint32_t control_length) {
    clear_bytes(header, sizeof(*header));
    vector->base = pointer32(payload);
    vector->length = 1;
    header->iov = pointer32(vector);
    header->iov_length = 1;
    header->control = control ? pointer32(control) : 0;
    header->control_length = control_length;
}

START_ATTRIBUTES void _start(void) {
    struct x32_cmsghdr *control_header;
    struct linux_ucred *credentials;
    int failures = 0;
    int received_descriptor;
    int pass_credentials = 1;
    char pipe_value = 'P';
    char received_pipe_value = 0;

    failures += expect_result(
        "socketpair", raw_syscall6(
            SYS_socketpair, AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0,
            (long)sockets, 0, 0), 0);
    failures += expect_result(
        "pipe2", raw_syscall6(
            SYS_pipe2, (long)pipe_descriptors, SOCK_CLOEXEC, 0, 0, 0, 0), 0);
    if (failures) goto finish;

    clear_bytes(send_control, sizeof(send_control));
    control_header = (struct x32_cmsghdr *)send_control;
    control_header->length = sizeof(*control_header) + sizeof(int32_t);
    control_header->level = SOL_SOCKET;
    control_header->type = SCM_RIGHTS;
    *(int32_t *)(send_control + sizeof(*control_header)) = pipe_descriptors[0];
    prepare_message(
        &send_header, &send_vector, &rights_payload,
        send_control, control_header->length);
    failures += expect_result(
        "send-rights", x32_syscall3(
            X32_SYS_sendmsg, sockets[0], (long)&send_header, 0), 1);

    clear_bytes(receive_control, sizeof(receive_control));
    receive_payload = 0;
    prepare_message(
        &receive_header, &receive_vector, &receive_payload,
        receive_control, sizeof(receive_control));
    failures += expect_result(
        "recv-rights", x32_syscall3(
            X32_SYS_recvmsg, sockets[1], (long)&receive_header, 0), 1);
    control_header = (struct x32_cmsghdr *)receive_control;
    failures += expect_result("rights-payload", receive_payload, 'R');
    failures += expect_result(
        "rights-control-length", receive_header.control_length, 16);
    failures += expect_result("rights-cmsg-length", control_header->length, 16);
    failures += expect_result("rights-level", control_header->level, SOL_SOCKET);
    failures += expect_result("rights-type", control_header->type, SCM_RIGHTS);
    received_descriptor =
        *(int32_t *)(receive_control + sizeof(*control_header));
    failures += expect_result(
        "write-pipe", raw_syscall6(
            SYS_write, pipe_descriptors[1], (long)&pipe_value, 1, 0, 0, 0), 1);
    failures += expect_result(
        "read-received-fd", raw_syscall6(
            SYS_read, received_descriptor, (long)&received_pipe_value,
            1, 0, 0, 0), 1);
    failures += expect_result(
        "received-fd-payload", received_pipe_value, 'P');

    failures += expect_result(
        "setsockopt-passcred", raw_syscall6(
            SYS_setsockopt, sockets[1], SOL_SOCKET, SO_PASSCRED,
            (long)&pass_credentials, sizeof(pass_credentials), 0), 0);
    prepare_message(
        &send_header, &send_vector, &credentials_payload, 0, 0);
    failures += expect_result(
        "send-credentials", x32_syscall3(
            X32_SYS_sendmsg, sockets[0], (long)&send_header, 0), 1);

    clear_bytes(receive_control, sizeof(receive_control));
    receive_payload = 0;
    prepare_message(
        &receive_header, &receive_vector, &receive_payload,
        receive_control, sizeof(receive_control));
    failures += expect_result(
        "recv-credentials", x32_syscall3(
            X32_SYS_recvmsg, sockets[1], (long)&receive_header, 0), 1);
    control_header = (struct x32_cmsghdr *)receive_control;
    credentials = (struct linux_ucred *)(
        receive_control + sizeof(*control_header));
    failures += expect_result("credentials-payload", receive_payload, 'C');
    failures += expect_result(
        "credentials-control-length", receive_header.control_length, 24);
    failures += expect_result(
        "credentials-cmsg-length", control_header->length, 24);
    failures += expect_result(
        "credentials-level", control_header->level, SOL_SOCKET);
    failures += expect_result(
        "credentials-type", control_header->type, SCM_CREDENTIALS);
    failures += expect_result(
        "credentials-pid", credentials->pid,
        raw_syscall6(SYS_getpid, 0, 0, 0, 0, 0, 0));
    failures += expect_result(
        "credentials-uid", credentials->uid,
        raw_syscall6(SYS_getuid, 0, 0, 0, 0, 0, 0));
    failures += expect_result(
        "credentials-gid", credentials->gid,
        raw_syscall6(SYS_getgid, 0, 0, 0, 0, 0, 0));

    (void)raw_syscall6(SYS_close, received_descriptor, 0, 0, 0, 0, 0);
    (void)raw_syscall6(SYS_close, pipe_descriptors[0], 0, 0, 0, 0, 0);
    (void)raw_syscall6(SYS_close, pipe_descriptors[1], 0, 0, 0, 0, 0);
    (void)raw_syscall6(SYS_close, sockets[0], 0, 0, 0, 0, 0);
    (void)raw_syscall6(SYS_close, sockets[1], 0, 0, 0, 0, 0);
finish:
    if (failures) {
        print_text("X32_SOCKET_CONTROL_ABI_PROBE_FAIL count=");
        print_number(failures);
        print_text("\n");
        raw_syscall6(SYS_exit, 1, 0, 0, 0, 0, 0);
    }
    print_text("X32_SOCKET_CONTROL_ABI_PROBE_PASS\n");
    raw_syscall6(SYS_exit, 0, 0, 0, 0, 0, 0);
    __builtin_unreachable();
}
