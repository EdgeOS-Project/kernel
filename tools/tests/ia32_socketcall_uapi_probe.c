/* SPDX-License-Identifier: MPL-2.0 */
/* Freestanding Linux i386 socketcall UAPI probe. */

#include <stdint.h>

#define SYS_exit 1
#define SYS_write 4
#define SYS_close 6
#define SYS_socketcall 102

#define SOCKETCALL_SOCKET 1
#define SOCKETCALL_GETSOCKNAME 6
#define SOCKETCALL_SOCKETPAIR 8
#define SOCKETCALL_SEND 9
#define SOCKETCALL_RECV 10
#define SOCKETCALL_SENDTO 11
#define SOCKETCALL_RECVFROM 12
#define SOCKETCALL_SHUTDOWN 13
#define SOCKETCALL_SETSOCKOPT 14
#define SOCKETCALL_GETSOCKOPT 15
#define SOCKETCALL_SENDMSG 16
#define SOCKETCALL_RECVMSG 17
#define SOCKETCALL_RECVMMSG 19
#define SOCKETCALL_SENDMMSG 20

#define AF_UNIX 1
#define SOCK_DGRAM 2
#define SOL_SOCKET 1
#define SO_REUSEADDR 2
#define SHUT_RDWR 2
#define EFAULT 14
#define EINVAL 22
#define ENOSYS 38

struct compat_iovec {
    uint32_t base;
    uint32_t length;
};

struct compat_msghdr {
    uint32_t name;
    int32_t name_length;
    uint32_t iov;
    uint32_t iov_length;
    uint32_t control;
    uint32_t control_length;
    uint32_t flags;
};

struct compat_mmsghdr {
    struct compat_msghdr message;
    uint32_t message_length;
};

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
    print_text("IA32_SOCKETCALL_UAPI_PROBE_FAIL ");
    print_text(name);
    print_text("\n");
    call6(SYS_exit, 1, 0, 0, 0, 0, 0);
    __builtin_unreachable();
}

static long socketcall(uint32_t operation, uint32_t *arguments) {
    return call6(SYS_socketcall, operation, arguments, 0, 0, 0, 0);
}

static void expect_all_operations_routed(void) {
    uint32_t arguments[6] = {0, 0, 0, 0, 0, 0};
    uint32_t operation;

    for (operation = SOCKETCALL_SOCKET;
         operation <= SOCKETCALL_SENDMMSG; ++operation) {
        if (socketcall(operation, arguments) == -ENOSYS)
            fail("operation-route");
    }
}

__attribute__((noreturn)) void _start(void) {
    int32_t descriptors[2] = {-1, -1};
    char receive[16] = {0};
    char message_receive[16] = {0};
    char batch_receive_buffer[16] = {0};
    uint32_t arguments[6] = {0, 0, 0, 0, 0, 0};
    uint32_t address_length = 16;
    uint8_t address[16] = {0};
    int32_t option = 1;
    int32_t option_result = 0;
    uint32_t option_length = sizeof(option_result);
    struct compat_iovec send_iov;
    struct compat_iovec receive_iov;
    struct compat_msghdr send_header;
    struct compat_msghdr receive_header;
    struct compat_iovec batch_send_iov;
    struct compat_iovec batch_receive_iov;
    struct compat_mmsghdr batch_send;
    struct compat_mmsghdr batch_receive;
    long result;

    if (socketcall(0, arguments) != -EINVAL)
        fail("invalid-operation-low");
    if (socketcall(21, arguments) != -EINVAL)
        fail("invalid-operation-high");
    if (socketcall(SOCKETCALL_SOCKET, (uint32_t *)(uintptr_t)1) != -EFAULT)
        fail("argument-fault");
    expect_all_operations_routed();

    arguments[0] = AF_UNIX;
    arguments[1] = SOCK_DGRAM;
    arguments[2] = 0;
    arguments[3] = (uint32_t)(uintptr_t)descriptors;
    if (socketcall(SOCKETCALL_SOCKETPAIR, arguments) != 0 ||
        descriptors[0] < 0 || descriptors[1] < 0)
        fail("socketpair");

    arguments[0] = (uint32_t)descriptors[0];
    arguments[1] = (uint32_t)(uintptr_t)"send";
    arguments[2] = 4;
    arguments[3] = 0;
    if (socketcall(SOCKETCALL_SEND, arguments) != 4)
        fail("send");
    arguments[0] = (uint32_t)descriptors[1];
    arguments[1] = (uint32_t)(uintptr_t)receive;
    arguments[2] = sizeof(receive);
    arguments[3] = 0;
    if (socketcall(SOCKETCALL_RECV, arguments) != 4 ||
        receive[0] != 's' || receive[3] != 'd')
        fail("recv");

    arguments[0] = (uint32_t)descriptors[0];
    arguments[1] = (uint32_t)(uintptr_t)"to";
    arguments[2] = 2;
    arguments[3] = 0;
    arguments[4] = 0;
    arguments[5] = 0;
    if (socketcall(SOCKETCALL_SENDTO, arguments) != 2)
        fail("sendto");
    arguments[0] = (uint32_t)descriptors[1];
    arguments[1] = (uint32_t)(uintptr_t)receive;
    arguments[2] = sizeof(receive);
    arguments[3] = 0;
    arguments[4] = 0;
    arguments[5] = 0;
    if (socketcall(SOCKETCALL_RECVFROM, arguments) != 2 ||
        receive[0] != 't')
        fail("recvfrom");

    arguments[0] = (uint32_t)descriptors[0];
    arguments[1] = SOL_SOCKET;
    arguments[2] = SO_REUSEADDR;
    arguments[3] = (uint32_t)(uintptr_t)&option;
    arguments[4] = sizeof(option);
    if (socketcall(SOCKETCALL_SETSOCKOPT, arguments) != 0)
        fail("setsockopt");
    arguments[3] = (uint32_t)(uintptr_t)&option_result;
    arguments[4] = (uint32_t)(uintptr_t)&option_length;
    if (socketcall(SOCKETCALL_GETSOCKOPT, arguments) != 0 ||
        option_result != 1 || option_length != sizeof(option_result))
        fail("getsockopt");

    arguments[0] = (uint32_t)descriptors[0];
    arguments[1] = (uint32_t)(uintptr_t)address;
    arguments[2] = (uint32_t)(uintptr_t)&address_length;
    if (socketcall(SOCKETCALL_GETSOCKNAME, arguments) != 0 ||
        address_length < 2 || address[0] != AF_UNIX)
        fail("getsockname");

    send_iov.base = (uint32_t)(uintptr_t)"message";
    send_iov.length = 7;
    send_header = (struct compat_msghdr){
        0, 0, (uint32_t)(uintptr_t)&send_iov, 1, 0, 0, 0,
    };
    arguments[0] = (uint32_t)descriptors[0];
    arguments[1] = (uint32_t)(uintptr_t)&send_header;
    arguments[2] = 0;
    if (socketcall(SOCKETCALL_SENDMSG, arguments) != 7)
        fail("sendmsg");
    receive_iov.base = (uint32_t)(uintptr_t)message_receive;
    receive_iov.length = sizeof(message_receive);
    receive_header = (struct compat_msghdr){
        0, 0, (uint32_t)(uintptr_t)&receive_iov, 1, 0, 0, 0,
    };
    arguments[0] = (uint32_t)descriptors[1];
    arguments[1] = (uint32_t)(uintptr_t)&receive_header;
    arguments[2] = 0;
    if (socketcall(SOCKETCALL_RECVMSG, arguments) != 7 ||
        message_receive[0] != 'm' || message_receive[6] != 'e')
        fail("recvmsg");

    batch_send_iov.base = (uint32_t)(uintptr_t)"batch";
    batch_send_iov.length = 5;
    batch_send = (struct compat_mmsghdr){
        {0, 0, (uint32_t)(uintptr_t)&batch_send_iov, 1, 0, 0, 0}, 0,
    };
    arguments[0] = (uint32_t)descriptors[0];
    arguments[1] = (uint32_t)(uintptr_t)&batch_send;
    arguments[2] = 1;
    arguments[3] = 0;
    result = socketcall(SOCKETCALL_SENDMMSG, arguments);
    if (result != 1 || batch_send.message_length != 5)
        fail("sendmmsg");
    batch_receive_iov.base = (uint32_t)(uintptr_t)batch_receive_buffer;
    batch_receive_iov.length = sizeof(batch_receive_buffer);
    batch_receive = (struct compat_mmsghdr){
        {0, 0, (uint32_t)(uintptr_t)&batch_receive_iov, 1, 0, 0, 0}, 0,
    };
    arguments[0] = (uint32_t)descriptors[1];
    arguments[1] = (uint32_t)(uintptr_t)&batch_receive;
    arguments[2] = 1;
    arguments[3] = 0;
    arguments[4] = 0;
    result = socketcall(SOCKETCALL_RECVMMSG, arguments);
    if (result != 1 || batch_receive.message_length != 5 ||
        batch_receive_buffer[0] != 'b' ||
        batch_receive_buffer[4] != 'h')
        fail("recvmmsg");

    arguments[0] = (uint32_t)descriptors[0];
    arguments[1] = SHUT_RDWR;
    if (socketcall(SOCKETCALL_SHUTDOWN, arguments) != 0)
        fail("shutdown");
    if (call6(SYS_close, descriptors[0], 0, 0, 0, 0, 0) != 0 ||
        call6(SYS_close, descriptors[1], 0, 0, 0, 0, 0) != 0)
        fail("close");

    print_text("IA32_SOCKETCALL_UAPI_PROBE_PASS\n");
    call6(SYS_exit, 0, 0, 0, 0, 0, 0);
    __builtin_unreachable();
}
