/* SPDX-License-Identifier: MPL-2.0 */
/* Freestanding Linux i386 SysV IPC UAPI probe. */

#include <stdint.h>

#define SYS_exit 1
#define SYS_write 4
#define SYS_ipc 117
#define SYS_semget 393
#define SYS_semctl 394
#define SYS_shmget 395
#define SYS_shmctl 396
#define SYS_shmat 397
#define SYS_shmdt 398
#define SYS_msgget 399
#define SYS_msgsnd 400
#define SYS_msgrcv 401
#define SYS_msgctl 402

#define IPC_PRIVATE 0
#define IPC_RMID 0
#define IPC_STAT 2
#define IPC_64 0x100
#define IPC_CREAT 01000
#define IPC_NOWAIT 04000
#define GETVAL 12
#define SETVAL 16

#define IPC_SEMGET 2
#define IPC_SEMCTL 3
#define IPC_MSGSND 11
#define IPC_MSGRCV 12
#define IPC_MSGGET 13
#define IPC_MSGCTL 14
#define IPC_SHMAT 21
#define IPC_SHMDT 22
#define IPC_SHMGET 23
#define IPC_SHMCTL 24

#define GUARD 0xa55a3cc3u

struct ipc_perm32 {
    int32_t key;
    uint32_t uid;
    uint32_t gid;
    uint32_t cuid;
    uint32_t cgid;
    uint16_t mode;
    uint16_t mode_padding;
    uint16_t sequence;
    uint16_t padding;
    uint32_t reserved1;
    uint32_t reserved2;
};

struct semid_ds32 {
    struct ipc_perm32 permission;
    uint32_t operation_time;
    uint32_t operation_time_high;
    uint32_t change_time;
    uint32_t change_time_high;
    uint32_t semaphore_count;
    uint32_t reserved3;
    uint32_t reserved4;
};

struct msqid_ds32 {
    struct ipc_perm32 permission;
    uint32_t send_time;
    uint32_t send_time_high;
    uint32_t receive_time;
    uint32_t receive_time_high;
    uint32_t change_time;
    uint32_t change_time_high;
    uint32_t current_bytes;
    uint32_t message_count;
    uint32_t maximum_bytes;
    int32_t sender_pid;
    int32_t receiver_pid;
    uint32_t reserved4;
    uint32_t reserved5;
};

struct shmid_ds32 {
    struct ipc_perm32 permission;
    uint32_t segment_size;
    uint32_t attach_time;
    uint32_t attach_time_high;
    uint32_t detach_time;
    uint32_t detach_time_high;
    uint32_t change_time;
    uint32_t change_time_high;
    int32_t creator_pid;
    int32_t last_pid;
    uint32_t attachment_count;
    uint32_t reserved4;
    uint32_t reserved5;
};

struct guarded_semid {
    struct semid_ds32 value;
    uint32_t guard;
};

struct guarded_msqid {
    struct msqid_ds32 value;
    uint32_t guard;
};

struct guarded_shmid {
    struct shmid_ds32 value;
    uint32_t guard;
};

struct message32 {
    int32_t type;
    char data[8];
};

struct ipc_kludge32 {
    uint32_t message;
    int32_t type;
};

void *memset(void *destination, int value, uint32_t size) {
    volatile uint8_t *output = (volatile uint8_t *)destination;
    for (uint32_t index = 0; index < size; ++index)
        output[index] = (uint8_t)value;
    return destination;
}

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
    char text[11] = "0x00000000";
    static const char digits[] = "0123456789abcdef";
    for (uint32_t index = 0; index < 8; ++index) {
        text[9 - index] = digits[value & 15u];
        value >>= 4;
    }
    print_text(text);
}

static void fail(const char *name) {
    print_text("IA32_SYSV_IPC_UAPI_PROBE_FAIL ");
    print_text(name);
    print_text("\n");
    call6(SYS_exit, 1, 0, 0, 0, 0, 0);
    __builtin_unreachable();
}

static int pointer_error(uint32_t value) {
    return value >= 0xfffff001u;
}

static void check_direct_semaphore(void) {
    struct guarded_semid status;
    long identifier = call6(SYS_semget, IPC_PRIVATE, 1,
                            IPC_CREAT | 0600, 0, 0, 0);
    if (identifier < 0) fail("direct-semget");
    if (call6(SYS_semctl, identifier, 0, SETVAL, 7, 0, 0) != 0)
        fail("direct-semctl-setval");
    if (call6(SYS_semctl, identifier, 0, GETVAL, 0, 0, 0) != 7)
        fail("direct-semctl-getval");
    memset(&status, 0, sizeof(status));
    status.guard = GUARD;
    if (call6(SYS_semctl, identifier, 0, IPC_STAT,
              &status.value, 0, 0) != 0 || status.guard != GUARD ||
        status.value.semaphore_count != 1)
        fail("direct-semctl-layout");
    if (call6(SYS_semctl, identifier, 0, IPC_RMID, 0, 0, 0) != 0)
        fail("direct-semctl-rmid");
}

static void check_direct_messages(void) {
    struct message32 sent = {5, {'e', 'd', 'g', 'e', 0, 0, 0, 0}};
    struct message32 received;
    struct guarded_msqid status;
    long identifier = call6(SYS_msgget, IPC_PRIVATE,
                            IPC_CREAT | 0600, 0, 0, 0, 0);
    if (identifier < 0) fail("direct-msgget");
    if (call6(SYS_msgsnd, identifier, &sent, 4, 0, 0, 0) != 0)
        fail("direct-msgsnd");
    memset(&status, 0, sizeof(status));
    status.guard = GUARD;
    if (call6(SYS_msgctl, identifier, IPC_STAT,
              &status.value, 0, 0, 0) != 0 || status.guard != GUARD ||
        status.value.message_count != 1 || status.value.current_bytes != 4)
        fail("direct-msgctl-layout");
    memset(&received, 0, sizeof(received));
    if (call6(SYS_msgrcv, identifier, &received, 4, 5,
              IPC_NOWAIT, 0) != 4 || received.type != 5 ||
        received.data[0] != 'e')
        fail("direct-msgrcv");
    if (call6(SYS_msgctl, identifier, IPC_RMID, 0, 0, 0, 0) != 0)
        fail("direct-msgctl-rmid");
}

static void check_direct_shared_memory(void) {
    struct guarded_shmid status;
    volatile uint32_t *mapping;
    long identifier = call6(SYS_shmget, IPC_PRIVATE, 4096,
                            IPC_CREAT | 0600, 0, 0, 0);
    if (identifier < 0) fail("direct-shmget");
    mapping = (volatile uint32_t *)(uintptr_t)
        call6(SYS_shmat, identifier, 0, 0, 0, 0, 0);
    if (pointer_error((uint32_t)(uintptr_t)mapping)) fail("direct-shmat");
    mapping[0] = GUARD;
    if (mapping[0] != GUARD) fail("direct-shm-access");
    memset(&status, 0, sizeof(status));
    status.guard = GUARD;
    if (call6(SYS_shmctl, identifier, IPC_STAT,
              &status.value, 0, 0, 0) != 0 || status.guard != GUARD ||
        status.value.segment_size != 4096 ||
        status.value.attachment_count < 1) {
        print_text("SHM_LAYOUT ");
        print_hex(status.value.segment_size);
        print_text(" ");
        print_hex(status.value.attachment_count);
        print_text(" ");
        print_hex(status.guard);
        print_text("\n");
        fail("direct-shmctl-layout");
    }
    if (call6(SYS_shmdt, mapping, 0, 0, 0, 0, 0) != 0)
        fail("direct-shmdt");
    if (call6(SYS_shmctl, identifier, IPC_RMID, 0, 0, 0, 0) != 0)
        fail("direct-shmctl-rmid");
}

static void check_legacy_multiplexor(void) {
    struct message32 sent = {9, {'i', 'p', 'c', 0, 0, 0, 0, 0}};
    struct message32 received;
    struct ipc_kludge32 receive_argument;
    uint32_t semctl_argument;
    uint32_t mapping = 0;
    long semaphore;
    long queue;
    long segment;

    semaphore = call6(SYS_ipc, IPC_SEMGET, IPC_PRIVATE, 1,
                      IPC_CREAT | 0600, 0, 0);
    if (semaphore < 0) fail("ipc-semget");
    semctl_argument = 3;
    if (call6(SYS_ipc, IPC_SEMCTL, semaphore, 0, SETVAL,
              &semctl_argument, 0) != 0)
        fail("ipc-semctl-setval");
    semctl_argument = 0;
    if (call6(SYS_ipc, IPC_SEMCTL, semaphore, 0, GETVAL,
              &semctl_argument, 0) != 3)
        fail("ipc-semctl-getval");
    if (call6(SYS_ipc, IPC_SEMCTL, semaphore, 0, IPC_RMID,
              &semctl_argument, 0) != 0)
        fail("ipc-semctl-rmid");

    queue = call6(SYS_ipc, IPC_MSGGET, IPC_PRIVATE,
                  IPC_CREAT | 0600, 0, 0, 0);
    if (queue < 0) fail("ipc-msgget");
    if (call6(SYS_ipc, IPC_MSGSND, queue, 3, 0, &sent, 0) != 0)
        fail("ipc-msgsnd");
    memset(&received, 0, sizeof(received));
    receive_argument.message = (uint32_t)(uintptr_t)&received;
    receive_argument.type = 9;
    if (call6(SYS_ipc, IPC_MSGRCV, queue, 3, IPC_NOWAIT,
              &receive_argument, 0) != 3 || received.type != 9 ||
        received.data[0] != 'i')
        fail("ipc-msgrcv");
    if (call6(SYS_ipc, IPC_MSGCTL, queue, IPC_RMID, 0, 0, 0) != 0)
        fail("ipc-msgctl-rmid");

    segment = call6(SYS_ipc, IPC_SHMGET, IPC_PRIVATE, 4096,
                    IPC_CREAT | 0600, 0, 0);
    if (segment < 0) fail("ipc-shmget");
    if (call6(SYS_ipc, IPC_SHMAT, segment, 0, &mapping, 0, 0) != 0 ||
        !mapping)
        fail("ipc-shmat");
    *(volatile uint32_t *)(uintptr_t)mapping = GUARD;
    if (call6(SYS_ipc, IPC_SHMDT, 0, 0, 0, mapping, 0) != 0)
        fail("ipc-shmdt");
    if (call6(SYS_ipc, IPC_SHMCTL, segment, IPC_RMID, 0, 0, 0) != 0)
        fail("ipc-shmctl-rmid");
}

__attribute__((noreturn)) void _start(void) {
    check_direct_semaphore();
    check_direct_messages();
    check_direct_shared_memory();
    check_legacy_multiplexor();
    print_text("IA32_SYSV_IPC_UAPI_PROBE_PASS\n");
    call6(SYS_exit, 0, 0, 0, 0, 0, 0);
    __builtin_unreachable();
}
