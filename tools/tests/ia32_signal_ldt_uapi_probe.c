/* SPDX-License-Identifier: MPL-2.0 */
/* Freestanding Linux i386 legacy signal and modify_ldt UAPI probe. */

#include <stdint.h>

#define SYS_exit 1
#define SYS_write 4
#define SYS_getpid 20
#define SYS_alarm 27
#define SYS_signal 48
#define SYS_kill 37
#define SYS_sigaction 67
#define SYS_sgetmask 68
#define SYS_ssetmask 69
#define SYS_sigsuspend 72
#define SYS_sigpending 73
#define SYS_modify_ldt 123
#define SYS_sigprocmask 126

#define EINTR 4
#define EINVAL 22
#define SIG_BLOCK 0
#define SIG_UNBLOCK 1
#define SIGUSR1 10
#define SIGUSR2 12
#define SIGALRM 14

struct old_sigaction {
    uint32_t handler;
    uint32_t mask;
    uint32_t flags;
    uint32_t restorer;
};

struct user_desc {
    uint32_t entry_number;
    uint32_t base_addr;
    uint32_t limit;
    uint32_t flags;
};

#define USER_DESC_SEG_32BIT (1u << 0)
#define USER_DESC_LIMIT_IN_PAGES (1u << 4)
#define USER_DESC_USEABLE (1u << 6)

static volatile uint32_t handled_usr1;
static volatile uint32_t handled_usr2;
static volatile uint32_t handled_alarm;

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

static void fail(const char *name) {
    static const char prefix[] = "IA32_SIGNAL_LDT_UAPI_PROBE_FAIL ";
    static const char newline[] = "\n";
    call6(SYS_write, 1, prefix, sizeof(prefix) - 1u, 0, 0, 0);
    call6(SYS_write, 1, name, text_length(name), 0, 0, 0);
    call6(SYS_write, 1, newline, 1, 0, 0, 0);
    call6(SYS_exit, 1, 0, 0, 0, 0, 0);
    __builtin_unreachable();
}

static void signal_handler(int signal) {
    if (signal == SIGUSR1) ++handled_usr1;
    else if (signal == SIGUSR2) ++handled_usr2;
    else if (signal == SIGALRM) ++handled_alarm;
}

static void install_old_action(int signal) {
    struct old_sigaction action = {
        .handler = (uint32_t)(uintptr_t)signal_handler,
    };
    if (call6(SYS_sigaction, signal, &action, 0, 0, 0, 0) != 0)
        fail("sigaction-install");
}

static void test_signal_calls(void) {
    struct old_sigaction previous = {0};
    uint32_t usr1_mask = 1u << (SIGUSR1 - 1);
    uint32_t usr2_mask = 1u << (SIGUSR2 - 1);
    uint32_t old_mask = UINT32_MAX;
    uint32_t pending = 0;
    long pid = call6(SYS_getpid, 0, 0, 0, 0, 0, 0);

    if (pid <= 0) fail("getpid");
    if (call6(SYS_signal, SIGUSR1, signal_handler, 0, 0, 0, 0) != 0)
        fail("signal-install");
    if (call6(SYS_kill, pid, SIGUSR1, 0, 0, 0, 0) != 0 ||
        handled_usr1 != 1)
        fail("signal-delivery");
    if (call6(SYS_sigaction, SIGUSR1, 0, &previous, 0, 0, 0) != 0 ||
        previous.handler != 0)
        fail("signal-reset");

    install_old_action(SIGUSR1);
    install_old_action(SIGUSR2);
    if (call6(SYS_ssetmask, usr2_mask, 0, 0, 0, 0, 0) != 0 ||
        (uint32_t)call6(SYS_sgetmask, 0, 0, 0, 0, 0, 0) != usr2_mask)
        fail("sgetmask-ssetmask");
    if (call6(SYS_sigprocmask, SIG_BLOCK, &usr1_mask, &old_mask,
              0, 0, 0) != 0 || old_mask != usr2_mask)
        fail("sigprocmask-block");
    if (call6(SYS_kill, pid, SIGUSR1, 0, 0, 0, 0) != 0 ||
        handled_usr1 != 1)
        fail("blocked-signal");
    if (call6(SYS_sigpending, &pending, 0, 0, 0, 0, 0) != 0 ||
        (pending & usr1_mask) == 0)
        fail("sigpending");
    if (call6(SYS_sigprocmask, SIG_UNBLOCK, &usr1_mask, 0,
              0, 0, 0) != 0 || handled_usr1 != 2)
        fail("sigprocmask-unblock");

    install_old_action(SIGALRM);
    if (call6(SYS_alarm, 1, 0, 0, 0, 0, 0) != 0)
        fail("alarm");
    if (call6(SYS_sigsuspend, 0, 0, 0, 0, 0, 0) != -EINTR ||
        handled_alarm != 1)
        fail("sigsuspend");
    (void)call6(SYS_ssetmask, 0, 0, 0, 0, 0, 0);
}

static void test_modify_ldt(void) {
    struct user_desc description = {
        .entry_number = 1,
        .base_addr = (uint32_t)(uintptr_t)&handled_usr1,
        .limit = 0xfffffu,
        .flags = USER_DESC_SEG_32BIT | USER_DESC_LIMIT_IN_PAGES |
                 USER_DESC_USEABLE,
    };
    uint64_t entries[3] = {UINT64_MAX, UINT64_MAX, UINT64_MAX};

    if (call6(SYS_modify_ldt, 0, 0, sizeof(entries), 0, 0, 0) != 0)
        fail("modify-ldt-empty");
    if (call6(SYS_modify_ldt, 0x11, &description,
              sizeof(description) - 1u, 0, 0, 0) != -EINVAL)
        fail("modify-ldt-size");
    if (call6(SYS_modify_ldt, 0x11, &description,
              sizeof(description), 0, 0, 0) != 0)
        fail("modify-ldt-write");
    if (call6(SYS_modify_ldt, 0, entries, sizeof(entries), 0, 0, 0) !=
            (long)sizeof(entries) || entries[1] == 0)
        fail("modify-ldt-read");
}

__attribute__((noreturn)) void _start(void) {
    static const char pass[] = "IA32_SIGNAL_LDT_UAPI_PROBE_PASS\n";

    test_signal_calls();
    test_modify_ldt();
    call6(SYS_write, 1, pass, sizeof(pass) - 1u, 0, 0, 0);
    call6(SYS_exit, 0, 0, 0, 0, 0, 0);
    __builtin_unreachable();
}
