/* SPDX-License-Identifier: MPL-2.0 */
/* Original EdgeOS Linux seccomp SIGSYS ABI regression test. */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <ucontext.h>
#include <unistd.h>

#ifndef SYS_SECCOMP
#define SYS_SECCOMP 1
#endif

static volatile sig_atomic_t g_handled;
static volatile sig_atomic_t g_failures;
static int g_signal_pipe[2] = {-1, -1};
static uint8_t g_altstack[64 * 1024];
static const char g_path[] = "/tmp/edgeos-seccomp-sigsys";
static uint8_t g_stat_buffer[256];

static const uintptr_t g_expected_arguments[6] = {
    (uintptr_t)(intptr_t)AT_FDCWD,
    (uintptr_t)g_path,
    (uintptr_t)g_stat_buffer,
    (uintptr_t)AT_SYMLINK_NOFOLLOW,
    UINT64_C(0x1122334455667788),
    UINT64_C(0x7766554433221100),
};

static uint32_t expected_audit_architecture(void) {
#if defined(__aarch64__)
    return AUDIT_ARCH_AARCH64;
#elif defined(__x86_64__)
    return AUDIT_ARCH_X86_64;
#else
#error "seccomp_sigsys_probe requires a supported 64-bit architecture"
#endif
}

static void sigsys_handler(int signal, siginfo_t *information,
                           void *context_pointer) {
    ucontext_t *context = (ucontext_t *)context_pointer;
    uintptr_t local_address = (uintptr_t)&context;
    char notification = 'S';
    if (signal != SIGSYS || !information || !context) {
        ++g_failures;
        return;
    }
    if (information->si_signo != SIGSYS ||
        information->si_code != SYS_SECCOMP ||
        information->si_errno != 77 ||
        information->si_syscall != SYS_newfstatat ||
        (uint32_t)information->si_arch != expected_audit_architecture() ||
        information->si_call_addr == NULL)
        ++g_failures;
    if (local_address < (uintptr_t)g_altstack ||
        local_address >= (uintptr_t)g_altstack + sizeof(g_altstack))
        ++g_failures;
#if defined(__aarch64__)
    if (context->uc_mcontext.pc !=
            (uintptr_t)information->si_call_addr ||
        context->uc_mcontext.regs[8] != SYS_newfstatat ||
        context->uc_mcontext.regs[0] != g_expected_arguments[0] ||
        context->uc_mcontext.regs[1] != g_expected_arguments[1] ||
        context->uc_mcontext.regs[2] != g_expected_arguments[2] ||
        context->uc_mcontext.regs[3] != g_expected_arguments[3] ||
        context->uc_mcontext.regs[4] != g_expected_arguments[4] ||
        context->uc_mcontext.regs[5] != g_expected_arguments[5])
        ++g_failures;
    context->uc_mcontext.regs[0] = 424242;
#else
    if ((uintptr_t)context->uc_mcontext.gregs[REG_RIP] !=
            (uintptr_t)information->si_call_addr ||
        context->uc_mcontext.gregs[REG_RAX] != SYS_newfstatat ||
        (uintptr_t)context->uc_mcontext.gregs[REG_RDI] !=
            g_expected_arguments[0] ||
        (uintptr_t)context->uc_mcontext.gregs[REG_RSI] !=
            g_expected_arguments[1] ||
        (uintptr_t)context->uc_mcontext.gregs[REG_RDX] !=
            g_expected_arguments[2] ||
        (uintptr_t)context->uc_mcontext.gregs[REG_R10] !=
            g_expected_arguments[3] ||
        (uintptr_t)context->uc_mcontext.gregs[REG_R8] !=
            g_expected_arguments[4] ||
        (uintptr_t)context->uc_mcontext.gregs[REG_R9] !=
            g_expected_arguments[5])
        ++g_failures;
    context->uc_mcontext.gregs[REG_RAX] = 424242;
#endif
    if (write(g_signal_pipe[1], &notification, 1) != 1)
        ++g_failures;
    g_handled = 1;
}

int main(void) {
    struct sigaction action;
    struct sock_filter instructions[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                 (uint32_t)offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_newfstatat, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRAP | 77u),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog program = {
        .len = (unsigned short)(sizeof(instructions) /
                                sizeof(instructions[0])),
        .filter = instructions,
    };
    stack_t signal_stack;
    char notification = 0;
    long result;

    if (pipe(g_signal_pipe) < 0) {
        perror("pipe");
        return 1;
    }
    memset(&signal_stack, 0, sizeof(signal_stack));
    signal_stack.ss_sp = g_altstack;
    signal_stack.ss_size = sizeof(g_altstack);
    if (sigaltstack(&signal_stack, NULL) < 0) {
        perror("sigaltstack");
        return 1;
    }
    memset(&action, 0, sizeof(action));
    action.sa_sigaction = sigsys_handler;
    action.sa_flags = SA_SIGINFO | SA_NODEFER | SA_ONSTACK;
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGSYS, &action, NULL) < 0) {
        perror("sigaction");
        return 1;
    }
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) {
        perror("prctl(PR_SET_NO_NEW_PRIVS)");
        return 1;
    }
    if (syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, &program) < 0) {
        perror("seccomp(SECCOMP_SET_MODE_FILTER)");
        return 1;
    }

    result = syscall(SYS_newfstatat,
                     g_expected_arguments[0], g_expected_arguments[1],
                     g_expected_arguments[2], g_expected_arguments[3],
                     g_expected_arguments[4], g_expected_arguments[5]);
    if (read(g_signal_pipe[0], &notification, 1) != 1 ||
        notification != 'S')
        ++g_failures;
    if (!g_handled || result != 424242) ++g_failures;
    if (g_failures) {
        fprintf(stderr,
                "seccomp-sigsys: FAIL handled=%d result=%ld failures=%d\n",
                (int)g_handled, result, (int)g_failures);
        return 1;
    }
    puts("seccomp-sigsys: PASS");
    return 0;
}
