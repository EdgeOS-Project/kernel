/*
 * Original EdgeOS code licensed under MPL-2.0.
 *
 * Linux wait4()/waitid() rusage ABI probe for Alpine rootfs validation.
 */

#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stddef.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef SYS_waitid
#define SYS_waitid 247
#endif

static struct rusage g_wait4_ru;
static struct rusage g_waitid_ru;
static siginfo_t g_waitid_si;

static size_t linux_rusage_kernel_size(void) {
    return offsetof(struct rusage, ru_nivcsw) + sizeof(g_wait4_ru.ru_nivcsw);
}

static __attribute__((no_stack_protector)) int bytes_all_zero(const void *ptr, size_t len) {
    const unsigned char *p = ptr;
    for (size_t i = 0; i < len; i++) {
        if (p[i] != 0) return 0;
    }
    return 1;
}

static int rusage_has_accounting(const struct rusage *ru) {
    return ru->ru_utime.tv_sec || ru->ru_utime.tv_usec ||
           ru->ru_stime.tv_sec || ru->ru_stime.tv_usec ||
           ru->ru_minflt || ru->ru_majflt ||
           ru->ru_nvcsw || ru->ru_nivcsw;
}

static void burn_cpu(void) {
    for (volatile unsigned long i = 0; i < 80000000UL; ++i) {
        __asm__ __volatile__("" ::: "memory");
    }
}

static __attribute__((no_stack_protector)) int test_wait4_rusage(void) {
    int status = 0;
    int saved_errno;
    pid_t child = fork();
    if (child < 0) {
        perror("fork wait4");
        return 1;
    }
    if (child == 0) {
        burn_cpu();
        _exit(33);
    }

    memset(&g_wait4_ru, 0x5a, sizeof(g_wait4_ru));
    errno = 0;
    pid_t rc = wait4(child, &status, 0, &g_wait4_ru);
    saved_errno = errno;
    dprintf(STDOUT_FILENO, "wait4_rusage_rc:%ld status:0x%x errno:%d ru_zero:%d\n",
            (long)rc, status, saved_errno, bytes_all_zero(&g_wait4_ru, linux_rusage_kernel_size()));

    if (rc != child) return 1;
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 33) return 1;
    if (!rusage_has_accounting(&g_wait4_ru)) return 1;
    return 0;
}

static __attribute__((no_stack_protector)) int test_waitid_rusage(void) {
    int saved_errno;
    pid_t child = fork();
    if (child < 0) {
        perror("fork waitid");
        return 1;
    }
    if (child == 0) {
        burn_cpu();
        _exit(44);
    }

    memset(&g_waitid_ru, 0x5a, sizeof(g_waitid_ru));
    memset(&g_waitid_si, 0, sizeof(g_waitid_si));
    errno = 0;
    long rc = syscall(SYS_waitid, P_PID, (id_t)child, &g_waitid_si, WEXITED, &g_waitid_ru);
    saved_errno = errno;
    dprintf(STDOUT_FILENO, "waitid_rusage_rc:%ld errno:%d signo:%d code:%d pid:%ld status:%d ru_zero:%d\n",
            rc, saved_errno, g_waitid_si.si_signo, g_waitid_si.si_code, (long)g_waitid_si.si_pid,
            g_waitid_si.si_status, bytes_all_zero(&g_waitid_ru, linux_rusage_kernel_size()));

    if (rc != 0) return 1;
    if (g_waitid_si.si_signo != SIGCHLD) return 1;
    if (g_waitid_si.si_code != CLD_EXITED) return 1;
    if (g_waitid_si.si_pid != child) return 1;
    if (g_waitid_si.si_status != 44) return 1;
    if (!rusage_has_accounting(&g_waitid_ru)) return 1;
    return 0;
}

int main(void) {
    if (test_wait4_rusage() != 0) _exit(1);
    if (test_waitid_rusage() != 0) _exit(1);
    dprintf(STDOUT_FILENO, "WAIT_RUSAGE_PROBE_PASS\n");
    _exit(0);
}
