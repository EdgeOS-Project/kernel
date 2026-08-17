/*
 * Original EdgeOS code licensed under MPL-2.0.
 *
 * Linux getrusage() ABI probe for Alpine rootfs validation.
 */

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stddef.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef RUSAGE_THREAD
#define RUSAGE_THREAD 1
#endif

#ifndef SYS_getrusage
#define SYS_getrusage 98
#endif

static struct rusage g_ru;

static size_t linux_rusage_kernel_size(void) {
    return offsetof(struct rusage, ru_nivcsw) + sizeof(g_ru.ru_nivcsw);
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

static __attribute__((no_stack_protector)) int check_success(int who, const char *name, int expect_accounting) {
    memset(&g_ru, 0x5a, sizeof(g_ru));
    errno = 0;
    long rc = syscall(SYS_getrusage, who, &g_ru);
    int saved_errno = errno;
    int zero = bytes_all_zero(&g_ru, linux_rusage_kernel_size());
    dprintf(STDOUT_FILENO, "getrusage_%s_rc:%ld errno:%d ru_zero:%d\n",
            name, rc, saved_errno, zero);
    if (rc != 0) return 1;
    if (saved_errno != 0) return 1;
    if (expect_accounting && !rusage_has_accounting(&g_ru)) return 1;
    if (!expect_accounting && !zero) return 1;
    return 0;
}

static __attribute__((no_stack_protector)) int check_error(int who, struct rusage *ru, int expected_errno, const char *name) {
    errno = 0;
    long rc = syscall(SYS_getrusage, who, ru);
    int saved_errno = errno;
    dprintf(STDOUT_FILENO, "getrusage_%s_rc:%ld errno:%d\n", name, rc, saved_errno);
    if (rc != -1) return 1;
    if (saved_errno != expected_errno) return 1;
    return 0;
}

int main(void) {
    burn_cpu();
    if (check_success(RUSAGE_SELF, "self", 1) != 0) _exit(1);
    if (check_success(RUSAGE_CHILDREN, "children", 0) != 0) _exit(1);
    if (check_success(RUSAGE_THREAD, "thread", 1) != 0) _exit(1);
    if (check_error(99, &g_ru, EINVAL, "badwho") != 0) _exit(1);
    if (check_error(RUSAGE_SELF, (struct rusage *)0, EFAULT, "null") != 0) _exit(1);
    dprintf(STDOUT_FILENO, "GETRUSAGE_THREAD_PROBE_PASS\n");
    _exit(0);
}
