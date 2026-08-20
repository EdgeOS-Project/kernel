/* SPDX-License-Identifier: MPL-2.0 */
/* Runtime probe for Linux vhangup permission and no-terminal behavior. */

#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#if defined(__x86_64__)
#define EDGE_SYS_VHANGUP 153
#elif defined(__aarch64__)
#define EDGE_SYS_VHANGUP 58
#else
#error "vhangup_abi_probe requires a supported 64-bit architecture"
#endif

static int expect_unprivileged_failure(void) {
    long result;

    errno = 0;
    result = syscall(EDGE_SYS_VHANGUP);
    if (result != -1 || errno != EPERM) {
        fprintf(stderr, "unprivileged vhangup: result=%ld errno=%d\n",
                result, errno);
        return 1;
    }
    return 0;
}

int main(void) {
    pid_t child;
    int status;

    if (geteuid() != 0) return expect_unprivileged_failure();
    errno = 0;
    if (syscall(EDGE_SYS_VHANGUP) != 0 || errno != 0) {
        fprintf(stderr, "privileged vhangup: errno=%d\n", errno);
        return 2;
    }
    child = fork();
    if (child < 0) return 3;
    if (child == 0) {
        if (setuid(65534) != 0) _exit(4);
        _exit(expect_unprivileged_failure() ? 5 : 0);
    }
    if (waitpid(child, &status, 0) != child || !WIFEXITED(status))
        return 6;
    return WEXITSTATUS(status);
}
