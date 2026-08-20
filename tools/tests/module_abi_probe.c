/* SPDX-License-Identifier: MPL-2.0 */
/* Linux module syscall validation-order probe. */

#define _GNU_SOURCE
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

static int has_module_capability(void) {
    FILE *status = fopen("/proc/self/status", "r");
    char line[256];
    unsigned long long effective = 0;

    if (!status) return 0;
    while (fgets(line, sizeof(line), status)) {
        if (sscanf(line, "CapEff:\t%llx", &effective) == 1) break;
    }
    fclose(status);
    return (effective & (1ull << 16)) != 0;
}

static int expect_errno(const char *name, long result, int expected) {
    int actual = result < 0 ? errno : 0;

    printf("%s\tresult=%ld\terrno=%d\n", name, result, actual);
    return result == -1 && actual == expected ? 0 : 1;
}

int main(void) {
    static const char empty[] = "";
    int privileged = has_module_capability();
    int failures = 0;

    errno = 0;
    failures += expect_errno(
        "init_bad_image",
        syscall(SYS_init_module, (void *)(uintptr_t)1, 1u, empty),
        privileged ? EFAULT : EPERM);
    errno = 0;
    failures += expect_errno(
        "delete_bad_name",
        syscall(SYS_delete_module, (void *)(uintptr_t)1, 0u),
        privileged ? EFAULT : EPERM);
    errno = 0;
    failures += expect_errno(
        "finit_bad_fd", syscall(SYS_finit_module, -1, empty, 0u),
        privileged ? EBADF : EPERM);
    errno = 0;
    failures += expect_errno(
        "finit_bad_flags", syscall(SYS_finit_module, -1, empty, 0x80000000u),
        privileged ? EINVAL : EPERM);
    return failures ? EXIT_FAILURE : EXIT_SUCCESS;
}
