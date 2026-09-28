/* SPDX-License-Identifier: MPL-2.0 */
/* Minimal PID 1 wrapper for the SquashFS KVM acceptance test. */

#include <unistd.h>

int main(void) {
    char *const arguments[] = {
        (char *)"/bin/sh",
        (char *)"/root/squashfs_runtime_test.sh",
        0
    };
    char *const environment[] = {
        (char *)"PATH=/usr/sbin:/usr/bin:/sbin:/bin",
        (char *)"HOME=/root",
        (char *)"TERM=linux",
        0
    };
    static const char failure[] = "SQUASHFS_RUNTIME_EXEC_FAILED\n";

    execve(arguments[0], arguments, environment);
    (void)write(2, failure, sizeof(failure) - 1u);
    return 111;
}
