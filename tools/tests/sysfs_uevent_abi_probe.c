/* SPDX-License-Identifier: MPL-2.0 */
/* Original EdgeOS sysfs kobject uevent ABI regression test. */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static int fail(const char *operation) {
    fprintf(stderr, "sysfs_uevent_abi_probe: %s: %s\n",
            operation, strerror(errno));
    return 1;
}

int main(void) {
    static const char action[] = "change";
    int descriptor = open("/sys/class/tty/console/uevent",
                          O_WRONLY | O_CLOEXEC | O_TRUNC);
    if (descriptor < 0) return fail("open O_TRUNC");
    if (write(descriptor, action, 0) != 0) {
        close(descriptor);
        return fail("zero-length write");
    }
    if (write(descriptor, action, sizeof(action) - 1u) !=
        (ssize_t)(sizeof(action) - 1u)) {
        close(descriptor);
        return fail("change uevent");
    }
    if (close(descriptor) < 0) return fail("close");
    puts("sysfs_uevent_abi_probe: PASS");
    return 0;
}
