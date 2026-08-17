/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS Linux procfs mount-notification ABI test.
 * Copyright (c) EdgeOS Contributors.
 */

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <unistd.h>

static const char test_mountpoint[] = "/tmp/edgeos-mountinfo-poll";

static int poll_mount_change(int descriptor, const char *stage,
                             int expect_ready) {
    struct pollfd event = {
        .fd = descriptor,
        .events = POLLPRI,
    };
    int result = poll(&event, 1, 0);

    if (result < 0) {
        fprintf(stderr, "%s: poll: %s\n", stage, strerror(errno));
        return 1;
    }
    printf("%s: poll=%d revents=0x%x\n", stage, result, event.revents);
    if (expect_ready)
        return result != 1 || !(event.revents & POLLPRI);
    return result != 0 || event.revents != 0;
}

static int read_mountinfo_contains(int descriptor, const char *needle) {
    char buffer[8192];
    char carry[512];
    size_t carry_length = 0;

    if (lseek(descriptor, 0, SEEK_SET) < 0) return -1;
    for (;;) {
        ssize_t length = read(descriptor, buffer, sizeof(buffer) - 1u);
        if (length < 0) return -1;
        if (length == 0) return 0;
        buffer[length] = 0;
        if (strstr(buffer, needle)) return 1;
        if (carry_length) {
            size_t copy = (size_t)length;
            if (copy > sizeof(carry) - carry_length - 1u)
                copy = sizeof(carry) - carry_length - 1u;
            memcpy(carry + carry_length, buffer, copy);
            carry[carry_length + copy] = 0;
            if (strstr(carry, needle)) return 1;
        }
        carry_length = (size_t)length;
        if (carry_length >= sizeof(carry)) carry_length = sizeof(carry) - 1u;
        memcpy(carry, buffer + (size_t)length - carry_length, carry_length);
        carry[carry_length] = 0;
    }
}

int main(void) {
    int descriptor;
    int failures = 0;

    (void)umount2(test_mountpoint, MNT_DETACH);
    if (mkdir(test_mountpoint, 0700) < 0 && errno != EEXIST) {
        fprintf(stderr, "mkdir: %s\n", strerror(errno));
        return 1;
    }
    descriptor = open("/proc/self/mountinfo", O_RDONLY | O_CLOEXEC);
    if (descriptor < 0) {
        fprintf(stderr, "open mountinfo: %s\n", strerror(errno));
        return 1;
    }
    failures += poll_mount_change(descriptor, "initial", 0);
    if (mount("tmpfs", test_mountpoint, "tmpfs", MS_NODEV | MS_NOSUID,
              "size=64k") < 0) {
        fprintf(stderr, "mount: %s\n", strerror(errno));
        close(descriptor);
        return 1;
    }
    failures += poll_mount_change(descriptor, "after-mount", 1);
    if (read_mountinfo_contains(descriptor, test_mountpoint) != 1) {
        fprintf(stderr, "new mount is absent from mountinfo\n");
        failures++;
    }
    failures += poll_mount_change(descriptor, "after-read", 0);
    if (umount2(test_mountpoint, MNT_DETACH) < 0) {
        fprintf(stderr, "umount: %s\n", strerror(errno));
        failures++;
    } else {
        failures += poll_mount_change(descriptor, "after-umount", 1);
        if (read_mountinfo_contains(descriptor, test_mountpoint) != 0) {
            fprintf(stderr, "removed mount remains in mountinfo\n");
            failures++;
        }
        failures += poll_mount_change(descriptor, "after-umount-read", 0);
    }
    close(descriptor);
    (void)rmdir(test_mountpoint);
    if (failures) {
        fprintf(stderr, "PROC_MOUNTINFO_POLL_FAIL failures=%d\n", failures);
        return 1;
    }
    puts("PROC_MOUNTINFO_POLL_PASS");
    return 0;
}
