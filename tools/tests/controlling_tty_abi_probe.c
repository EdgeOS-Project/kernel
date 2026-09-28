/*
 * Copyright (c) EdgeOS Contributors.
 * SPDX-License-Identifier: MPL-2.0
 *
 * Validate that /dev/tty reopens the caller's controlling pseudo-terminal.
 * The same binary is intended to run on native Linux and EdgeOS.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>

static void child_fail(const char *operation) {
    fprintf(stderr, "%s: errno=%d (%s)\n", operation, errno,
            strerror(errno));
    _exit(1);
}

static void run_child(void) {
    char slave_path[128];
    struct stat slave_descriptor_stat;
    struct stat slave_path_stat;
    struct termios termios_value;
    struct winsize winsize_value;
    pid_t foreground;
    int controlling = -1;
    int master = -1;
    int slave = -1;

    if (setsid() < 0) child_fail("setsid");
    master = posix_openpt(O_RDWR | O_NOCTTY | O_CLOEXEC);
    if (master < 0) child_fail("posix_openpt");
    if (grantpt(master) < 0) child_fail("grantpt");
    if (unlockpt(master) < 0) child_fail("unlockpt");
    if (ptsname_r(master, slave_path, sizeof(slave_path)) != 0)
        child_fail("ptsname_r");
    slave = open(slave_path, O_RDWR | O_NOCTTY | O_CLOEXEC);
    if (slave < 0) child_fail("open slave");
    if (fstat(slave, &slave_descriptor_stat) < 0)
        child_fail("fstat slave");
    if (stat(slave_path, &slave_path_stat) < 0)
        child_fail("stat slave");
    if (!S_ISCHR(slave_descriptor_stat.st_mode) ||
        !S_ISCHR(slave_path_stat.st_mode) ||
        slave_descriptor_stat.st_dev != slave_path_stat.st_dev ||
        slave_descriptor_stat.st_ino != slave_path_stat.st_ino ||
        slave_descriptor_stat.st_rdev != slave_path_stat.st_rdev) {
        fprintf(stderr,
                "slave metadata mismatch: fd dev=%llu ino=%llu rdev=%llu mode=%o path dev=%llu ino=%llu rdev=%llu mode=%o\n",
                (unsigned long long)slave_descriptor_stat.st_dev,
                (unsigned long long)slave_descriptor_stat.st_ino,
                (unsigned long long)slave_descriptor_stat.st_rdev,
                (unsigned)slave_descriptor_stat.st_mode,
                (unsigned long long)slave_path_stat.st_dev,
                (unsigned long long)slave_path_stat.st_ino,
                (unsigned long long)slave_path_stat.st_rdev,
                (unsigned)slave_path_stat.st_mode);
        _exit(1);
    }
    if (access(slave_path, R_OK | W_OK) < 0)
        child_fail("access slave");
    if (ioctl(slave, TIOCSCTTY, 0) < 0) child_fail("TIOCSCTTY");

    controlling = open("/dev/tty", O_RDWR | O_NOCTTY | O_CLOEXEC);
    if (controlling < 0) child_fail("open /dev/tty");
    if (tcgetattr(controlling, &termios_value) < 0)
        child_fail("tcgetattr /dev/tty");
    if (ioctl(controlling, TIOCGWINSZ, &winsize_value) < 0)
        child_fail("TIOCGWINSZ /dev/tty");
    foreground = tcgetpgrp(controlling);
    if (foreground < 0) child_fail("tcgetpgrp /dev/tty");
    if (foreground != getpgrp()) {
        fprintf(stderr, "foreground pgrp: expected=%ld actual=%ld\n",
                (long)getpgrp(), (long)foreground);
        _exit(1);
    }

    close(controlling);
    close(slave);
    close(master);
    _exit(0);
}

int main(void) {
    int status;
    pid_t child = fork();

    if (child < 0) {
        fprintf(stderr, "fork: errno=%d (%s)\n", errno, strerror(errno));
        return 1;
    }
    if (child == 0) run_child();
    if (waitpid(child, &status, 0) != child) {
        fprintf(stderr, "waitpid: errno=%d (%s)\n", errno, strerror(errno));
        return 1;
    }
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        fprintf(stderr, "controlling tty child status=0x%x\n", status);
        return 1;
    }
    puts("controlling_tty_abi_probe: PASS");
    return 0;
}
