/* SPDX-License-Identifier: MPL-2.0 */
/* Start a single-task profile, restore the benchmark user's identity, and exec. */
#define _DEFAULT_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <pwd.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
int main(int argc, char **argv) {
    char *end;
    unsigned long uid;
    struct passwd *user;
    int fd;
    if (argc < 4 || (strcmp(argv[2], "start") && strcmp(argv[2], "counts") &&
                     strcmp(argv[2], "global-start") &&
                     strcmp(argv[2], "global-counts") &&
                     strcmp(argv[2], "stop"))) {
        fprintf(stderr, "usage: %s UID start|counts|global-start|global-counts|stop COMMAND [ARG...]\n", argv[0]);
        return 2;
    }
    errno = 0;
    uid = strtoul(argv[1], &end, 10);
    if (errno || !argv[1][0] || *end || uid >= UINT32_MAX) return 2;
    user = getpwuid((uid_t)uid);
    if (!user) { perror("getpwuid"); return 1; }
    if (initgroups(user->pw_name, user->pw_gid) || setgid(user->pw_gid)) {
        perror("groups"); return 1;
    }
    fd = open("/proc/vfs_profile", O_WRONLY | O_CLOEXEC);
    if (fd < 0) { perror("/proc/vfs_profile"); return 1; }
    size_t length = strlen(argv[2]);
    if (write(fd, argv[2], length) != (ssize_t)length) {
        perror("profile start"); close(fd); return 1;
    }
    if (setuid((uid_t)uid)) {
        perror("setuid"); close(fd); return 1;
    }
    close(fd);
    execvp(argv[3], argv + 3);
    perror("execvp");
    return 127;
}
