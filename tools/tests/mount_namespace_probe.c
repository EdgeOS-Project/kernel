/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS Linux mount-namespace regression test.
 * Copyright (c) EdgeOS Contributors.
 */

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int inspect_path(const char *path) {
    struct stat st;

    errno = 0;
    if (stat(path, &st) < 0) {
        printf("path=%s stat=-1 errno=%d (%s)\n", path, errno,
               strerror(errno));
        return -1;
    }
    printf("path=%s stat=0 mode=%#o size=%lld\n", path,
           (unsigned int)st.st_mode, (long long)st.st_size);
    return 0;
}

int main(int argc, char **argv) {
    char cwd[4096];
    int failures = 0;

    printf("argc=%d\n", argc);
    for (int index = 0; index < argc; ++index)
        printf("argv[%d]=%s\n", index, argv[index] ? argv[index] : "<null>");

    if (getcwd(cwd, sizeof(cwd)))
        printf("cwd=%s\n", cwd);
    else
        printf("cwd=<error> errno=%d (%s)\n", errno, strerror(errno));

    for (int index = 1; index < argc; ++index)
        if (inspect_path(argv[index]) < 0) ++failures;

    return failures ? 1 : 0;
}
