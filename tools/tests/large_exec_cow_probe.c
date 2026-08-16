/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS executable-image and fork COW regression test.
 * Copyright (c) EdgeOS Contributors.
 *
 * Build with -fno-pie -no-pie when validating the x86_64 low executable
 * window.  The far writes force the data segment to cover addresses that are
 * well beyond the historical 8 MiB image limit.
 */

#include <stdint.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define IMAGE_BYTES (24u * 1024u * 1024u)
#define FIRST_OFFSET (12u * 1024u * 1024u)
#define SECOND_OFFSET (23u * 1024u * 1024u)

static volatile unsigned char image_data[IMAGE_BYTES];

int main(void) {
    int status = 0;
    pid_t child;

    image_data[FIRST_OFFSET] = 0x2au;
    image_data[SECOND_OFFSET] = 0x35u;

    child = fork();
    if (child < 0) {
        perror("fork");
        return 1;
    }
    if (child == 0) {
        image_data[FIRST_OFFSET] = 0x63u;
        image_data[SECOND_OFFSET] = 0x64u;
        _exit(image_data[FIRST_OFFSET] == 0x63u &&
                      image_data[SECOND_OFFSET] == 0x64u ?
                  0 : 2);
    }

    if (waitpid(child, &status, 0) != child) {
        perror("waitpid");
        return 3;
    }
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        fprintf(stderr, "child image write failed: status=%d\n", status);
        return 4;
    }
    if (image_data[FIRST_OFFSET] != 0x2au ||
        image_data[SECOND_OFFSET] != 0x35u) {
        fputs("fork did not preserve private executable-image pages\n", stderr);
        return 5;
    }

    puts("LARGE_EXEC_COW_PROBE_PASS");
    return 0;
}
