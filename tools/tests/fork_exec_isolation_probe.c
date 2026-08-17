/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Verify that a child exec cannot replace or modify its parent's executable
 * mappings.  This exercises the same fork/exec/wait sequence used by shell
 * launchers without depending on a desktop environment.
 */

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#define DEFAULT_ITERATIONS 128
#define FINGERPRINT_BYTES 256

static __attribute__((noinline)) uint64_t probe_marker(uint64_t value)
{
    return (value ^ UINT64_C(0x9e3779b97f4a7c15)) +
           UINT64_C(0xd1b54a32d192ed03);
}

static uint64_t fingerprint(const unsigned char *bytes, size_t length)
{
    uint64_t hash = UINT64_C(1469598103934665603);

    for (size_t i = 0; i < length; ++i) {
        hash ^= bytes[i];
        hash *= UINT64_C(1099511628211);
    }
    return hash;
}

int main(int argc, char **argv)
{
    const unsigned char *text = (const unsigned char *)(uintptr_t)&probe_marker;
    const char *child_path = "/bin/true";
    unsigned char baseline[FINGERPRINT_BYTES];
    int iterations = DEFAULT_ITERATIONS;
    uint64_t baseline_hash;

    if (argc > 1) {
        iterations = atoi(argv[1]);
        if (iterations <= 0 || iterations > 100000) {
            fprintf(stderr, "invalid iteration count: %s\n", argv[1]);
            return 2;
        }
    }
    if (argc > 2) child_path = argv[2];

    memcpy(baseline, text, sizeof(baseline));
    baseline_hash = fingerprint(baseline, sizeof(baseline));

    for (int iteration = 0; iteration < iterations; ++iteration) {
        pid_t child = fork();
        int status;

        if (child < 0) {
            fprintf(stderr, "fork failed at iteration %d: %s\n",
                    iteration, strerror(errno));
            return 3;
        }
        if (child == 0) {
            execl(child_path, child_path, (char *)NULL);
            _exit(127);
        }
        if (waitpid(child, &status, 0) != child) {
            fprintf(stderr, "waitpid failed at iteration %d: %s\n",
                    iteration, strerror(errno));
            return 4;
        }
        if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
            fprintf(stderr, "child failed at iteration %d: status=0x%x\n",
                    iteration, status);
            return 5;
        }

        if (fingerprint(text, sizeof(baseline)) != baseline_hash ||
            memcmp(text, baseline, sizeof(baseline)) != 0) {
            fprintf(stderr,
                    "FORK_EXEC_ISOLATION_FAIL iteration=%d marker=%p "
                    "expected_hash=%016llx actual_hash=%016llx\n",
                    iteration, (const void *)text,
                    (unsigned long long)baseline_hash,
                    (unsigned long long)fingerprint(text, sizeof(baseline)));
            return 6;
        }

        if (probe_marker((uint64_t)iteration) !=
            (((uint64_t)iteration ^ UINT64_C(0x9e3779b97f4a7c15)) +
             UINT64_C(0xd1b54a32d192ed03))) {
            fprintf(stderr, "marker execution failed at iteration %d\n", iteration);
            return 7;
        }
    }

    printf("FORK_EXEC_ISOLATION_PASS iterations=%d marker=%p hash=%016llx\n",
           iterations, (const void *)text, (unsigned long long)baseline_hash);
    return 0;
}
