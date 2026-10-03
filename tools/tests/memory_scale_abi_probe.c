/* SPDX-License-Identifier: MPL-2.0 */
/* Touch and verify every word of an anonymous mapping, including above 4 GiB. */
#define _GNU_SOURCE
#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>

static uint64_t pattern(uint64_t index, uint64_t round) {
    return (index * UINT64_C(0x9e3779b97f4a7c15)) ^
           (round * UINT64_C(0xd1b54a32d192ed03));
}

static uint64_t number(const char *text) {
    char *end;
    errno = 0;
    if (!text || text[0] < '1' || text[0] > '9') return 0;
    unsigned long long value = strtoull(text, &end, 10);
    return errno || *end ? 0 : value;
}

int main(int argc, char **argv) {
    uint64_t mib = argc > 1 ? number(argv[1]) : 0;
    uint64_t rounds = argc > 2 ? number(argv[2]) : 1;
    if (argc < 2 || argc > 3 || !mib || !rounds ||
        mib > SIZE_MAX / (1024u * 1024u)) {
        fprintf(stderr, "Usage: memory_scale_abi_probe MiB [rounds]\n");
        return 2;
    }
    size_t bytes = (size_t)mib * 1024u * 1024u;
    for (uint64_t round = 0; round < rounds; ++round) {
        volatile uint64_t *mapping = mmap(0, bytes, PROT_READ | PROT_WRITE,
                                          MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (mapping == MAP_FAILED) {
            perror("mmap");
            return 1;
        }
        size_t words = bytes / sizeof(uint64_t);
        for (size_t index = 0; index < words; ++index) {
            if (mapping[index] != 0) {
                fprintf(stderr, "Zero-fill mismatch at word %zu\n", index);
                munmap((void *)mapping, bytes);
                return 1;
            }
            mapping[index] = pattern(index, round + 1);
        }
        for (size_t index = words; index-- > 0;) {
            if (mapping[index] != pattern(index, round + 1)) {
                fprintf(stderr, "Data mismatch at word %zu\n", index);
                munmap((void *)mapping, bytes);
                return 1;
            }
        }
        if (munmap((void *)mapping, bytes) != 0) {
            perror("munmap");
            return 1;
        }
        printf("{\"test\":\"memory_scale\",\"bytes\":%zu,\"round\":%" PRIu64
               ",\"status\":\"pass\"}\n", bytes, round + 1);
        fflush(stdout);
    }
    return 0;
}
