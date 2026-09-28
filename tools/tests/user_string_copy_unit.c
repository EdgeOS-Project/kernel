/* SPDX-License-Identifier: MPL-2.0 */
#define _DEFAULT_SOURCE
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include "kernel/user_string_copy.h"

typedef struct {
    uint64_t base;
    uint32_t readable, calls, largest;
    int reject_bulk;
    unsigned char bytes[8192];
} memory_t;

static int read_memory(void *context, void *destination,
                       uint64_t source, uint64_t length) {
    memory_t *memory = context;
    ++memory->calls;
    assert(length && length <= 128);
    assert(length <= 4096 - (source & 4095));
    assert(length - 1 <= UINT64_MAX - source);
    if (length > memory->largest) memory->largest = (uint32_t)length;
    if (source < memory->base || source - memory->base > memory->readable ||
        length > memory->readable - (source - memory->base) ||
        (memory->reject_bulk && length > 1)) {
        /* Failed callbacks may leave partial output; it must not escape. */
        memset(destination, 0xa5, (size_t)length);
        return -1;
    }
    memcpy(destination, memory->bytes + (source - memory->base), (size_t)length);
    return 0;
}
static void reset(memory_t *memory) {
    memset(memory, 0, sizeof(*memory));
    memory->base = 0x4000;
    memory->readable = sizeof(memory->bytes);
    memset(memory->bytes, 'x', sizeof(memory->bytes));
}
static int copy(memory_t *memory, uint64_t source, char *destination,
                uint32_t capacity, kernel_user_string_copy_stats_t *stats) {
    return kernel_user_string_copy(read_memory, memory, source, destination,
                                   capacity, EDGE_LINUX_ENAMETOOLONG, stats);
}
static int legacy_result(memory_t *memory, uint64_t source, char *destination,
                         uint32_t capacity) {
    for (uint32_t i = 0; i < capacity; ++i) {
        char byte;
        if (source > UINT64_MAX - i ||
            read_memory(memory, &byte, source + i, 1) < 0)
            return -EDGE_LINUX_EFAULT;
        destination[i] = byte;
        if (!byte) return (int)i;
    }
    destination[capacity - 1] = 0;
    return -EDGE_LINUX_ENAMETOOLONG;
}

static int direct_read(void *context, void *destination,
                       uint64_t source, uint64_t length) {
    uint32_t *calls = context;
    ++*calls;
    assert(length <= 128 && length <= 4096 - (source & 4095));
    memcpy(destination, (const void *)(uintptr_t)source, (size_t)length);
    return 0;
}
static void guard_pages(void) {
    long page = sysconf(_SC_PAGESIZE);
    assert(page > 0 && page % 4096 == 0);
    char *mapping = mmap(0, (size_t)page * 2, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANON, -1, 0);
    assert(mapping != MAP_FAILED);
    assert(mprotect(mapping + page, (size_t)page, PROT_NONE) == 0);
    mapping[page - 2] = 'a';
    mapping[page - 1] = 0;
    char destination[256];
    memset(destination, '#', sizeof(destination));
    uint32_t calls = 0;
    kernel_user_string_copy_stats_t stats;
    assert(kernel_user_string_copy(direct_read, &calls,
        (uintptr_t)(mapping + page - 2), destination, sizeof(destination),
        EDGE_LINUX_ENAMETOOLONG, &stats) == 1);
    assert(calls == 1 && stats.requested_bytes == 2);
    assert(destination[0] == 'a' && !destination[1] && destination[2] == '#');
    assert(mprotect(mapping + page, (size_t)page, PROT_READ | PROT_WRITE) == 0);
    memcpy(mapping + page - 2, "abc", 4);
    calls = 0;
    assert(kernel_user_string_copy(direct_read, &calls,
        (uintptr_t)(mapping + page - 2), destination, sizeof(destination),
        EDGE_LINUX_ENAMETOOLONG, &stats) == 3);
    assert(calls == 2 && strcmp(destination, "abc") == 0);
    assert(munmap(mapping, (size_t)page * 2) == 0);
}

int main(void) {
    memory_t memory;
    kernel_user_string_copy_stats_t stats;
    char destination[4098], reference[4098];
    reset(&memory);
    memory.bytes[2047] = 0;
    memset(destination, '#', sizeof(destination));
    assert(copy(&memory, memory.base, destination, 4096, &stats) == 2047);
    assert(stats.calls == 16 && memory.calls == 16 && memory.largest == 128);
    assert(destination[2048] == '#');
    printf("2048-byte string: 16 architecture callbacks (legacy: 2048)\n");

    reset(&memory);
    memory.readable = 1;
    memory.bytes[0] = 0;
    memset(destination, '#', sizeof(destination));
    assert(copy(&memory, memory.base, destination, 128, &stats) == 0);
    assert(stats.calls == 2 && !destination[0] && destination[1] == '#');

    reset(&memory);
    memory.reject_bulk = 1;
    memcpy(memory.bytes, "hello", 6);
    assert(copy(&memory, memory.base, destination, 128, &stats) == 5);
    assert(stats.calls == 7 && strcmp(destination, "hello") == 0);

    reset(&memory);
    memory.readable = 128;
    memset(destination, '#', sizeof(destination));
    assert(copy(&memory, memory.base, destination, 256, &stats) == -EDGE_LINUX_EFAULT);
    assert(stats.calls == 3 && destination[127] == 'x' && destination[128] == '#');

    reset(&memory);
    assert(copy(&memory, memory.base, destination, 128, &stats) == -EDGE_LINUX_ENAMETOOLONG);
    assert(stats.calls == 1 && destination[126] == 'x' && destination[127] == 0);
    memory.bytes[127] = 0;
    assert(copy(&memory, memory.base, destination, 128, &stats) == 127);
    assert(stats.calls == 1);
    assert(kernel_user_string_copy(read_memory, &memory, memory.base,
        destination, 1, EDGE_LINUX_E2BIG, &stats) == -EDGE_LINUX_E2BIG);
    assert(destination[0] == 0 && stats.calls == 1);
    memory.bytes[0] = 0;
    assert(copy(&memory, memory.base, destination, 1, &stats) == 0);
    assert(copy(&memory, 0, destination, 1, &stats) == -EDGE_LINUX_EFAULT);
    assert(!stats.calls);
    assert(copy(&memory, memory.base, 0, 1, &stats) == -EDGE_LINUX_EIO);
    assert(copy(&memory, memory.base, destination, 0, &stats) == -EDGE_LINUX_EIO);
    assert(!stats.calls);

    reset(&memory);
    memory.readable = 4096;
    memset(destination, '#', sizeof(destination));
    assert(copy(&memory, memory.base + 4094, destination, 128, &stats) ==
           -EDGE_LINUX_EFAULT);
    assert(stats.calls == 3 && destination[1] == 'x' && destination[2] == '#');

    reset(&memory);
    memory.base = UINT64_MAX - 1;
    memory.readable = 2;
    memset(destination, '#', sizeof(destination));
    assert(copy(&memory, memory.base, destination, 3, &stats) == -EDGE_LINUX_EFAULT);
    assert(stats.calls == 1 && destination[2] == '#');
    memory.bytes[1] = 0;
    assert(copy(&memory, memory.base, destination, 3, &stats) == 1);
    assert(stats.calls == 1);
    assert(copy(&memory, UINT64_MAX, destination, 3, &stats) == 0);
    assert(stats.calls == 1);

    /* Compare return values and successful/truncated output to the bytewise
     * contract over offsets, partial readability, terminators and limits. */
    uint32_t random = 17;
    for (uint32_t test = 0; test < 10000; ++test) {
        reset(&memory);
        random = random * 1664525u + 1013904223u;
        uint32_t offset = random % 4096;
        uint32_t capacity = 1 + ((random >> 12) % 512);
        memory.readable = offset + ((random >> 20) % 600);
        memory.bytes[offset + ((random >> 4) % 550)] = 0;
        memory.reject_bulk = (test % 7) == 0;
        memset(destination, '#', sizeof(destination));
        memset(reference, '#', sizeof(reference));
        int expected = legacy_result(&memory, memory.base + offset, reference, capacity);
        memory.calls = 0;
        int actual = copy(&memory, memory.base + offset, destination, capacity, &stats);
        assert(actual == expected);
        if (actual != -EDGE_LINUX_EFAULT)
            assert(memcmp(destination, reference, sizeof(destination)) == 0);
        assert(stats.calls == memory.calls);
        assert(stats.calls <= capacity + (capacity + 127) / 128 + 2);
    }
    guard_pages();
    puts("user_string_copy_unit: PASS");
    return 0;
}
