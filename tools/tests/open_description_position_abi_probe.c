/*
 * Copyright (c) EdgeOS Contributors.
 * SPDX-License-Identifier: MPL-2.0
 */

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

enum {
    READ_RECORD_COUNT = 4096,
    THREAD_COUNT = 8,
    WRITE_ITERATIONS = 512,
};

typedef struct write_record {
    uint32_t writer;
    uint32_t sequence;
    uint64_t checksum;
} write_record_t;

typedef struct read_context {
    int descriptor;
    atomic_uint *seen;
    atomic_uint *failures;
} read_context_t;

typedef struct write_context {
    int descriptor;
    uint32_t writer;
    atomic_uint *failures;
} write_context_t;

static uint64_t record_checksum(uint32_t writer, uint32_t sequence) {
    uint64_t value =
        ((uint64_t)writer << 32) | (uint64_t)sequence;
    value ^= UINT64_C(0x9e3779b97f4a7c15);
    value *= UINT64_C(0xbf58476d1ce4e5b9);
    value ^= value >> 31;
    return value;
}

static void fail(atomic_uint *failures, const char *message) {
    atomic_fetch_add_explicit(
        failures, 1u, memory_order_relaxed);
    fprintf(stderr, "FAIL %s errno=%d\n", message, errno);
}

static int write_full(int descriptor, const void *buffer, size_t length) {
    const uint8_t *bytes = (const uint8_t *)buffer;
    size_t done = 0;

    while (done < length) {
        ssize_t written = write(
            descriptor, bytes + done, length - done);
        if (written < 0 && errno == EINTR) continue;
        if (written <= 0) return -1;
        done += (size_t)written;
    }
    return 0;
}

static void *read_worker(void *opaque) {
    read_context_t *context = (read_context_t *)opaque;

    for (;;) {
        uint64_t record = UINT64_MAX;
        ssize_t received = read(
            context->descriptor, &record, sizeof(record));
        if (received < 0 && errno == EINTR) continue;
        if (received == 0) break;
        if (received != (ssize_t)sizeof(record)) {
            fail(context->failures, "shared read returned partial record");
            break;
        }
        if (record >= READ_RECORD_COUNT) {
            fail(context->failures, "shared read returned invalid record");
            continue;
        }
        if (atomic_fetch_add_explicit(
                &context->seen[record], 1u,
                memory_order_relaxed) != 0u)
            fail(context->failures, "shared read duplicated a record");
    }
    return 0;
}

static void *write_worker(void *opaque) {
    write_context_t *context = (write_context_t *)opaque;

    for (uint32_t sequence = 0;
         sequence < WRITE_ITERATIONS; ++sequence) {
        write_record_t record;
        ssize_t written;

        record.writer = context->writer;
        record.sequence = sequence;
        record.checksum =
            record_checksum(record.writer, record.sequence);
        do {
            written = write(
                context->descriptor, &record, sizeof(record));
        } while (written < 0 && errno == EINTR);
        if (written != (ssize_t)sizeof(record)) {
            fail(context->failures,
                 "shared write did not commit one complete record");
            break;
        }
    }
    return 0;
}

static int duplicate_descriptors(int source,
                                 int descriptors[THREAD_COUNT]) {
    descriptors[0] = source;
    for (uint32_t index = 1; index < THREAD_COUNT; ++index) {
        descriptors[index] = dup(source);
        if (descriptors[index] < 0) {
            for (uint32_t prior = 1; prior < index; ++prior)
                close(descriptors[prior]);
            return -1;
        }
    }
    return 0;
}

static void close_duplicates(int descriptors[THREAD_COUNT]) {
    for (uint32_t index = 1; index < THREAD_COUNT; ++index)
        close(descriptors[index]);
}

static void test_shared_reads(int descriptor,
                              atomic_uint *failures) {
    atomic_uint seen[READ_RECORD_COUNT];
    int descriptors[THREAD_COUNT];
    read_context_t contexts[THREAD_COUNT];
    pthread_t threads[THREAD_COUNT];

    if (ftruncate(descriptor, 0) < 0 ||
        lseek(descriptor, 0, SEEK_SET) < 0) {
        fail(failures, "prepare shared read file");
        return;
    }
    for (uint64_t record = 0;
         record < READ_RECORD_COUNT; ++record) {
        if (write_full(descriptor, &record, sizeof(record)) < 0) {
            fail(failures, "populate shared read file");
            return;
        }
        atomic_init(&seen[record], 0u);
    }
    if (lseek(descriptor, 0, SEEK_SET) != 0 ||
        duplicate_descriptors(descriptor, descriptors) < 0) {
        fail(failures, "duplicate shared read descriptors");
        return;
    }

    for (uint32_t index = 0; index < THREAD_COUNT; ++index) {
        contexts[index].descriptor = descriptors[index];
        contexts[index].seen = seen;
        contexts[index].failures = failures;
        if (pthread_create(
                &threads[index], 0, read_worker,
                &contexts[index]) != 0) {
            fail(failures, "create shared read worker");
            exit(2);
        }
    }
    for (uint32_t index = 0; index < THREAD_COUNT; ++index)
        pthread_join(threads[index], 0);
    close_duplicates(descriptors);

    for (uint32_t record = 0;
         record < READ_RECORD_COUNT; ++record) {
        if (atomic_load_explicit(
                &seen[record], memory_order_relaxed) != 1u)
            fail(failures, "shared read missed a record");
    }
}

static void test_failed_user_copy_preserves_position(
    int descriptor, atomic_uint *failures) {
    off_t before;
    off_t after;
    long result;

    before = lseek(descriptor, 17, SEEK_SET);
    errno = 0;
    result = syscall(
        SYS_read, descriptor, (void *)(uintptr_t)1u, 8u);
    after = lseek(descriptor, 0, SEEK_CUR);
    if (before != 17 || result != -1 || errno != EFAULT ||
        after != before)
        fail(failures, "read EFAULT changed shared position");

    before = lseek(descriptor, 29, SEEK_SET);
    errno = 0;
    result = syscall(
        SYS_write, descriptor,
        (const void *)(uintptr_t)1u, 8u);
    after = lseek(descriptor, 0, SEEK_CUR);
    if (before != 29 || result != -1 || errno != EFAULT ||
        after != before)
        fail(failures, "write EFAULT changed shared position");
}

static void test_shared_writes(int descriptor, int append,
                               atomic_uint *failures) {
    enum {
        TOTAL_RECORDS = THREAD_COUNT * WRITE_ITERATIONS,
    };
    atomic_uint seen[TOTAL_RECORDS];
    int descriptors[THREAD_COUNT];
    write_context_t contexts[THREAD_COUNT];
    pthread_t threads[THREAD_COUNT];
    struct stat status;
    int flags;

    if (ftruncate(descriptor, 0) < 0 ||
        lseek(descriptor, 0, SEEK_SET) < 0) {
        fail(failures, "prepare shared write file");
        return;
    }
    flags = fcntl(descriptor, F_GETFL);
    if (flags < 0 ||
        fcntl(descriptor, F_SETFL,
              append ? flags | O_APPEND :
                       flags & ~O_APPEND) < 0 ||
        duplicate_descriptors(descriptor, descriptors) < 0) {
        fail(failures, "configure shared write descriptors");
        return;
    }
    for (uint32_t index = 0; index < TOTAL_RECORDS; ++index)
        atomic_init(&seen[index], 0u);

    for (uint32_t index = 0; index < THREAD_COUNT; ++index) {
        contexts[index].descriptor = descriptors[index];
        contexts[index].writer = index;
        contexts[index].failures = failures;
        if (pthread_create(
                &threads[index], 0, write_worker,
                &contexts[index]) != 0) {
            fail(failures, "create shared write worker");
            exit(2);
        }
    }
    for (uint32_t index = 0; index < THREAD_COUNT; ++index)
        pthread_join(threads[index], 0);
    close_duplicates(descriptors);

    if (fstat(descriptor, &status) < 0 ||
        status.st_size !=
            (off_t)(TOTAL_RECORDS * sizeof(write_record_t))) {
        fail(failures, "shared writes produced incorrect file size");
        return;
    }
    for (uint32_t position = 0;
         position < TOTAL_RECORDS; ++position) {
        write_record_t record;
        uint32_t identity;
        ssize_t received = pread(
            descriptor, &record, sizeof(record),
            (off_t)position * (off_t)sizeof(record));
        if (received != (ssize_t)sizeof(record) ||
            record.writer >= THREAD_COUNT ||
            record.sequence >= WRITE_ITERATIONS ||
            record.checksum !=
                record_checksum(record.writer, record.sequence)) {
            fail(failures, "shared writes corrupted a record");
            continue;
        }
        identity =
            record.writer * WRITE_ITERATIONS + record.sequence;
        if (atomic_fetch_add_explicit(
                &seen[identity], 1u,
                memory_order_relaxed) != 0u)
            fail(failures, "shared writes duplicated a record");
    }
    for (uint32_t index = 0; index < TOTAL_RECORDS; ++index) {
        if (atomic_load_explicit(
                &seen[index], memory_order_relaxed) != 1u)
            fail(failures, "shared writes missed a record");
    }
}

int main(void) {
    char path[] = "/tmp/edgeos-position-abi-XXXXXX";
    atomic_uint failures;
    int descriptor;

    _Static_assert(sizeof(write_record_t) == 16u,
                   "write record ABI");
    atomic_init(&failures, 0u);
    descriptor = mkstemp(path);
    if (descriptor < 0) {
        perror("mkstemp");
        return 2;
    }
    unlink(path);

    test_shared_reads(descriptor, &failures);
    test_failed_user_copy_preserves_position(
        descriptor, &failures);
    test_shared_writes(descriptor, 0, &failures);
    test_shared_writes(descriptor, 1, &failures);
    close(descriptor);

    if (atomic_load_explicit(
            &failures, memory_order_relaxed)) {
        fprintf(stderr,
                "OPEN_DESCRIPTION_POSITION_ABI_FAIL failures=%u\n",
                atomic_load_explicit(
                    &failures, memory_order_relaxed));
        return 1;
    }
    puts("OPEN_DESCRIPTION_POSITION_ABI_PASS");
    return 0;
}
