/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS test code.
 * Copyright (c) EdgeOS Contributors.
 *
 * Linux userspace regression coverage for large epoll batches and faults
 * encountered after a prefix of the event array has been copied.  A
 * successfully copied EPOLLONESHOT event is committed, while an event whose
 * copy faults must remain armed and available to a later epoll_wait().
 */

#define _GNU_SOURCE

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/mman.h>
#include <unistd.h>

#define LARGE_SOURCE_COUNT 128
#define FAULT_SOURCE_COUNT 4
#define WAIT_EVENT_CAPACITY 256
#define TOKEN_INDEX_MASK UINT64_C(0xffff)
#define LARGE_TOKEN_TAG UINT64_C(0x4c41524745000000)
#define PARTIAL_TOKEN_TAG UINT64_C(0x5041525449000000)
#define FIRST_FAULT_TOKEN_TAG UINT64_C(0x4641554c54000000)

#if defined(__x86_64__)
_Static_assert(sizeof(struct epoll_event) == 12,
               "x86_64 Linux epoll_event must use its packed ABI layout");
#elif defined(__aarch64__)
_Static_assert(sizeof(struct epoll_event) == 16,
               "AArch64 Linux epoll_event must use its natural ABI layout");
#endif

struct ready_set {
    int epoll_descriptor;
    int descriptors[LARGE_SOURCE_COUNT];
    size_t count;
};

static uint64_t event_token(uint64_t tag, size_t index)
{
    return tag | (uint64_t)(index + 1);
}

static void ready_set_destroy(struct ready_set *set)
{
    size_t index;

    for (index = 0; index < set->count; ++index) {
        if (set->descriptors[index] >= 0)
            (void)close(set->descriptors[index]);
    }
    if (set->epoll_descriptor >= 0)
        (void)close(set->epoll_descriptor);
    set->epoll_descriptor = -1;
    set->count = 0;
}

static int ready_set_create(struct ready_set *set, size_t count,
                            uint32_t event_flags, uint64_t tag)
{
    struct epoll_event registration;
    size_t index;

    memset(set, 0, sizeof(*set));
    set->epoll_descriptor = -1;
    for (index = 0; index < LARGE_SOURCE_COUNT; ++index)
        set->descriptors[index] = -1;

    if (count > LARGE_SOURCE_COUNT) {
        fprintf(stderr, "ready_set_create: invalid source count %zu\n",
                count);
        return -1;
    }
    set->epoll_descriptor = epoll_create1(EPOLL_CLOEXEC);
    if (set->epoll_descriptor < 0) {
        perror("epoll_create1");
        return -1;
    }
    for (index = 0; index < count; ++index) {
        int descriptor = eventfd(1, EFD_CLOEXEC | EFD_NONBLOCK);

        if (descriptor < 0) {
            perror("eventfd");
            ready_set_destroy(set);
            return -1;
        }
        set->descriptors[index] = descriptor;
        set->count = index + 1;
        memset(&registration, 0, sizeof(registration));
        registration.events = event_flags;
        registration.data.u64 = event_token(tag, index);
        if (epoll_ctl(set->epoll_descriptor, EPOLL_CTL_ADD, descriptor,
                      &registration) != 0) {
            perror("epoll_ctl(EPOLL_CTL_ADD)");
            ready_set_destroy(set);
            return -1;
        }
    }
    return 0;
}

static int record_events(const char *test_name,
                         const struct epoll_event *events, int event_count,
                         uint64_t tag, size_t source_count,
                         unsigned char *seen)
{
    int failures = 0;
    int position;

    for (position = 0; position < event_count; ++position) {
        uint64_t token = events[position].data.u64;
        uint64_t encoded_index = token & TOKEN_INDEX_MASK;
        size_t index;

        if (!(events[position].events & EPOLLIN)) {
            fprintf(stderr,
                    "%s: event %d is missing EPOLLIN (events=0x%x)\n",
                    test_name, position, events[position].events);
            ++failures;
        }
        if ((token & ~TOKEN_INDEX_MASK) != tag || encoded_index == 0 ||
            encoded_index > source_count) {
            fprintf(stderr,
                    "%s: event %d has invalid token 0x%016llx\n",
                    test_name, position, (unsigned long long)token);
            ++failures;
            continue;
        }
        index = (size_t)encoded_index - 1;
        if (seen[index]) {
            fprintf(stderr,
                    "%s: source %zu was delivered more than once\n",
                    test_name, index);
            ++failures;
            continue;
        }
        seen[index] = 1;
    }
    return failures;
}

static size_t seen_count(const unsigned char *seen, size_t source_count)
{
    size_t count = 0;
    size_t index;

    for (index = 0; index < source_count; ++index)
        count += seen[index] != 0;
    return count;
}

static int require_all_seen(const char *test_name,
                            const unsigned char *seen, size_t source_count)
{
    size_t index;

    for (index = 0; index < source_count; ++index) {
        if (!seen[index]) {
            fprintf(stderr, "%s: source %zu was not delivered\n",
                    test_name, index);
            return 1;
        }
    }
    return 0;
}

static int require_drained(const char *test_name, int epoll_descriptor)
{
    struct epoll_event event;
    int result;

    errno = 0;
    result = epoll_wait(epoll_descriptor, &event, 1, 0);
    if (result != 0) {
        fprintf(stderr,
                "%s: one-shot set was not drained (result=%d errno=%d)\n",
                test_name, result, errno);
        return 1;
    }
    return 0;
}

static void *create_guarded_mapping(size_t *page_size_out)
{
    long page_size_value = sysconf(_SC_PAGESIZE);
    size_t page_size;
    unsigned char *mapping;

    if (page_size_value <= 0) {
        fprintf(stderr, "sysconf(_SC_PAGESIZE) failed\n");
        return MAP_FAILED;
    }
    page_size = (size_t)page_size_value;
    if (2 * sizeof(struct epoll_event) > page_size) {
        fprintf(stderr,
                "epoll_event records do not fit before one page boundary\n");
        return MAP_FAILED;
    }
    mapping = mmap(NULL, page_size * 2, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mapping == MAP_FAILED) {
        perror("mmap");
        return MAP_FAILED;
    }
    if (mprotect(mapping + page_size, page_size, PROT_NONE) != 0) {
        perror("mprotect");
        (void)munmap(mapping, page_size * 2);
        return MAP_FAILED;
    }
    *page_size_out = page_size;
    return mapping;
}

static int test_large_delivery(void)
{
    struct ready_set set;
    struct epoll_event events[WAIT_EVENT_CAPACITY];
    unsigned char seen[LARGE_SOURCE_COUNT] = {0};
    int failures = 0;
    int result;

    if (ready_set_create(&set, LARGE_SOURCE_COUNT,
                         EPOLLIN | EPOLLONESHOT,
                         LARGE_TOKEN_TAG) != 0)
        return 1;

    memset(events, 0, sizeof(events));
    errno = 0;
    result = epoll_wait(set.epoll_descriptor, events, WAIT_EVENT_CAPACITY, 0);
    if (result != LARGE_SOURCE_COUNT) {
        fprintf(stderr,
                "large_delivery: expected %d events in one wait, got %d "
                "(errno=%d)\n",
                LARGE_SOURCE_COUNT, result, errno);
        ++failures;
    }
    if (result <= 64) {
        fprintf(stderr,
                "large_delivery: result %d did not exceed the old "
                "64-event ceiling\n",
                result);
        ++failures;
    }
    if (result > 0) {
        int inspect_count = result;

        if (inspect_count > WAIT_EVENT_CAPACITY)
            inspect_count = WAIT_EVENT_CAPACITY;
        failures += record_events("large_delivery", events, inspect_count,
                                  LARGE_TOKEN_TAG, LARGE_SOURCE_COUNT, seen);
    }
    failures += require_all_seen("large_delivery", seen,
                                 LARGE_SOURCE_COUNT);
    failures += require_drained("large_delivery", set.epoll_descriptor);
    ready_set_destroy(&set);
    return failures;
}

static int test_partial_copy_fault(void)
{
    struct ready_set set;
    struct epoll_event retry_events[FAULT_SOURCE_COUNT];
    unsigned char seen[FAULT_SOURCE_COUNT] = {0};
    unsigned char *mapping;
    struct epoll_event *boundary_events;
    size_t page_size = 0;
    size_t delivered;
    int failures = 0;
    int result;

    if (ready_set_create(&set, FAULT_SOURCE_COUNT,
                         EPOLLIN | EPOLLET | EPOLLONESHOT,
                         PARTIAL_TOKEN_TAG) != 0)
        return 1;
    mapping = create_guarded_mapping(&page_size);
    if (mapping == MAP_FAILED) {
        ready_set_destroy(&set);
        return 1;
    }
    boundary_events = (struct epoll_event *)
        (mapping + page_size - 2 * sizeof(struct epoll_event));
    memset(boundary_events, 0, 2 * sizeof(*boundary_events));

    errno = 0;
    result = epoll_wait(set.epoll_descriptor, boundary_events,
                        WAIT_EVENT_CAPACITY, 0);
    if (result != 2) {
        fprintf(stderr,
                "partial_copy: expected a committed two-event prefix, "
                "got %d (errno=%d)\n",
                result, errno);
        ++failures;
    }
    if (result > 0) {
        int inspect_count = result > 2 ? 2 : result;

        failures += record_events("partial_copy_prefix", boundary_events,
                                  inspect_count, PARTIAL_TOKEN_TAG,
                                  FAULT_SOURCE_COUNT, seen);
    }

    delivered = seen_count(seen, FAULT_SOURCE_COUNT);
    memset(retry_events, 0, sizeof(retry_events));
    errno = 0;
    result = epoll_wait(set.epoll_descriptor, retry_events,
                        FAULT_SOURCE_COUNT, 0);
    if (result != (int)(FAULT_SOURCE_COUNT - delivered)) {
        fprintf(stderr,
                "partial_copy: retry expected %zu uncommitted events, "
                "got %d (errno=%d)\n",
                FAULT_SOURCE_COUNT - delivered, result, errno);
        ++failures;
    }
    if (result > 0) {
        int inspect_count = result;

        if (inspect_count > FAULT_SOURCE_COUNT)
            inspect_count = FAULT_SOURCE_COUNT;
        failures += record_events("partial_copy_retry", retry_events,
                                  inspect_count, PARTIAL_TOKEN_TAG,
                                  FAULT_SOURCE_COUNT, seen);
    }
    failures += require_all_seen("partial_copy", seen, FAULT_SOURCE_COUNT);
    failures += require_drained("partial_copy", set.epoll_descriptor);

    (void)munmap(mapping, page_size * 2);
    ready_set_destroy(&set);
    return failures;
}

static int test_first_record_fault(void)
{
    struct ready_set set;
    struct epoll_event retry_events[FAULT_SOURCE_COUNT];
    unsigned char seen[FAULT_SOURCE_COUNT] = {0};
    unsigned char *mapping;
    size_t page_size = 0;
    int failures = 0;
    int result;

    if (ready_set_create(&set, FAULT_SOURCE_COUNT,
                         EPOLLIN | EPOLLET | EPOLLONESHOT,
                         FIRST_FAULT_TOKEN_TAG) != 0)
        return 1;
    mapping = create_guarded_mapping(&page_size);
    if (mapping == MAP_FAILED) {
        ready_set_destroy(&set);
        return 1;
    }

    errno = 0;
    result = epoll_wait(set.epoll_descriptor,
                        (struct epoll_event *)(mapping + page_size),
                        WAIT_EVENT_CAPACITY, 0);
    if (result != -1 || errno != EFAULT) {
        fprintf(stderr,
                "first_record_fault: expected -1/EFAULT, got %d/%d\n",
                result, errno);
        ++failures;
    }

    memset(retry_events, 0, sizeof(retry_events));
    errno = 0;
    result = epoll_wait(set.epoll_descriptor, retry_events,
                        FAULT_SOURCE_COUNT, 0);
    if (result != FAULT_SOURCE_COUNT) {
        fprintf(stderr,
                "first_record_fault: retry expected all %d events, "
                "got %d (errno=%d)\n",
                FAULT_SOURCE_COUNT, result, errno);
        ++failures;
    }
    if (result > 0) {
        int inspect_count = result;

        if (inspect_count > FAULT_SOURCE_COUNT)
            inspect_count = FAULT_SOURCE_COUNT;
        failures += record_events("first_record_fault_retry", retry_events,
                                  inspect_count, FIRST_FAULT_TOKEN_TAG,
                                  FAULT_SOURCE_COUNT, seen);
    }
    failures += require_all_seen("first_record_fault", seen,
                                 FAULT_SOURCE_COUNT);
    failures += require_drained("first_record_fault",
                                set.epoll_descriptor);

    (void)munmap(mapping, page_size * 2);
    ready_set_destroy(&set);
    return failures;
}

int main(void)
{
    int failures = 0;

    setvbuf(stdout, NULL, _IONBF, 0);
    failures += test_large_delivery();
    failures += test_partial_copy_fault();
    failures += test_first_record_fault();
    if (failures) {
        fprintf(stderr,
                "EPOLL_BATCH_COPY_FAULT_ABI_FAIL failures=%d "
                "event_size=%zu\n",
                failures, sizeof(struct epoll_event));
        return 1;
    }
    printf("EPOLL_BATCH_COPY_FAULT_ABI_PASS large=%d partial=2+2 "
           "first_fault=%d event_size=%zu\n",
           LARGE_SOURCE_COUNT, FAULT_SOURCE_COUNT,
           sizeof(struct epoll_event));
    return 0;
}
