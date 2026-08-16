/* SPDX-License-Identifier: MPL-2.0 */
/* Unit tests for shared BSD event registration and invocation. */

#include <assert.h>
#include <stdint.h>
#include <stdlib.h>

#include "compat/freebsd/edgeos/allocator.h"
#include "compat/freebsd/sys/eventhandler.h"

static int g_log[128];
static int g_log_count;

static void
test_handler(void *argument, uintptr_t value)
{
    g_log[g_log_count++] = *(int *)argument + (int)value;
}

static void *
test_allocate_pages(uint64_t page_count, void *context)
{
    void *memory = 0;

    (void)context;
    if (page_count > SIZE_MAX / 4096U ||
        posix_memalign(&memory, 4096U,
        (size_t)page_count * 4096U) != 0)
        return 0;
    return memory;
}

static void
test_release_pages(void *base, uint64_t page_count, void *context)
{
    (void)page_count;
    (void)context;
    free(base);
}

int
main(void)
{
    bsd_allocator_ops_t allocator_operations = {
        .allocate_pages = test_allocate_pages,
        .release_pages = test_release_pages,
    };
    int first = 10;
    int second = 20;
    eventhandler_tag later;
    eventhandler_tag earlier;

    assert(bsd_allocator_initialize(&allocator_operations) == 0);
    later = EVENTHANDLER_REGISTER(test_event, test_handler, &second, 200);
    earlier = EVENTHANDLER_REGISTER(test_event, test_handler, &first, 100);
    assert(later != 0);
    assert(earlier != 0);
    assert(bsd_eventhandler_count("test_event") == 2);

    EVENTHANDLER_INVOKE(test_event, (uintptr_t)3);
    assert(g_log_count == 2);
    assert(g_log[0] == 13);
    assert(g_log[1] == 23);

    EVENTHANDLER_DEREGISTER(test_event, earlier);
    assert(bsd_eventhandler_count("test_event") == 1);
    EVENTHANDLER_INVOKE(test_event, (uintptr_t)5);
    assert(g_log_count == 3);
    assert(g_log[2] == 25);
    EVENTHANDLER_DEREGISTER_NOWAIT(test_event, later);
    assert(bsd_eventhandler_count("test_event") == 0);
    assert(bsd_eventhandler_count("missing_event") == 0);

    {
        int arguments[64];
        eventhandler_tag tags[64];

        g_log_count = 0;
        for (int index = 63; index >= 0; --index) {
            arguments[index] = index;
            tags[index] = EVENTHANDLER_REGISTER(bulk_event,
                test_handler, &arguments[index], index);
            assert(tags[index] != 0);
        }
        assert(bsd_eventhandler_count("bulk_event") == 64);
        EVENTHANDLER_INVOKE(bulk_event, (uintptr_t)7);
        assert(g_log_count == 64);
        for (int index = 0; index < 64; ++index) {
            assert(g_log[index] == index + 7);
            EVENTHANDLER_DEREGISTER(bulk_event, tags[index]);
        }
        assert(bsd_eventhandler_count("bulk_event") == 0);
    }
    return 0;
}
