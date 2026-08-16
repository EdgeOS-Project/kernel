/* SPDX-License-Identifier: MPL-2.0 */
/* Host behavior tests for the shared BSD LED adapter. */

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <dev/led/led.h>

#include "compat/freebsd/edgeos/allocator.h"

#define TEST_PAGE_SIZE 4096u

typedef struct led_test_state {
    int calls;
    int state;
} led_test_state_t;

static void *
allocate_pages(uint64_t pages, void *context)
{
    void *memory = 0;

    (void)context;
    if (pages > SIZE_MAX / TEST_PAGE_SIZE ||
        posix_memalign(&memory, TEST_PAGE_SIZE,
        (size_t)pages * TEST_PAGE_SIZE) != 0)
        return 0;
    memset(memory, 0, (size_t)pages * TEST_PAGE_SIZE);
    return memory;
}

static void
release_pages(void *base, uint64_t pages, void *context)
{
    (void)pages;
    (void)context;
    free(base);
}

static void
record_state(void *context, int state)
{
    led_test_state_t *test = context;

    ++test->calls;
    test->state = state;
}

int
main(void)
{
    bsd_allocator_ops_t allocator = {
        .allocate_pages = allocate_pages,
        .release_pages = release_pages,
    };
    led_test_state_t first = {0};
    led_test_state_t second = {0};
    struct cdev *first_device;
    struct cdev *second_device;

    assert(bsd_allocator_initialize(&allocator) == 0);
    assert(led_create_state(0, &first, "invalid", 1) == 0);
    assert(led_create_state(record_state, &first, "", 1) == 0);

    first_device = led_create_state(
        record_state, &first, "status", 1);
    assert(first_device != 0);
    assert(first.calls == 1 && first.state == 1);
    assert(led_set("status", "off") == 0);
    assert(first.calls == 2 && first.state == 0);
    assert(led_set("status", "1") == 0);
    assert(first.calls == 3 && first.state == 1);
    assert(led_set("status", "blink") == 22);
    assert(led_set("missing", "on") == 2);

    second_device = led_create(record_state, &second, "activity");
    assert(second_device != 0);
    assert(second.calls == 1 && second.state == 0);
    assert(led_set("activity", "on") == 0);
    assert(second.calls == 2 && second.state == 1);

    led_destroy(second_device);
    assert(led_set("activity", "off") == 2);
    led_destroy(first_device);
    assert(led_set("status", "off") == 2);

    printf("bsd_bridge_led_unit: PASS\n");
    return 0;
}
