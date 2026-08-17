/* SPDX-License-Identifier: MPL-2.0 */
/* Unit tests for the shared display backend registry. */

#include <assert.h>
#include <stdint.h>
#include <stdio.h>

#include "display.h"

typedef struct test_display {
    display_mode_t mode;
    uint32_t presents;
    uint32_t batches;
    uint32_t polls;
} test_display_t;

static void
test_present(void *context, uint32_t x, uint32_t y, uint32_t width,
             uint32_t height)
{
    test_display_t *display = context;

    assert(x == 2);
    assert(y == 3);
    assert(width == 640);
    assert(height == 480);
    display->presents++;
}

static void
test_present_batch(void *context, const display_rect_t *rects,
                   uint32_t count)
{
    test_display_t *display = context;

    assert(rects != NULL);
    assert(count == 2u);
    assert(rects[0].x == 10u && rects[0].width == 20u);
    assert(rects[1].y == 40u && rects[1].height == 50u);
    display->batches++;
}

static int
test_get_mode(void *context, display_mode_t *mode)
{
    test_display_t *display = context;

    *mode = display->mode;
    return 0;
}

static int
test_set_mode(void *context, const display_mode_t *mode)
{
    test_display_t *display = context;

    display->mode = *mode;
    return 0;
}

static int
test_poll(void *context)
{
    test_display_t *display = context;

    display->polls++;
    return 1;
}

int
main(void)
{
    test_display_t display = {
        .mode = {
            .width = 800,
            .height = 600,
            .refresh_millihz = 60000,
        },
    };
    int owner;
    display_backend_t backend = {
        .name = "test-display",
        .owner = &owner,
        .context = &display,
        .flags = DISPLAY_BACKEND_EXPLICIT_PRESENT |
                 DISPLAY_BACKEND_DYNAMIC_MODE,
        .operations = {
            .present_rect = test_present,
            .present_rects = test_present_batch,
            .get_mode = test_get_mode,
            .set_mode = test_set_mode,
            .poll = test_poll,
        },
    };
    display_backend_t snapshot;
    display_mode_t mode;
    uint64_t generation;
    uint64_t updated_generation;

    assert(display_backend_register(0) < 0);
    assert(display_backend_register(&(display_backend_t){
        .name = "invalid",
        .owner = &owner,
        .flags = DISPLAY_BACKEND_EXPLICIT_PRESENT,
    }) < 0);
    assert(display_backend_register(&backend) == 0);
    assert(display_backend_snapshot(&snapshot, &generation) == 1);
    assert(snapshot.owner == &owner);
    assert(display_backend_is_owner(&owner));
    assert(display_backend_requires_present());
    display_backend_present_rect(2, 3, 640, 480);
    assert(display.presents == 1);
    {
        const display_rect_t rects[2] = {
            { .x = 10u, .y = 11u, .width = 20u, .height = 21u },
            { .x = 30u, .y = 40u, .width = 41u, .height = 50u },
        };
        display_backend_present_rects(rects, 2u);
        assert(display.batches == 1u);
        assert(display.presents == 1u);
    }
    assert(display_backend_get_mode(&mode) == 0);
    assert(mode.width == 800 && mode.height == 600);
    mode.width = 1920;
    mode.height = 1080;
    assert(display_backend_set_mode(&mode) == 0);
    assert(display.mode.width == 1920 && display.mode.height == 1080);
    updated_generation = display_backend_generation();
    assert(updated_generation > generation);
    assert(display_backend_poll() == 1);
    assert(display.polls == 1);
    display_backend_unregister((const void *)(uintptr_t)1);
    assert(display_backend_is_owner(&owner));
    display_backend_unregister(&owner);
    assert(display_backend_snapshot(&snapshot, &generation) == 0);
    assert(!display_backend_requires_present());
    display_backend_reset();
    puts("display_backend_unit: PASS");
    return 0;
}
