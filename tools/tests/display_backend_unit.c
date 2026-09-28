/* SPDX-License-Identifier: MPL-2.0 */
/* Unit tests for the shared display backend registry. */

#include <assert.h>
#include <stdint.h>
#include <stdio.h>

#include "display.h"

typedef struct test_display {
    display_mode_t mode;
    display_mode_t modes[3];
    uint32_t mode_count;
    uint32_t presents;
    uint32_t batches;
    uint32_t polls;
    uint8_t edid[4];
} test_display_t;

static uint32_t
test_get_modes(void *context, display_mode_t *modes, uint32_t capacity)
{
    test_display_t *display = context;
    uint32_t count = display->mode_count < capacity ?
        display->mode_count : capacity;

    for (uint32_t index = 0; modes && index < count; ++index)
        modes[index] = display->modes[index];
    return display->mode_count;
}

static uint32_t
test_get_edid(void *context, uint8_t *edid, uint32_t capacity)
{
    test_display_t *display = context;
    uint32_t count = capacity < sizeof(display->edid) ?
        capacity : sizeof(display->edid);

    for (uint32_t index = 0; edid && index < count; ++index)
        edid[index] = display->edid[index];
    return sizeof(display->edid);
}

static void
test_checksum(uint8_t block[128])
{
    uint8_t sum = 0;

    block[127] = 0;
    for (uint32_t index = 0; index < 127u; ++index)
        sum = (uint8_t)(sum + block[index]);
    block[127] = (uint8_t)(0u - sum);
}

static void
test_advanced_edid(void)
{
    uint8_t edid[256] = {0};
    uint8_t *displayid = edid + 128u;
    uint8_t *timing = displayid + 8u;
    display_mode_t modes[4];
    uint32_t raw_clock = 3519999u;
    int count;

    edid[0] = 0x00u;
    for (uint32_t index = 1u; index < 7u; ++index)
        edid[index] = 0xffu;
    edid[7] = 0x00u;
    edid[18] = 1u;
    edid[19] = 4u;
    edid[21] = 70u;
    edid[22] = 39u;
    for (uint32_t index = 38u; index < 54u; index += 2u) {
        edid[index] = 0x01u;
        edid[index + 1u] = 0x01u;
    }
    edid[126] = 1u;
    test_checksum(edid);

    displayid[0] = 0x70u;
    displayid[1] = 0x01u;
    displayid[2] = 23u;
    displayid[5] = 0x03u;
    displayid[6] = 0x01u;
    displayid[7] = 20u;
    timing[0] = (uint8_t)raw_clock;
    timing[1] = (uint8_t)(raw_clock >> 8);
    timing[2] = (uint8_t)(raw_clock >> 16);
    timing[3] = 0x80u;
    timing[4] = 0xffu;
    timing[5] = 0x1du;
    timing[6] = 0x3fu;
    timing[7] = 0x01u;
    timing[8] = 63u;
    timing[10] = 31u;
    timing[12] = 0xdfu;
    timing[13] = 0x10u;
    timing[14] = 79u;
    timing[16] = 7u;
    timing[18] = 7u;
    test_checksum(displayid);

    count = display_edid_parse(
        edid, sizeof(edid), modes, 4u, NULL, NULL);
    assert(count == 1);
    assert(modes[0].width == 7680u && modes[0].height == 4320u);
    assert(modes[0].refresh_millihz == 1000000u);
    assert(display_mode_frame_interval_us(&modes[0]) == 1000u);
    assert((modes[0].flags & DISPLAY_MODE_PREFERRED) != 0);
}

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
        .modes = {
            {
                .width = 800,
                .height = 600,
                .refresh_millihz = 60000,
            },
            {
                .width = 7680,
                .height = 4320,
                .refresh_millihz = 1000000,
                .flags = DISPLAY_MODE_PREFERRED,
            },
        },
        .mode_count = 2u,
        .edid = { 0x00u, 0xffu, 0xffu, 0x00u },
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
            .get_modes = test_get_modes,
            .get_edid = test_get_edid,
            .set_mode = test_set_mode,
            .poll = test_poll,
        },
    };
    display_backend_t snapshot;
    display_mode_t mode;
    display_mode_t modes[3];
    uint8_t edid[4];
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
    assert(display_backend_get_modes(modes, 3u) == 2u);
    assert(modes[1].width == 7680u && modes[1].height == 4320u);
    assert(display_backend_get_edid(edid, sizeof(edid)) == sizeof(edid));
    assert(edid[0] == 0x00u && edid[1] == 0xffu);
    assert(display_mode_frame_interval_us(&modes[1]) == 1000u);
    mode.refresh_millihz = 144000u;
    assert(display_mode_frame_interval_us(&mode) == 6944u);
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
    test_advanced_edid();
    puts("display_backend_unit: PASS");
    return 0;
}
