/* SPDX-License-Identifier: MPL-2.0 */

#include <assert.h>
#include <stdio.h>

#include "drivers/virtio_gpu_damage.h"

static void test_cursor_stays_small(void)
{
    virtio_gpu_damage_t damage;
    display_rect_t cursor = { 100u, 200u, 64u, 64u };

    virtio_gpu_damage_reset(&damage);
    virtio_gpu_damage_add(&damage, &cursor, 1u, 1920u, 1080u);
    assert(damage.count == 1u);
    assert(!damage.full_screen);
    assert(virtio_gpu_damage_area(&damage) == 4096u);
}

static void test_adjacent_rectangles_merge(void)
{
    virtio_gpu_damage_t damage;
    display_rect_t rects[] = {
        { 0u, 0u, 100u, 50u },
        { 100u, 0u, 100u, 50u },
    };

    virtio_gpu_damage_reset(&damage);
    virtio_gpu_damage_add(&damage, rects, 2u, 1920u, 1080u);
    assert(damage.count == 1u);
    assert(damage.rects[0].width == 200u);
    assert(damage.rects[0].height == 50u);
    assert(damage.merged == 1u);
}

static void test_many_rectangles_are_bounded(void)
{
    virtio_gpu_damage_t damage;
    display_rect_t rects[12];

    for (uint32_t index = 0; index < 12u; ++index) {
        rects[index].x = index * 120u;
        rects[index].y = (index & 1u) ? 100u : 0u;
        rects[index].width = 32u;
        rects[index].height = 32u;
    }
    virtio_gpu_damage_reset(&damage);
    virtio_gpu_damage_add(&damage, rects, 12u, 1920u, 1080u);
    assert(damage.count <= VIRTIO_GPU_DAMAGE_MAX_RECTS);
    assert(damage.compacted != 0u);
    assert(!damage.full_screen);
}

static void test_large_damage_promotes_to_full_screen(void)
{
    virtio_gpu_damage_t damage;
    display_rect_t rect = { 0u, 0u, 1920u, 700u };

    virtio_gpu_damage_reset(&damage);
    virtio_gpu_damage_add(&damage, &rect, 1u, 1920u, 1080u);
    assert(damage.full_screen);
    assert(damage.count == 1u);
    assert(damage.rects[0].width == 1920u);
    assert(damage.rects[0].height == 1080u);
}

static void test_damage_is_clipped(void)
{
    virtio_gpu_damage_t damage;
    display_rect_t rect = { 1900u, 1060u, 100u, 100u };

    virtio_gpu_damage_reset(&damage);
    virtio_gpu_damage_add(&damage, &rect, 1u, 1920u, 1080u);
    assert(damage.count == 1u);
    assert(damage.rects[0].width == 20u);
    assert(damage.rects[0].height == 20u);
}

int main(void)
{
    test_cursor_stays_small();
    test_adjacent_rectangles_merge();
    test_many_rectangles_are_bounded();
    test_large_damage_promotes_to_full_screen();
    test_damage_is_clipped();
    puts("virtio_gpu_damage_unit: PASS");
    return 0;
}
