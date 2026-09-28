/* SPDX-License-Identifier: MPL-2.0 */
/* Copyright (c) EdgeOS Contributors. */

#include "drivers/virtio_gpu_damage.h"

static uint32_t rect_right(const display_rect_t *rect)
{
    return rect->x + rect->width;
}

static uint32_t rect_bottom(const display_rect_t *rect)
{
    return rect->y + rect->height;
}

static uint64_t rect_area(const display_rect_t *rect)
{
    return (uint64_t)rect->width * rect->height;
}

static display_rect_t rect_union(const display_rect_t *left,
                                 const display_rect_t *right)
{
    display_rect_t result;
    uint32_t x2 = rect_right(left);
    uint32_t y2 = rect_bottom(left);
    uint32_t right_x2 = rect_right(right);
    uint32_t right_y2 = rect_bottom(right);

    result.x = left->x < right->x ? left->x : right->x;
    result.y = left->y < right->y ? left->y : right->y;
    if (right_x2 > x2) x2 = right_x2;
    if (right_y2 > y2) y2 = right_y2;
    result.width = x2 - result.x;
    result.height = y2 - result.y;
    return result;
}

static int rects_touch(const display_rect_t *left,
                       const display_rect_t *right)
{
    return left->x <= rect_right(right) &&
           right->x <= rect_right(left) &&
           left->y <= rect_bottom(right) &&
           right->y <= rect_bottom(left);
}

static int normalize_rect(display_rect_t *rect, uint32_t screen_width,
                          uint32_t screen_height)
{
    if (!rect->width || !rect->height || rect->x >= screen_width ||
        rect->y >= screen_height)
        return 0;
    if (rect->width > screen_width - rect->x)
        rect->width = screen_width - rect->x;
    if (rect->height > screen_height - rect->y)
        rect->height = screen_height - rect->y;
    return rect->width != 0u && rect->height != 0u;
}

static void remove_rect(virtio_gpu_damage_t *damage, uint32_t index)
{
    for (uint32_t current = index + 1u; current < damage->count; ++current)
        damage->rects[current - 1u] = damage->rects[current];
    damage->count--;
}

static void collapse_smallest_growth(virtio_gpu_damage_t *damage)
{
    uint32_t best_left = 0u;
    uint32_t best_right = 1u;
    uint64_t best_growth = UINT64_MAX;

    for (uint32_t left = 0; left < damage->count; ++left) {
        for (uint32_t right = left + 1u; right < damage->count; ++right) {
            display_rect_t combined = rect_union(&damage->rects[left],
                                                  &damage->rects[right]);
            uint64_t growth = rect_area(&combined) -
                rect_area(&damage->rects[left]) -
                rect_area(&damage->rects[right]);

            if (growth < best_growth) {
                best_growth = growth;
                best_left = left;
                best_right = right;
            }
        }
    }
    damage->rects[best_left] = rect_union(&damage->rects[best_left],
                                          &damage->rects[best_right]);
    remove_rect(damage, best_right);
    damage->compacted++;
}

static void promote_full_screen(virtio_gpu_damage_t *damage,
                                uint32_t screen_width,
                                uint32_t screen_height)
{
    damage->rects[0].x = 0u;
    damage->rects[0].y = 0u;
    damage->rects[0].width = screen_width;
    damage->rects[0].height = screen_height;
    damage->count = 1u;
    damage->full_screen = 1u;
}

static void merge_touching(virtio_gpu_damage_t *damage)
{
    uint32_t left = 0u;

    while (left < damage->count) {
        uint32_t right = left + 1u;
        int combined = 0;

        while (right < damage->count) {
            if (!rects_touch(&damage->rects[left], &damage->rects[right])) {
                right++;
                continue;
            }
            damage->rects[left] = rect_union(&damage->rects[left],
                                              &damage->rects[right]);
            remove_rect(damage, right);
            damage->merged++;
            combined = 1;
        }
        if (!combined) left++;
    }
}

void virtio_gpu_damage_reset(virtio_gpu_damage_t *damage)
{
    if (!damage) return;
    for (uint32_t index = 0; index < VIRTIO_GPU_DAMAGE_MAX_RECTS; ++index) {
        damage->rects[index].x = 0u;
        damage->rects[index].y = 0u;
        damage->rects[index].width = 0u;
        damage->rects[index].height = 0u;
    }
    damage->count = 0u;
    damage->merged = 0u;
    damage->compacted = 0u;
    damage->full_screen = 0u;
}

uint64_t virtio_gpu_damage_area(const virtio_gpu_damage_t *damage)
{
    uint64_t area = 0u;

    if (!damage) return 0u;
    for (uint32_t index = 0; index < damage->count; ++index)
        area += rect_area(&damage->rects[index]);
    return area;
}

void virtio_gpu_damage_add(virtio_gpu_damage_t *damage,
                           const display_rect_t *rects, uint32_t count,
                           uint32_t screen_width, uint32_t screen_height)
{
    uint64_t screen_area;

    if (!damage || !rects || !screen_width || !screen_height ||
        damage->full_screen)
        return;
    screen_area = (uint64_t)screen_width * screen_height;
    for (uint32_t index = 0; index < count; ++index) {
        display_rect_t rect = rects[index];

        if (!normalize_rect(&rect, screen_width, screen_height)) continue;
        if (damage->count == VIRTIO_GPU_DAMAGE_MAX_RECTS)
            collapse_smallest_growth(damage);
        damage->rects[damage->count++] = rect;
        merge_touching(damage);
        if (virtio_gpu_damage_area(damage) * 100u >= screen_area * 60u) {
            promote_full_screen(damage, screen_width, screen_height);
            return;
        }
    }
}
