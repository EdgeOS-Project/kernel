/* SPDX-License-Identifier: MPL-2.0 */
/* Original EdgeOS swapped-page map unit test. */

#include <stdint.h>
#include <stdio.h>

#include "mm/swap_map.h"

static int g_failures;
static uint32_t g_retain_count;
static uint32_t g_release_count;
static uint8_t g_swap_map_memory[64u * 64u];

static void expect_true(const char *name, int condition) {
    if (condition) return;
    fprintf(stderr, "FAIL: %s\n", name);
    ++g_failures;
}

int swap_retain_entry(uint64_t entry) {
    if (!entry) return -1;
    ++g_retain_count;
    return 0;
}

void swap_release_entry(uint64_t entry) {
    if (entry) ++g_release_count;
}

int main(void) {
    uint64_t entry = 0;
    uint64_t space = 0;
    uint64_t address = 0;

    expect_true("memory-sized capacity",
                edge_swap_map_capacity_for_memory(1048576u) == 262144u);
    expect_true("initialize dynamic map",
                edge_swap_map_initialize(
                    g_swap_map_memory, sizeof(g_swap_map_memory), 64u) == 0);
    expect_true("empty map", edge_swap_map_count() == 0u);
    expect_true("insert first page",
                edge_swap_map_insert(0x1000u, 0x4123u, 0x8001u) == 0);
    expect_true("align page key",
                edge_swap_map_acquire(0x1000u, 0x4fffu, &entry) == 0 &&
                entry == 0x8001u && g_retain_count == 1u);
    swap_release_entry(entry);
    expect_true("duplicate rejected",
                edge_swap_map_insert(0x1000u, 0x4000u, 0x8002u) < 0);
    expect_true("insert adjacent page",
                edge_swap_map_insert(0x1000u, 0x5000u, 0x8003u) == 0);
    expect_true("move swapped range",
                edge_swap_map_move_range(
                    0x1000u, 0x4000u, 0x14000u, 0x2000u) == 0 &&
                edge_swap_map_acquire(
                    0x1000u, 0x15000u, &entry) == 0 &&
                entry == 0x8003u);
    swap_release_entry(entry);
    expect_true("insert second address space",
                edge_swap_map_insert(0x2000u, 0x4000u, 0x9001u) == 0);
    expect_true("find entry for swapoff",
                edge_swap_map_find_entry(
                    0x9001u, &space, &address) == 0 &&
                space == 0x2000u && address == 0x4000u);
    swap_release_entry(0x9001u);
    expect_true("clone address space",
                edge_swap_map_clone_space(0x1000u, 0x3000u) == 0 &&
                edge_swap_map_count() == 5u && g_retain_count == 5u);
    expect_true("clone page visible",
                edge_swap_map_acquire(0x3000u, 0x15000u, &entry) == 0 &&
                entry == 0x8003u);
    swap_release_entry(entry);
    expect_true("drop source subrange",
                edge_swap_map_drop_range(0x1000u, 0x14000u, 0x1000u) == 1u &&
                edge_swap_map_count() == 4u);
    expect_true("take transfers ownership",
                edge_swap_map_take(0x2000u, 0x4000u, &entry) == 0 &&
                entry == 0x9001u && edge_swap_map_count() == 3u);
    swap_release_entry(entry);
    edge_swap_map_release_space(0x3000u);
    expect_true("release cloned space",
                edge_swap_map_count() == 1u);
    edge_swap_map_release_space(0x1000u);
    expect_true("release final space",
                edge_swap_map_count() == 0u);
    expect_true("balanced map ownership",
                g_release_count == 9u);
    if (g_failures) return 1;
    puts("swap_map_unit: PASS");
    return 0;
}
