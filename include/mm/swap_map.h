/* SPDX-License-Identifier: MPL-2.0 */
/* Original EdgeOS architecture-neutral swapped-page map. */

#ifndef EDGEOS_MM_SWAP_MAP_H
#define EDGEOS_MM_SWAP_MAP_H

#include <stdint.h>

uint32_t edge_swap_map_capacity_for_memory(uint64_t memory_pages);
uint64_t edge_swap_map_pool_bytes(uint32_t capacity);
int edge_swap_map_initialize(void *memory, uint64_t memory_bytes,
                             uint32_t capacity);
int edge_swap_map_insert(uint64_t address_space, uint64_t address,
                         uint64_t swap_entry);
int edge_swap_map_acquire(uint64_t address_space, uint64_t address,
                          uint64_t *swap_entry_out);
int edge_swap_map_take(uint64_t address_space, uint64_t address,
                       uint64_t *swap_entry_out);
uint32_t edge_swap_map_drop_range(uint64_t address_space, uint64_t start,
                                  uint64_t length);
int edge_swap_map_move_range(uint64_t address_space, uint64_t source,
                             uint64_t destination, uint64_t length);
int edge_swap_map_find_entry(uint64_t swap_entry,
                             uint64_t *address_space_out,
                             uint64_t *address_out);
int edge_swap_map_clone_space(uint64_t source_address_space,
                              uint64_t destination_address_space);
void edge_swap_map_release_space(uint64_t address_space);
uint32_t edge_swap_map_count(void);

#endif
