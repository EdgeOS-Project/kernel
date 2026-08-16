/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS architecture-independent PID index.
 * Copyright (c) EdgeOS Contributors.
 */

#ifndef EDGEOS_KERNEL_PID_INDEX_H
#define EDGEOS_KERNEL_PID_INDEX_H

#include <stdint.h>

/*
 * The native task tables currently hold at most 1024 live tasks. A load
 * factor no greater than 25 percent keeps successful and unsuccessful PID
 * lookups short even after sustained thread churn.
 */
#define EDGE_PID_INDEX_BUCKET_COUNT 4096u

typedef struct edge_pid_index {
    uint64_t buckets[EDGE_PID_INDEX_BUCKET_COUNT];
} edge_pid_index_t;

void edge_pid_index_init(edge_pid_index_t *index);
int edge_pid_index_insert(edge_pid_index_t *index, int32_t pid,
                          uint32_t slot);
int edge_pid_index_lookup(const edge_pid_index_t *index, int32_t pid);
void edge_pid_index_remove(edge_pid_index_t *index, int32_t pid,
                           uint32_t slot);

#endif
