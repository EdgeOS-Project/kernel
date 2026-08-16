/* SPDX-License-Identifier: MPL-2.0 */
#ifndef EDGEOS_KERNEL_FILE_MAPPING_POLICY_H
#define EDGEOS_KERNEL_FILE_MAPPING_POLICY_H

/* Keep general sequential readahead capable of 256 KiB windows. */
#define EDGE_FILE_MAPPING_WINDOW_PAGES 64u

/*
 * A page fault is synchronous until the task can return to the scheduler.
 * Bound one fault to 64 KiB so input and display work can run between batches
 * while later faults continue filling the same shared file cache.
 */
#define EDGE_FILE_MAPPING_FAULT_BATCH_PAGES 16u

#endif
