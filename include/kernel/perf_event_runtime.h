/* SPDX-License-Identifier: MPL-2.0 */

#ifndef EDGEOS_KERNEL_PERF_EVENT_RUNTIME_H
#define EDGEOS_KERNEL_PERF_EVENT_RUNTIME_H

#include <stdint.h>

#include "kernel/ioctl_runtime.h"
#include "kernel/perf_event.h"

int kernel_perf_event_create_descriptor(
    const kernel_perf_event_open_request_t *request);
int kernel_perf_event_descriptor_id(int32_t descriptor);
int64_t kernel_perf_event_read_descriptor(
    int32_t descriptor, uint64_t *values, uint32_t value_capacity);
int64_t kernel_perf_event_ioctl(const kernel_ioctl_request_t *request);

#endif
