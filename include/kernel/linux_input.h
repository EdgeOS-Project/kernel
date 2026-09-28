/* SPDX-License-Identifier: MPL-2.0 */
/* Architecture-independent Linux evdev ioctl policy. */

#ifndef EDGEOS_KERNEL_LINUX_INPUT_H
#define EDGEOS_KERNEL_LINUX_INPUT_H

#include <stdint.h>
#include "kernel/file_description_runtime.h"

#define EDGE_LINUX_INPUT_EVENT_SIZE 24u
#define EDGE_LINUX_INPUT_IOCTL_BUFFER_SIZE 128u

typedef enum {
    EDGE_LINUX_INPUT_ACTION_NONE = 0,
    EDGE_LINUX_INPUT_ACTION_SET_CLOCK = 1,
    EDGE_LINUX_INPUT_ACTION_GRAB = 2,
    EDGE_LINUX_INPUT_ACTION_REVOKE = 3
} edge_linux_input_action_t;

typedef struct {
    int64_t return_value;
    uint32_t output_length;
    edge_linux_input_action_t action;
    int32_t action_value;
} edge_linux_input_ioctl_result_t;

uint32_t edge_linux_input_ioctl_input_size(uint32_t command);
int edge_linux_input_ioctl_execute(
    uint32_t device, uint32_t role, uint32_t command,
    const void *input, uint32_t input_length,
    void *output, uint32_t output_capacity,
    edge_linux_input_ioctl_result_t *result);
int edge_linux_input_description_check(
    kernel_file_description_locator_t locator);
int edge_linux_input_description_may_read(
    uint32_t device, kernel_file_description_locator_t locator);
int edge_linux_input_description_action(
    uint32_t device, kernel_file_description_locator_t locator,
    edge_linux_input_action_t action, int32_t value);

#endif
