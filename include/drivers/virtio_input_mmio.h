/* SPDX-License-Identifier: MPL-2.0 */
#ifndef EDGEOS_ARCH_ARM64_VIRTIO_INPUT_H
#define EDGEOS_ARCH_ARM64_VIRTIO_INPUT_H

#include "arch/arm64/bootinfo.h"
#include "drivers/virtio_input.h"

int edgeos_arm64_virtio_input_init(const edgeos_arm64_bootinfo_t *bootinfo);
int edgeos_arm64_virtio_input_enable_interrupts(void);
void virtio_input_poll(void);
int virtio_input_getchar(void);
int virtio_input_haschar(void);
int input_has_event(uint32_t device);
uint64_t input_event_sequence(uint32_t device);
uint64_t input_event_cursor_init(uint32_t device);
int input_has_event_from(uint32_t device, uint64_t cursor);
int input_read_event_from(uint32_t device, uint64_t *cursor, int clock_id,
                          void *out, uint32_t length);
int input_write_events(uint32_t device, const void *events,
                                    uint32_t length);

#endif
