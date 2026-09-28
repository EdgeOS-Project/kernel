/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Copyright (c) EdgeOS Contributors.
 *
 * VirtIO console driver interface.
 */

#ifndef DRIVERS_VIRTIO_CONSOLE_H
#define DRIVERS_VIRTIO_CONSOLE_H

#include <stdint.h>

int virtio_console_init(void);
int virtio_console_is_ready(void);
void virtio_console_poll(void);
int virtio_console_read(char *out, uint32_t max);
int virtio_console_write(const char *buf, uint32_t len);

#endif
