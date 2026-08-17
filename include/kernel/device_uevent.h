/* SPDX-License-Identifier: MPL-2.0 */
/* Original EdgeOS Linux-compatible kobject uevent policy. */

#ifndef EDGEOS_KERNEL_DEVICE_UEVENT_H
#define EDGEOS_KERNEL_DEVICE_UEVENT_H

#include <stdint.h>

/* Emits one Linux kobject event to subscribed NETLINK_KOBJECT_UEVENT peers. */
int kernel_device_uevent_emit(const char *action, const char *path,
                              const char *subsystem, uint32_t major,
                              uint32_t minor, const char *device_name,
                              const char *driver, const char *modalias);

#endif
