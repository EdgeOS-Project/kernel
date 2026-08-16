/* SPDX-License-Identifier: MPL-2.0 */
/*
 * EdgeOS watchdog driver interface.
 *
 * Copyright (c) EdgeOS Contributors.
 *
 * This is original EdgeOS glue around hardware watchdog implementations.
 * Linux userspace sees /dev/watchdog and WDIOC_* ioctls; drivers underneath
 * must expose real timer hardware and must not fake success when hardware is
 * absent or a feature is unsupported.
 */

#ifndef EDGEOS_DRIVERS_WATCHDOG_H
#define EDGEOS_DRIVERS_WATCHDOG_H

#include <stdint.h>

void watchdog_init(void);
int watchdog_available(void);
int watchdog_pci_function_ready(uint8_t bus, uint8_t slot, uint8_t func);
int watchdog_pci_device_supported(uint16_t vendor, uint16_t device);
const char *watchdog_pci_device_name(uint16_t vendor, uint16_t device);
int watchdog_enable(void);
int watchdog_disable(void);
int watchdog_keepalive(void);
int watchdog_set_timeout(int seconds);
int watchdog_get_timeout(void);
int watchdog_get_timeleft(void);
int watchdog_is_running(void);
int watchdog_write(const char *buf, uint32_t len);
const char *watchdog_identity(void);

#endif
