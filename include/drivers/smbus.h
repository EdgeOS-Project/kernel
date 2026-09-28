/* SPDX-License-Identifier: MPL-2.0 */
/*
 * EdgeOS SMBus controller interface.
 *
 * Copyright (c) EdgeOS Contributors.
 */

#ifndef EDGEOS_DRIVERS_SMBUS_H
#define EDGEOS_DRIVERS_SMBUS_H

#include <stdint.h>

#define EDGE_SMBUS_OK        0
#define EDGE_SMBUS_ENODEV   -1
#define EDGE_SMBUS_EBUSY    -2
#define EDGE_SMBUS_EIO      -3
#define EDGE_SMBUS_ENOACK   -4
#define EDGE_SMBUS_TIMEOUT  -5
#define EDGE_SMBUS_EINVAL   -6

void smbus_init(void);
int smbus_controller_count(void);
int smbus_is_ready(void);
int smbus_pci_function_ready(uint8_t bus, uint8_t slot, uint8_t func);
int smbus_pci_device_supported(uint16_t vendor, uint16_t device);
int smbus_read_byte(uint8_t controller, uint8_t slave_7bit, uint8_t command, uint8_t *out);
int smbus_read_word(uint8_t controller, uint8_t slave_7bit, uint8_t command, uint16_t *out);
int smbus_write_byte(uint8_t controller, uint8_t slave_7bit, uint8_t command, uint8_t value);
int smbus_write_word(uint8_t controller, uint8_t slave_7bit, uint8_t command, uint16_t value);

#endif
