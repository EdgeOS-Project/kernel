/* SPDX-License-Identifier: MPL-2.0 */
/*
 * EdgeOS I2C adapter interface.
 *
 * Copyright (c) EdgeOS Contributors.
 */

#ifndef EDGEOS_DRIVERS_I2C_H
#define EDGEOS_DRIVERS_I2C_H

#include <stdint.h>

#define EDGE_I2C_OK       0
#define EDGE_I2C_ENODEV  -19
#define EDGE_I2C_EINVAL  -22
#define EDGE_I2C_EOPNOTSUPP -95

void i2c_init(void);
int i2c_adapter_count(void);
int i2c_smbus_read_byte_data(uint8_t adapter, uint8_t addr_7bit,
                             uint8_t command, uint8_t *out);
int i2c_smbus_read_word_data(uint8_t adapter, uint8_t addr_7bit,
                             uint8_t command, uint16_t *out);
int i2c_smbus_write_byte_data(uint8_t adapter, uint8_t addr_7bit,
                              uint8_t command, uint8_t value);
int i2c_smbus_write_word_data(uint8_t adapter, uint8_t addr_7bit,
                              uint8_t command, uint16_t value);

#endif
