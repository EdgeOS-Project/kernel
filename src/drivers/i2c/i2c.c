/* SPDX-License-Identifier: MPL-2.0 */
/*
 * EdgeOS I2C adapter layer.
 *
 * Copyright (c) EdgeOS Contributors.
 *
 * FreeBSD's iicbus/smbus split was used as the design reference: controller
 * drivers own hardware transactions, and the common layer presents adapters.
 * This file currently exposes real SMBus byte/word operations from the Intel
 * ICH/PCH SMBus driver as Linux-compatible I2C adapter building blocks.  It
 * does not claim generic combined-message I2C support until a controller with
 * that transfer mode is wired in.
 */

#include "drivers/i2c.h"
#include "drivers/smbus.h"
#include "stdio.h"

static uint32_t g_i2c_adapters;

static int smbus_to_i2c_error(int err) {
    if (err == 0) return EDGE_I2C_OK;
    return err;
}

void i2c_init(void) {
    g_i2c_adapters = 0;
#ifdef CONFIG_SMBUS
    g_i2c_adapters = (uint32_t)smbus_controller_count();
#endif
    if (g_i2c_adapters) {
        printf("[i2c] registered %u SMBus-backed I2C adapter(s)\n", g_i2c_adapters);
    } else {
        printf("[i2c] no I2C adapters found\n");
    }
}

int i2c_adapter_count(void) {
    return (int)g_i2c_adapters;
}

int i2c_smbus_read_byte_data(uint8_t adapter, uint8_t addr_7bit,
                             uint8_t command, uint8_t *out) {
    if (!out) return EDGE_I2C_EINVAL;
    if (adapter >= g_i2c_adapters) return EDGE_I2C_ENODEV;
#ifdef CONFIG_SMBUS
    return smbus_to_i2c_error(smbus_read_byte(adapter, addr_7bit, command, out));
#else
    (void)addr_7bit; (void)command;
    return EDGE_I2C_EOPNOTSUPP;
#endif
}

int i2c_smbus_read_word_data(uint8_t adapter, uint8_t addr_7bit,
                             uint8_t command, uint16_t *out) {
    if (!out) return EDGE_I2C_EINVAL;
    if (adapter >= g_i2c_adapters) return EDGE_I2C_ENODEV;
#ifdef CONFIG_SMBUS
    return smbus_to_i2c_error(smbus_read_word(adapter, addr_7bit, command, out));
#else
    (void)addr_7bit; (void)command;
    return EDGE_I2C_EOPNOTSUPP;
#endif
}

int i2c_smbus_write_byte_data(uint8_t adapter, uint8_t addr_7bit,
                              uint8_t command, uint8_t value) {
    if (adapter >= g_i2c_adapters) return EDGE_I2C_ENODEV;
#ifdef CONFIG_SMBUS
    return smbus_to_i2c_error(smbus_write_byte(adapter, addr_7bit, command, value));
#else
    (void)addr_7bit; (void)command; (void)value;
    return EDGE_I2C_EOPNOTSUPP;
#endif
}

int i2c_smbus_write_word_data(uint8_t adapter, uint8_t addr_7bit,
                              uint8_t command, uint16_t value) {
    if (adapter >= g_i2c_adapters) return EDGE_I2C_ENODEV;
#ifdef CONFIG_SMBUS
    return smbus_to_i2c_error(smbus_write_word(adapter, addr_7bit, command, value));
#else
    (void)addr_7bit; (void)command; (void)value;
    return EDGE_I2C_EOPNOTSUPP;
#endif
}
