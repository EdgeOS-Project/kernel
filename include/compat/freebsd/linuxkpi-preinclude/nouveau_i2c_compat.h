#ifndef EDGEOS_FREEBSD_LINUXKPI_NOUVEAU_I2C_COMPAT_H
#define EDGEOS_FREEBSD_LINUXKPI_NOUVEAU_I2C_COMPAT_H

#include <linux/i2c-algo-bit.h>

static const struct i2c_algorithm edgeos_nouveau_i2c_bit_algo = {
	.master_xfer = lkpi_i2cbb_transfer,
};

static inline int
edgeos_nouveau_i2c_bit_add_bus(struct i2c_adapter *adapter)
{
	int result;

	result = lkpi_i2c_bit_add_bus(adapter);
	if (result == 0)
		adapter->algo = &edgeos_nouveau_i2c_bit_algo;
	return result;
}

#undef i2c_bit_add_bus
#define i2c_bit_add_bus(_adapter) \
	edgeos_nouveau_i2c_bit_add_bus(_adapter)
#define i2c_bit_algo edgeos_nouveau_i2c_bit_algo

#endif
