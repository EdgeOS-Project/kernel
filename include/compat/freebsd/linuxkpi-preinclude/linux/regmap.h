#ifndef _EDGEOS_LINUXKPI_REGMAP_H_
#define _EDGEOS_LINUXKPI_REGMAP_H_

#include <linux/i2c.h>
#include <linux/slab.h>

struct regmap_config {
	unsigned int reg_bits;
	unsigned int val_bits;
	unsigned int max_register;
	unsigned int reg_stride;
	unsigned int cache_type;
	bool use_single_read;
	bool use_single_write;
	bool disable_locking;
	const struct regmap_range_cfg *ranges;
	unsigned int num_ranges;
	bool (*writeable_reg)(struct device *, unsigned int);
	bool (*readable_reg)(struct device *, unsigned int);
	bool (*volatile_reg)(struct device *, unsigned int);
	bool (*precious_reg)(struct device *, unsigned int);
	const struct regmap_access_table *wr_table;
};

#ifndef REGCACHE_MAPLE
#define REGCACHE_MAPLE 1
#endif

struct regmap_range_cfg {
	unsigned int range_min;
	unsigned int range_max;
	unsigned int selector_reg;
	unsigned int selector_mask;
	unsigned int selector_shift;
	unsigned int window_start;
	unsigned int window_len;
};

struct regmap_range {
	unsigned int range_min;
	unsigned int range_max;
};

struct regmap_access_table {
	const struct regmap_range *yes_ranges;
	unsigned int n_yes_ranges;
};

struct reg_sequence {
	unsigned int reg;
	unsigned int def;
	unsigned int delay_us;
};

#define regmap_reg_range(_min, _max) \
	{ .range_min = (_min), .range_max = (_max) }
#define REG_SEQ(_reg, _value, _delay) \
	{ .reg = (_reg), .def = (_value), .delay_us = (_delay) }

struct regmap {
	struct i2c_client *client;
};

static inline struct regmap *
devm_regmap_init_i2c(struct i2c_client *client,
    const struct regmap_config *config)
{
	struct regmap *map;

	(void)config;
	map = devm_kzalloc(&client->dev, sizeof(*map), GFP_KERNEL);
	if (map == NULL)
		return (ERR_PTR(-ENOMEM));
	map->client = client;
	return (map);
}

static inline int
regmap_read(struct regmap *map, unsigned int reg, unsigned int *value)
{
	int result;

	*value = 0;
	result = i2c_smbus_read_byte_data(map->client, reg);
	if (result < 0)
		return (result);
	*value = (unsigned int)result;
	return (0);
}

static inline int
regmap_write(struct regmap *map, unsigned int reg, unsigned int value)
{
	return (i2c_smbus_write_byte_data(map->client, reg, value));
}

static inline int
regmap_update_bits(struct regmap *map, unsigned int reg,
    unsigned int mask, unsigned int value)
{
	unsigned int reg_value;
	int result;

	result = regmap_read(map, reg, &reg_value);
	if (result != 0)
		return (result);
	reg_value = (reg_value & ~mask) | (value & mask);
	return (regmap_write(map, reg, reg_value));
}

#define regmap_write_bits(_map, _reg, _mask, _value) \
	regmap_update_bits((_map), (_reg), (_mask), (_value))

static inline int
regmap_assign_bits(struct regmap *map, unsigned int reg,
    unsigned int mask, bool value)
{
	return (regmap_update_bits(map, reg, mask, value ? mask : 0));
}

static inline int
regmap_test_bits(struct regmap *map, unsigned int reg, unsigned int bits)
{
	unsigned int value;
	int result;

	result = regmap_read(map, reg, &value);
	return (result != 0 ? result : ((value & bits) != 0));
}

#define regmap_set_bits(_map, _reg, _bits) \
	regmap_update_bits((_map), (_reg), (_bits), (_bits))
#define regmap_clear_bits(_map, _reg, _bits) \
	regmap_update_bits((_map), (_reg), (_bits), 0)

static inline int
regmap_raw_read(struct regmap *map, unsigned int reg, void *value,
    size_t length)
{
	memset(value, 0, length);
	return (i2c_smbus_read_i2c_block_data(map->client, reg, length, value));
}

static inline int
regmap_raw_write(struct regmap *map, unsigned int reg, const void *value,
    size_t length)
{
	return (i2c_smbus_write_i2c_block_data(map->client, reg, length, value));
}

static inline int
regmap_bulk_read(struct regmap *map, unsigned int reg, void *value,
    size_t count)
{
	return (regmap_raw_read(map, reg, value, count));
}

static inline int
regmap_bulk_write(struct regmap *map, unsigned int reg, const void *value,
    size_t count)
{
	return (regmap_raw_write(map, reg, value, count));
}

static inline int
regcache_sync(struct regmap *map)
{
	(void)map;
	return (0);
}

static inline struct regmap *
dev_get_regmap(struct device *dev, const char *name)
{
	(void)dev;
	(void)name;
	return (NULL);
}

static inline int
regmap_register_patch(struct regmap *map, const struct reg_sequence *sequence,
    int count)
{
	(void)map;
	(void)sequence;
	(void)count;
	return (0);
}

#define regmap_read_poll_timeout(_map, _reg, _value, _condition, \
    _sleep_us, _timeout_us) ({ \
	int __result; \
	unsigned int __elapsed = 0; \
	do { \
		__result = regmap_read((_map), (_reg), &(_value)); \
		if (__result != 0 || (_condition)) \
			break; \
		udelay(_sleep_us); \
		__elapsed += (_sleep_us); \
	} while (__elapsed < (_timeout_us)); \
	__result != 0 ? __result : ((_condition) ? 0 : -ETIMEDOUT); \
})

#endif /* _EDGEOS_LINUXKPI_REGMAP_H_ */
