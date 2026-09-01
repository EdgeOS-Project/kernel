#ifndef _EDGEOS_LINUXKPI_REGULATOR_CONSUMER_H_
#define _EDGEOS_LINUXKPI_REGULATOR_CONSUMER_H_

#include_next <linux/regulator/consumer.h>
#include <linux/device.h>

struct regulator {
	bool enabled;
};

static inline struct regulator *
devm_of_regulator_get_optional(struct device *dev,
    struct device_node *node, const char *name)
{
	(void)dev;
	(void)node;
	(void)name;
	return (ERR_PTR(-ENODEV));
}

static inline int
regulator_is_enabled(struct regulator *regulator)
{
	return (regulator != NULL && regulator->enabled);
}

static inline int
regulator_enable(struct regulator *regulator)
{
	if (regulator == NULL)
		return (-EINVAL);
	regulator->enabled = true;
	return (0);
}

static inline int
regulator_disable(struct regulator *regulator)
{
	if (regulator == NULL)
		return (-EINVAL);
	regulator->enabled = false;
	return (0);
}

static inline int
regulator_get_voltage(struct regulator *regulator)
{
	return (regulator != NULL ? 5000000 : -EINVAL);
}

static inline int
devm_regulator_get_enable_optional(struct device *dev, const char *name)
{
	(void)dev;
	(void)name;
	return (0);
}

static inline int
devm_regulator_get_enable(struct device *dev, const char *name)
{
	(void)dev;
	(void)name;
	return (-ENODEV);
}

static inline struct regulator *
devm_regulator_get(struct device *dev, const char *name)
{
	(void)dev;
	(void)name;
	return (ERR_PTR(-ENODEV));
}

static inline struct regulator *
devm_regulator_get_optional(struct device *dev, const char *name)
{
	(void)dev;
	(void)name;
	return (ERR_PTR(-ENODEV));
}

static inline struct regulator *
devm_regulator_get_exclusive(struct device *dev, const char *name)
{
	return (devm_regulator_get(dev, name));
}

#endif /* _EDGEOS_LINUXKPI_REGULATOR_CONSUMER_H_ */
