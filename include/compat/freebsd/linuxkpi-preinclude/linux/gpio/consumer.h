#ifndef _EDGEOS_LINUXKPI_GPIO_CONSUMER_H_
#define _EDGEOS_LINUXKPI_GPIO_CONSUMER_H_

#include <linux/device.h>
#include <linux/err.h>

struct gpio_desc {
	int value;
	int irq;
};

enum gpiod_flags {
	GPIOD_ASIS,
	GPIOD_IN,
	GPIOD_OUT_LOW,
	GPIOD_OUT_HIGH,
};

static inline struct gpio_desc *
devm_gpiod_get(struct device *dev, const char *name, enum gpiod_flags flags)
{
	(void)dev;
	(void)name;
	(void)flags;
	return (ERR_PTR(-ENODEV));
}

static inline struct gpio_desc *
devm_gpiod_get_optional(struct device *dev, const char *name,
    enum gpiod_flags flags)
{
	(void)dev;
	(void)name;
	(void)flags;
	return (NULL);
}

static inline struct gpio_desc *
devm_gpiod_get_index_optional(struct device *dev, const char *name,
    unsigned int index, enum gpiod_flags flags)
{
	(void)index;
	return (devm_gpiod_get_optional(dev, name, flags));
}

static inline int
gpiod_get_value(const struct gpio_desc *desc)
{
	return (desc != NULL ? desc->value : 0);
}

static inline int
gpiod_get_value_cansleep(const struct gpio_desc *desc)
{
	return (gpiod_get_value(desc));
}

static inline void
gpiod_set_value(struct gpio_desc *desc, int value)
{
	if (desc != NULL)
		desc->value = value;
}

static inline int
gpiod_set_value_cansleep(struct gpio_desc *desc, int value)
{
	gpiod_set_value(desc, value);
	return (0);
}

static inline int
gpiod_direction_output(struct gpio_desc *desc, int value)
{
	gpiod_set_value(desc, value);
	return (0);
}

static inline int
gpiod_to_irq(const struct gpio_desc *desc)
{
	return (desc != NULL ? desc->irq : -ENXIO);
}

#endif /* _EDGEOS_LINUXKPI_GPIO_CONSUMER_H_ */
