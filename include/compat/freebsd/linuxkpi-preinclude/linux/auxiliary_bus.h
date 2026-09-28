#ifndef _EDGEOS_LINUXKPI_AUXILIARY_BUS_H_
#define _EDGEOS_LINUXKPI_AUXILIARY_BUS_H_

#include <linux/device.h>

struct auxiliary_device {
	struct device dev;
};

struct auxiliary_device_id {
	char name[64];
	kernel_ulong_t driver_data;
};

struct auxiliary_driver {
	const char *name;
	int (*probe)(struct auxiliary_device *, const struct auxiliary_device_id *);
	void (*remove)(struct auxiliary_device *);
	const struct auxiliary_device_id *id_table;
};

static inline void
auxiliary_set_drvdata(struct auxiliary_device *device, void *data)
{
	dev_set_drvdata(&device->dev, data);
}

static inline void *
auxiliary_get_drvdata(struct auxiliary_device *device)
{
	return (dev_get_drvdata(&device->dev));
}

#define module_auxiliary_driver(_driver) \
	static struct auxiliary_driver * const __used \
	edgeos_auxiliary_driver_##_driver = &(_driver)

#endif /* _EDGEOS_LINUXKPI_AUXILIARY_BUS_H_ */
