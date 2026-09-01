#ifndef _EDGEOS_LINUXKPI_POWER_SUPPLY_H_
#define _EDGEOS_LINUXKPI_POWER_SUPPLY_H_

#include_next <linux/power_supply.h>
#include <linux/device.h>
#include <linux/slab.h>

enum power_supply_usb_type {
	POWER_SUPPLY_USB_TYPE_UNKNOWN,
	POWER_SUPPLY_USB_TYPE_C,
	POWER_SUPPLY_USB_TYPE_PD,
	POWER_SUPPLY_USB_TYPE_PD_PPS,
	POWER_SUPPLY_USB_TYPE_PD_PPS_SPR_AVS,
	POWER_SUPPLY_USB_TYPE_PD_SPR_AVS,
};

enum power_supply_property {
	POWER_SUPPLY_PROP_USB_TYPE,
	POWER_SUPPLY_PROP_ONLINE,
	POWER_SUPPLY_PROP_VOLTAGE_MIN,
	POWER_SUPPLY_PROP_VOLTAGE_MAX,
	POWER_SUPPLY_PROP_VOLTAGE_NOW,
	POWER_SUPPLY_PROP_CURRENT_MAX,
	POWER_SUPPLY_PROP_CURRENT_NOW,
	POWER_SUPPLY_PROP_SCOPE,
	POWER_SUPPLY_PROP_INPUT_POWER_LIMIT,
	POWER_SUPPLY_PROP_CHARGE_TYPE,
	POWER_SUPPLY_PROP_STATUS,
};

enum power_supply_scope {
	POWER_SUPPLY_SCOPE_UNKNOWN,
	POWER_SUPPLY_SCOPE_SYSTEM,
	POWER_SUPPLY_SCOPE_DEVICE,
};

enum power_supply_status {
	POWER_SUPPLY_STATUS_UNKNOWN,
	POWER_SUPPLY_STATUS_CHARGING,
	POWER_SUPPLY_STATUS_DISCHARGING,
	POWER_SUPPLY_STATUS_NOT_CHARGING,
};

enum power_supply_charge_type {
	POWER_SUPPLY_CHARGE_TYPE_UNKNOWN,
	POWER_SUPPLY_CHARGE_TYPE_NONE,
	POWER_SUPPLY_CHARGE_TYPE_TRICKLE,
	POWER_SUPPLY_CHARGE_TYPE_STANDARD,
};

enum power_supply_type {
	POWER_SUPPLY_TYPE_UNKNOWN,
	POWER_SUPPLY_TYPE_USB,
};

union power_supply_propval {
	int intval;
	const char *strval;
};

struct power_supply;

struct power_supply_desc {
	const char *name;
	enum power_supply_type type;
	unsigned long usb_types;
	enum power_supply_property *properties;
	size_t num_properties;
	int (*get_property)(struct power_supply *, enum power_supply_property,
	    union power_supply_propval *);
	int (*set_property)(struct power_supply *, enum power_supply_property,
	    const union power_supply_propval *);
	int (*property_is_writeable)(struct power_supply *,
	    enum power_supply_property);
};

struct power_supply_config {
	void *drv_data;
	struct fwnode_handle *fwnode;
};

struct power_supply {
	void *drv_data;
	const struct power_supply_desc *desc;
};

static inline struct power_supply *
devm_power_supply_register(struct device *dev,
    const struct power_supply_desc *desc,
    const struct power_supply_config *config)
{
	struct power_supply *supply;

	supply = devm_kzalloc(dev, sizeof(*supply), GFP_KERNEL);
	if (supply == NULL)
		return (ERR_PTR(-ENOMEM));
	supply->desc = desc;
	supply->drv_data = config != NULL ? config->drv_data : dev_get_drvdata(dev);
	return (supply);
}

static inline void *
power_supply_get_drvdata(struct power_supply *supply)
{
	return (supply->drv_data);
}

static inline void
power_supply_changed(struct power_supply *supply)
{
	(void)supply;
}

static inline struct power_supply *
power_supply_register(struct device *dev, const struct power_supply_desc *desc,
    const struct power_supply_config *config)
{
	struct power_supply *supply;

	(void)dev;
	supply = kzalloc(sizeof(*supply), GFP_KERNEL);
	if (supply == NULL)
		return (ERR_PTR(-ENOMEM));
	supply->desc = desc;
	supply->drv_data = config != NULL ? config->drv_data : NULL;
	return (supply);
}

static inline void
power_supply_unregister(struct power_supply *supply)
{
	kfree(supply);
}

#endif /* _EDGEOS_LINUXKPI_POWER_SUPPLY_H_ */
