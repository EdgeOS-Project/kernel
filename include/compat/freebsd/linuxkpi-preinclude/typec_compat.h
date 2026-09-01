#ifndef _EDGEOS_LINUXKPI_TYPEC_COMPAT_H_
#define _EDGEOS_LINUXKPI_TYPEC_COMPAT_H_

#define MODULE_DEVICE_TABLE_BUS_typec(_bus, _table)
#define MODULE_DEVICE_TABLE_BUS_of(_bus, _table)
#define MODULE_DEVICE_TABLE_BUS_i2c(_bus, _table)
#define MODULE_DEVICE_TABLE_BUS_acpi(_bus, _table)

#include <linux/property.h>
#include <linux/of.h>
#include <linux/sysfs.h>
#include <linux/usb.h>
#include <linux/delay.h>
#include <dev/usb/usb_device.h>
#include <drm/drm_connector.h>

struct kobj_uevent_env {
	char *envp[32];
};

struct bus_type {
	const char *name;
	const struct attribute_group *const *dev_groups;
	int (*match)(struct device *, const struct device_driver *);
	int (*uevent)(const struct device *, struct kobj_uevent_env *);
	int (*probe)(struct device *);
	void (*remove)(struct device *);
};

static inline int
edgeos_linux_bus_register(const struct bus_type *bus)
{
	(void)bus;
	return (0);
}

static inline void
edgeos_linux_bus_unregister(const struct bus_type *bus)
{
	(void)bus;
}

static inline int
edgeos_linux_driver_register(struct device_driver *driver)
{
	(void)driver;
	return (0);
}

static inline void
edgeos_linux_driver_unregister(struct device_driver *driver)
{
	(void)driver;
}

static inline int
edgeos_linux_device_match_type(struct device *dev, const void *type)
{
	return (dev != NULL && dev->type == type);
}

static inline struct device *
edgeos_linux_device_find_child(struct device *parent, const void *data,
    int (*match)(struct device *, const void *))
{
	device_t *children;
	struct device *child;
	int count;
	int index;

	if (parent == NULL || parent->bsddev == NULL || match == NULL)
		return (NULL);
	if (device_get_children(parent->bsddev, &children, &count) != 0)
		return (NULL);
	child = NULL;
	for (index = 0; index < count; index++) {
		child = device_get_softc(children[index]);
		if (child != NULL && match(child, data)) {
			get_device(child);
			break;
		}
		child = NULL;
	}
	free(children, M_TEMP);
	return (child);
}

static inline int
edgeos_linux_device_for_each_child(struct device *parent, void *data,
    int (*callback)(struct device *, void *))
{
	device_t *children;
	struct device *child;
	int count;
	int index;
	int result;

	if (parent == NULL || parent->bsddev == NULL || callback == NULL)
		return (0);
	if (device_get_children(parent->bsddev, &children, &count) != 0)
		return (0);
	result = 0;
	for (index = 0; index < count && result == 0; index++) {
		child = device_get_softc(children[index]);
		if (child != NULL)
			result = callback(child, data);
	}
	free(children, M_TEMP);
	return (result);
}

static inline int
edgeos_add_uevent_var(struct kobj_uevent_env *env, const char *format, ...)
{
	(void)env;
	(void)format;
	return (0);
}

static inline int
edgeos_kobject_uevent(struct kobject *kobj, int action)
{
	kobject_uevent_env(kobj, action, NULL);
	return (0);
}

static inline struct usb_device *
edgeos_to_usb_device(struct device *dev)
{
	return (dev != NULL && dev->bsddev != NULL ?
	    device_get_softc(dev->bsddev) : NULL);
}

#define bus_register(_bus) edgeos_linux_bus_register(_bus)
#define bus_unregister(_bus) edgeos_linux_bus_unregister(_bus)
#define driver_register(_driver) edgeos_linux_driver_register(_driver)
#define driver_unregister(_driver) edgeos_linux_driver_unregister(_driver)
#define device_find_child(_parent, _data, _match) \
	edgeos_linux_device_find_child((_parent), (_data), (_match))
#define device_for_each_child(_parent, _data, _callback) \
	edgeos_linux_device_for_each_child((_parent), (_data), (_callback))
#define device_match_type edgeos_linux_device_match_type
#define add_uevent_var edgeos_add_uevent_var
#define kobject_uevent edgeos_kobject_uevent
#define to_usb_device edgeos_to_usb_device
#define subsys_initcall(_function) module_init(_function)
#define IRQF_TRIGGER_RISING 0x00000001
#define IRQF_TRIGGER_FALLING 0x00000002
#define IRQF_TRIGGER_LOW 0x00000008
#define IRQF_TRIGGER_HIGH 0x00000004
#define IRQF_ONESHOT 0x00002000
#define IRQF_NO_AUTOEN 0x00080000
#define usb_debug_root NULL
#ifndef dev_vdbg
#define dev_vdbg(_dev, _format, ...) do { (void)(_dev); } while (0)
#endif
#ifdef dev_dbg
#undef dev_dbg
#endif
#define dev_dbg(_dev, _format, ...) do { (void)(_dev); } while (0)
#define FW_ACTION_UEVENT 1
#define pm_runtime_put_sync(_dev) ({ (void)(_dev); 0; })
#define pm_runtime_idle(_dev) ({ (void)(_dev); 0; })

static inline void
device_disable_async_suspend(struct device *dev)
{
	(void)dev;
}

static inline bool
device_wakeup_path(struct device *dev)
{
	(void)dev;
	return (false);
}

static inline void
put_unaligned_be32(u32 value, void *pointer)
{
	__be32 encoded = cpu_to_be32(value);
	memcpy(pointer, &encoded, sizeof(encoded));
}

static inline const char *
str_true_false(bool value)
{
	return (value ? "true" : "false");
}

static inline int
enable_irq_wake(unsigned int irq)
{
	(void)irq;
	return (0);
}

static inline int
disable_irq_wake(unsigned int irq)
{
	(void)irq;
	return (0);
}

static inline void
device_set_wakeup_capable(struct device *dev, bool capable)
{
	(void)dev;
	(void)capable;
}

static inline bool
device_may_wakeup(struct device *dev)
{
	return (device_can_wakeup(dev));
}

static inline int
device_init_wakeup(struct device *dev, bool enable)
{
	device_set_wakeup_capable(dev, enable);
	device_set_wakeup_enable(dev, enable);
	return (0);
}

static inline int
devm_device_init_wakeup(struct device *dev)
{
	return (device_init_wakeup(dev, true));
}

#ifndef FIELD_MODIFY
#define FIELD_MODIFY(_mask, _reg, _value) do { \
	*(_reg) = (*(_reg) & ~(_mask)) | FIELD_PREP((_mask), (_value)); \
} while (0)
#endif
#ifndef kthread_run_worker
#define kthread_run_worker(_flags, _format, ...) \
	kthread_create_worker((_flags), (_format), ##__VA_ARGS__)
#endif
#ifndef hrtimer_setup
#define hrtimer_setup(_timer, _function, _clock, _mode) do { \
	hrtimer_init((_timer), (_clock), (_mode)); \
	(_timer)->function = (_function); \
} while (0)
#endif
#ifndef SET_RUNTIME_PM_OPS
#define SET_RUNTIME_PM_OPS(_suspend, _resume, _idle) \
	.runtime_suspend = (_suspend), \
	.runtime_resume = (_resume), \
	.runtime_idle = (_idle),
#endif

#ifdef MODULE_VERSION
#undef MODULE_VERSION
#endif
#define MODULE_VERSION(_version)
#ifdef MODULE_ALIAS
#undef MODULE_ALIAS
#endif
#define MODULE_ALIAS(_alias)
#ifndef CONFIG_DEBUG_FS
#define CONFIG_DEBUG_FS 1
#endif
#ifndef CONFIG_POWER_SUPPLY
#define CONFIG_POWER_SUPPLY 1
#endif

static inline unsigned long
edgeos_bitmap_read(const unsigned long *map, unsigned long start,
    unsigned long count)
{
	unsigned long index;
	unsigned long shift;
	unsigned long value;

	if (map == NULL || count == 0)
		return (0);
	index = start / BITS_PER_LONG;
	shift = start % BITS_PER_LONG;
	value = map[index] >> shift;
	if (shift != 0 && count > BITS_PER_LONG - shift)
		value |= map[index + 1] << (BITS_PER_LONG - shift);
	if (count < BITS_PER_LONG)
		value &= BIT(count) - 1;
	return (value);
}

#define bitmap_read(_map, _start, _count) \
	edgeos_bitmap_read((_map), (_start), (_count))
#ifndef __must_hold
#define __must_hold(_lock)
#endif

static inline bool
device_match_fwnode(struct device *dev, const void *fwnode)
{
	return (dev != NULL && dev->fwnode == fwnode);
}

static inline struct device *
class_find_device(const struct class *class, const struct device *start,
    const void *data, int (*match)(struct device *, const void *))
{
	device_t bsddev;
	struct device *dev;
	int maxunit;
	int unit;

	(void)start;
	if (class == NULL || class->bsdclass == NULL || match == NULL)
		return (NULL);
	maxunit = devclass_get_maxunit(class->bsdclass);
	for (unit = 0; unit < maxunit; unit++) {
		bsddev = devclass_get_device(class->bsdclass, unit);
		if (bsddev == NULL)
			continue;
		dev = device_get_softc(bsddev);
		if (dev != NULL && match(dev, data))
			return (get_device(dev));
	}
	return (NULL);
}

static inline int
edgeos_device_match_name(struct device *dev, const void *name)
{
	return (dev != NULL && name != NULL &&
	    strcmp(dev_name(dev), (const char *)name) == 0);
}

static inline struct device *
class_find_device_by_name(const struct class *class, const char *name)
{
	return (class_find_device(class, NULL, name, edgeos_device_match_name));
}

#ifndef __ATTRIBUTE_GROUPS
#define __ATTRIBUTE_GROUPS(_name) \
	static const struct attribute_group *_name##_groups[] = { \
		&_name##_group, \
		NULL, \
	}
#endif

static inline int
edgeos_sysfs_update_group(struct kobject *kobj,
    const struct attribute_group *group)
{
	(void)kobj;
	(void)group;
	return (0);
}

#define sysfs_update_group(_kobj, _group) \
	edgeos_sysfs_update_group((_kobj), (_group))

#ifndef sysfs_notify
#define sysfs_notify(_kobj, _directory, _attribute) do { \
	(void)(_kobj); \
	(void)(_directory); \
	(void)(_attribute); \
} while (0)
#endif

static inline void
edgeos_drm_connector_oob_hotplug_event(struct fwnode_handle *connector_fwnode,
    int status)
{
	(void)connector_fwnode;
	(void)status;
}

#define drm_connector_oob_hotplug_event(_fwnode, _status) \
	edgeos_drm_connector_oob_hotplug_event((_fwnode), (_status))

#endif /* _EDGEOS_LINUXKPI_TYPEC_COMPAT_H_ */
