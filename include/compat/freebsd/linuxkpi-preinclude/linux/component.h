#ifndef EDGEOS_FREEBSD_LINUXKPI_COMPONENT_H
#define EDGEOS_FREEBSD_LINUXKPI_COMPONENT_H

#include <linux/device.h>
#include <linux/errno.h>

struct component_ops {
	int (*bind)(struct device *, struct device *, void *);
	void (*unbind)(struct device *, struct device *, void *);
};

struct component_master_ops {
	int (*bind)(struct device *);
	void (*unbind)(struct device *);
};

struct component_match {
	int unused;
};

static inline int
component_add(struct device *device, const struct component_ops *ops)
{
	(void)device;
	(void)ops;
	return -ENODEV;
}

static inline void
component_del(struct device *device, const struct component_ops *ops)
{
	(void)device;
	(void)ops;
}

static inline int
component_bind_all(struct device *device, void *data)
{
	(void)device;
	(void)data;
	return (0);
}

static inline void
component_unbind_all(struct device *device, void *data)
{
	(void)device;
	(void)data;
}

static inline void
component_match_add(struct device *parent, struct component_match **match,
    int (*compare)(struct device *, void *), void *data)
{
	(void)parent;
	(void)match;
	(void)compare;
	(void)data;
}

static inline int
component_master_add_with_match(struct device *device,
    const struct component_master_ops *ops, struct component_match *match)
{
	(void)device;
	(void)ops;
	(void)match;
	return (0);
}

static inline void
component_master_del(struct device *device,
    const struct component_master_ops *ops)
{
	(void)device;
	(void)ops;
}

#endif
