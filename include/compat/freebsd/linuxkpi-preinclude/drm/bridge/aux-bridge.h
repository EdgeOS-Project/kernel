#ifndef _EDGEOS_DRM_AUX_BRIDGE_H_
#define _EDGEOS_DRM_AUX_BRIDGE_H_

#include <linux/device.h>

struct auxiliary_device;

static inline int
drm_aux_bridge_register(struct device *dev)
{
	(void)dev;
	return (0);
}

static inline struct auxiliary_device *
devm_drm_dp_hpd_bridge_alloc(struct device *parent, struct device_node *node)
{
	(void)parent;
	(void)node;
	return (NULL);
}

static inline int
devm_drm_dp_hpd_bridge_add(struct device *dev,
    struct auxiliary_device *auxiliary)
{
	(void)dev;
	(void)auxiliary;
	return (0);
}

#endif /* _EDGEOS_DRM_AUX_BRIDGE_H_ */
