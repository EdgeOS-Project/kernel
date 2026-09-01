#ifndef EDGEOS_NOUVEAU_LEGACY_DRM_PANEL_COMPAT_H
#define EDGEOS_NOUVEAU_LEGACY_DRM_PANEL_COMPAT_H

#include <linux/backlight.h>
#include <linux/err.h>

static inline struct backlight_device *
devm_of_find_backlight(struct device *dev)
{
	return ERR_PTR(-ENODEV);
}

#endif
