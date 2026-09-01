#ifndef EDGEOS_NOUVEAU_LEGACY_DRM_MODESET_LOCK_COMPAT_H
#define EDGEOS_NOUVEAU_LEGACY_DRM_MODESET_LOCK_COMPAT_H

#include <linux/ww_mutex.h>

static inline int
edgeos_nouveau_ww_mutex_trylock(struct ww_mutex *lock)
{
	return ww_mutex_trylock(lock, NULL);
}

#define ww_mutex_trylock edgeos_nouveau_ww_mutex_trylock

#endif
