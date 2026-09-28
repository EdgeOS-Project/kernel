#ifndef EDGEOS_FREEBSD_LINUXKPI_NOUVEAU_GEM_PUT_COMPAT_H
#define EDGEOS_FREEBSD_LINUXKPI_NOUVEAU_GEM_PUT_COMPAT_H

#define drm_gem_object_put_unlocked edgeos_drm_gem_object_put_unlocked

#include <drm/drm_gem.h>

void
edgeos_drm_gem_object_put_unlocked(struct drm_gem_object *object)
{
	if (object != NULL)
		__drm_gem_object_put(object);
}

#endif
