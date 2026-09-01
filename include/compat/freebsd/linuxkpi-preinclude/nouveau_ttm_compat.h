#ifndef EDGEOS_FREEBSD_LINUXKPI_NOUVEAU_TTM_COMPAT_H
#define EDGEOS_FREEBSD_LINUXKPI_NOUVEAU_TTM_COMPAT_H

#include "nouveau_drv.h"

static inline int
edgeos_ttm_bo_device_init(struct ttm_bo_device *device,
    struct ttm_bo_driver *driver,
    struct drm_vma_offset_manager *vma_manager, bool use_dma32)
{
	return ttm_bo_device_init(device, driver, NULL, vma_manager, use_dma32);
}

#define ttm_bo_device_init(_device, _driver, _mapping, _manager, _dma32) \
	edgeos_ttm_bo_device_init((_device), (_driver), (_manager), (_dma32))

#endif
