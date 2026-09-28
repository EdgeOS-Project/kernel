#ifndef EDGEOS_FREEBSD_LINUXKPI_NOUVEAU_LEGACY_TTM_BO_UTIL_COMPAT_H
#define EDGEOS_FREEBSD_LINUXKPI_NOUVEAU_LEGACY_TTM_BO_UTIL_COMPAT_H

#include "nouveau_legacy_ttm_compat.h"

#define pgprot_val(_protection) (_protection)
#define drm_vma_node_destroy(_node) \
	drm_vma_offset_remove(fbo->base.bdev->vma_manager, (_node))

#endif
