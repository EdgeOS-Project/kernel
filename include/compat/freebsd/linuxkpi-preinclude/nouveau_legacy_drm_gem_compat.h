#ifndef EDGEOS_NOUVEAU_LEGACY_DRM_GEM_COMPAT_H
#define EDGEOS_NOUVEAU_LEGACY_DRM_GEM_COMPAT_H

#include <linux/idr.h>
#include <linux/xarray.h>

#ifndef idr_init_base
#define idr_init_base(idr, base) idr_init(idr)
#endif

#endif
