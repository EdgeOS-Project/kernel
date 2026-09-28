#ifndef EDGEOS_NOUVEAU_BO_TTM_COMPAT_H
#define EDGEOS_NOUVEAU_BO_TTM_COMPAT_H

#include <drm/ttm/ttm_page_alloc.h>

#define ttm_dma_populate(ttm_dma, dev, ctx) \
	ttm_populate_and_map_pages((dev), (ttm_dma), (ctx))
#define ttm_dma_unpopulate(ttm_dma, dev) \
	ttm_unmap_and_unpopulate_pages((dev), (ttm_dma))

#endif
