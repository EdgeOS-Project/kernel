#ifndef EDGEOS_FREEBSD_LINUXKPI_NOUVEAU_LEGACY_TTM_BO_COMPAT_H
#define EDGEOS_FREEBSD_LINUXKPI_NOUVEAU_LEGACY_TTM_BO_COMPAT_H

#include "nouveau_legacy_ttm_compat.h"

struct dma_resv_list {
	struct rcu_head rcu;
	u32 num_fences;
	u32 max_fences;
	struct dma_fence __rcu *table[];
};

static inline struct dma_resv_list *
edgeos_legacy_ttm_dma_resv_get_list(struct dma_resv *resv)
{
	return (struct dma_resv_list *)resv->fences;
}

#define dma_resv_get_list edgeos_legacy_ttm_dma_resv_get_list
#define shared_count num_fences
#define shared table
#define dma_resv_test_signaled_rcu(_resv, _write) \
	dma_resv_test_signaled((_resv), dma_resv_usage_rw((_write)))
#define dmat dev_mapping
#define drm_prime_sg_importable(_tag, _sg) 1

#undef pr_fmt

#endif
