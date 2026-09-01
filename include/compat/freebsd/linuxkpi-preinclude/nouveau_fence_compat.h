#ifndef EDGEOS_FREEBSD_LINUXKPI_NOUVEAU_FENCE_COMPAT_H
#define EDGEOS_FREEBSD_LINUXKPI_NOUVEAU_FENCE_COMPAT_H

struct dma_resv_list {
	struct rcu_head rcu;
	u32 num_fences;
	u32 max_fences;
	struct dma_fence __rcu *table[];
};

static inline struct dma_resv_list *
edgeos_dma_resv_get_list(struct dma_resv *resv)
{
	return rcu_dereference_protected(resv->fences, dma_resv_held(resv));
}

#define dma_resv_get_list edgeos_dma_resv_get_list
#define shared_count num_fences
#define shared table

#endif
