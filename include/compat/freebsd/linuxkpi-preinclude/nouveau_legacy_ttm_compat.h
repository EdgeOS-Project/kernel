#ifndef EDGEOS_FREEBSD_LINUXKPI_NOUVEAU_LEGACY_TTM_COMPAT_H
#define EDGEOS_FREEBSD_LINUXKPI_NOUVEAU_LEGACY_TTM_COMPAT_H

#define _DRM_BUS_DMA_HACKS_H_

#pragma GCC diagnostic ignored "-Wendif-labels"

#ifndef si_mem_available
#define si_mem_available() totalram_pages()
#endif

#define f_mapping f_shmem
#define mapping object
#define index pindex
#define mapping_gfp_mask(_mapping) GFP_KERNEL

#endif
