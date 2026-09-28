#ifndef EDGEOS_FREEBSD_LINUXKPI_NOUVEAU_LEGACY_TTM_PAGE_ALLOC_COMPAT_H
#define EDGEOS_FREEBSD_LINUXKPI_NOUVEAU_LEGACY_TTM_PAGE_ALLOC_COMPAT_H

#include "nouveau_legacy_ttm_compat.h"

#pragma GCC diagnostic ignored "-Wcompare-distinct-pointer-types"

#define clear_highpage(_page) clear_page(page_address((_page)))
#define page_count(_page) ((int)(_page)->ref_count)

#undef pr_fmt

#endif
