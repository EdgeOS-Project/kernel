/* SPDX-License-Identifier: MPL-2.0 */
/* IOMMU integration boundary for imported BSD PCI drivers. */

#ifndef EDGEOS_COMPAT_FREEBSD_DEV_IOMMU_IOMMU_H
#define EDGEOS_COMPAT_FREEBSD_DEV_IOMMU_IOMMU_H

#ifdef EDGEOS_BSD_FULL_IOMMU
#include_next <dev/iommu/iommu.h>
#else

#include <stdbool.h>

#include "../../edgeos/newbus.h"
#include "../../machine/bus.h"
#include "../../vm/vm.h"

bool bus_dma_iommu_set_buswide(device_t device);
int bus_dma_iommu_load_ident(bus_dma_tag_t tag, bus_dmamap_t map,
    vm_paddr_t start, vm_size_t length, int flags);

#endif

#endif
