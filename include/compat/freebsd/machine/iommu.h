/* SPDX-License-Identifier: MPL-2.0 */
/* Architecture IOMMU include adapter for the BSD Driver Bridge. */

#ifndef EDGEOS_COMPAT_FREEBSD_MACHINE_IOMMU_H
#define EDGEOS_COMPAT_FREEBSD_MACHINE_IOMMU_H

#if defined(__aarch64__)
#include <arm64/iommu/iommu.h>
#else
#include <vm/pmap.h>
#include <x86/include/busdma_impl.h>
#include <x86/iommu/intel_reg.h>
#include <x86/iommu/x86_iommu.h>
#include <x86/iommu/intel_dmar.h>
#endif

#endif
