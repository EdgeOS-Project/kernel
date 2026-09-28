/* SPDX-License-Identifier: BSD-2-Clause */
/* PCI register wrapper for target-specific FreeBSD driver ABI policy. */

#ifndef EDGEOS_COMPAT_FREEBSD_DEV_PCI_PCIREG_H
#define EDGEOS_COMPAT_FREEBSD_DEV_PCI_PCIREG_H

#include_next <dev/pci/pcireg.h>

#if defined(_WIN32) && \
    (defined(EDGEOS_ARCMSR_ARM64_LP64) || \
    defined(EDGEOS_HPTIOP_ARM64_LP64))
#define long __int64
#endif

#endif
