/* SPDX-License-Identifier: BSD-3-Clause */

#ifndef EDGEOS_FREEBSD_BRCM80211_COMPAT_H
#define EDGEOS_FREEBSD_BRCM80211_COMPAT_H

#if defined(__clang__)
#pragma clang diagnostic ignored "-Wunterminated-string-initialization"
#endif

/* The imported FreeBSD brcmfmac module excludes its Linux ACPI helper. */
#ifdef CONFIG_ACPI
#undef CONFIG_ACPI
#endif

#endif
