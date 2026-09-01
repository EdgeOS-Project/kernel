/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef EDGEOS_LINUXKPI_PREINCLUDE_IWLWIFI_COMPAT_H
#define EDGEOS_LINUXKPI_PREINCLUDE_IWLWIFI_COMPAT_H

/* LinuxKPI alignment annotations require this compile-time cache geometry. */
#include <sys/param.h>

#if defined(__clang__)
#pragma clang diagnostic ignored "-Winitializer-overrides"
#endif

/* FreeBSD's current iwlwifi import uses this EML timeout encoding. */
#define IEEE80211_EML_CAP_TRANSITION_TIMEOUT_128TU 0x04
#define IEEE80211_EML_CAP_EMLSR_PADDING_DELAY 0x08
#define IEEE80211_EML_CAP_EMLSR_PADDING_DELAY_32US 0x10
#define IEEE80211_EML_CAP_EMLSR_TRANSITION_DELAY 0x20
#define IEEE80211_EML_CAP_EMLSR_TRANSITION_DELAY_64US 0x40

#endif
