/* SPDX-License-Identifier: BSD-3-Clause */

#ifndef EDGEOS_FREEBSD_RTW89_COMPAT_H
#define EDGEOS_FREEBSD_RTW89_COMPAT_H

#include <sys/systm.h>

/* Linux rtw89 uses pause as an HCI operation field name. */
#undef pause

#define IEEE80211_EML_CAP_EMLSR_PADDING_DELAY_256US \
    IEEE80211_EML_CAP_EML_PADDING_DELAY_256US

#endif
