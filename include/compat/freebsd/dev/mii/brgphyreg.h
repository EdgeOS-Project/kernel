/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Broadcom PHY register interface used by BSD-derived Ethernet drivers.
 *
 * This EdgeOS compatibility header defines the hardware programming values
 * required to select the IEEE auto-negotiation MMD on BCM570x-family PHYs.
 * It is original EdgeOS integration code and is not derived from the
 * advertising-clause FreeBSD header of the same name.
 */

#ifndef EDGEOS_COMPAT_FREEBSD_DEV_MII_BRGPHYREG_H
#define EDGEOS_COMPAT_FREEBSD_DEV_MII_BRGPHYREG_H

#define BRGPHY_ADDR_EXT                         0x1e
#define BRGPHY_BLOCK_ADDR                       0x1f
#define BRGPHY_BLOCK_ADDR_ADDR_EXT              0xffd0
#define BRGPHY_BLOCK_ADDR_COMBO_IEEE0           0xffe0
#define BRGPHY_ADDR_EXT_AN_MMD                  0x3800

#endif
