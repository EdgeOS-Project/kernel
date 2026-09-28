/* SPDX-License-Identifier: MPL-2.0 */
/* EdgeOS LinuxKPI MHI compatibility extensions. */

#ifndef _EDGEOS_LINUXKPI_PREINCLUDE_LINUX_MHI_H_
#define _EDGEOS_LINUXKPI_PREINCLUDE_LINUX_MHI_H_

#include_next <linux/mhi.h>

static inline void
mhi_power_down_keep_dev(struct mhi_controller *controller, bool graceful)
{
    mhi_power_down(controller, graceful);
}

static inline int
mhi_download_rddm_image(struct mhi_controller *controller, bool in_panic)
{
    (void)in_panic;
    return mhi_force_rddm_mode(controller);
}

#endif
