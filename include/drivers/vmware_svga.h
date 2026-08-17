/* SPDX-License-Identifier: MPL-2.0 */
/*
 * EdgeOS VMware SVGA framebuffer driver.
 *
 * Copyright (c) EdgeOS Contributors.
 */
#ifndef EDGEOS_DRIVERS_VMWARE_SVGA_H
#define EDGEOS_DRIVERS_VMWARE_SVGA_H

int vmware_svga_init(int framebuffer_already_active);
int vmware_svga_available(void);

#endif
