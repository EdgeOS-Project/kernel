/* SPDX-License-Identifier: MPL-2.0 */
/*
 * EdgeOS Bochs/QEMU BGA framebuffer driver.
 *
 * Copyright (c) EdgeOS Contributors.
 */
#ifndef EDGEOS_DRIVERS_BGA_H
#define EDGEOS_DRIVERS_BGA_H

int bga_init(int framebuffer_already_active);
int bga_available(void);

#endif
