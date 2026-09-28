/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Hyper-V guest service probe interface for EdgeOS.
 *
 * Copyright (c) EdgeOS Contributors.
 */

#ifndef EDGEOS_DRIVERS_HYPERV_H
#define EDGEOS_DRIVERS_HYPERV_H

void hyperv_probe_init(void);
int hyperv_is_present(void);

#endif
