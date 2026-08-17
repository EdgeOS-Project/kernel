/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS architecture-independent persistent boot log interface.
 * Copyright (c) EdgeOS Contributors.
 */

#ifndef EDGEOS_KERNEL_BOOT_LOGFILE_H
#define EDGEOS_KERNEL_BOOT_LOGFILE_H

int kernel_boot_log_configure(void);
int kernel_boot_log_start(void);
void kernel_boot_log_poll(void);
void kernel_boot_log_flush_now(void);

#endif /* EDGEOS_KERNEL_BOOT_LOGFILE_H */
