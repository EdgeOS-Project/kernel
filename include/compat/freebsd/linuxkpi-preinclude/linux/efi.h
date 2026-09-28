/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef EDGEOS_LINUXKPI_PREINCLUDE_LINUX_EFI_H
#define EDGEOS_LINUXKPI_PREINCLUDE_LINUX_EFI_H

/* EdgeOS does not expose the FreeBSD amd64 loader's EFI boot flag. */
#define efi_boot 0
#include_next <linux/efi.h>
#undef efi_boot

#endif
