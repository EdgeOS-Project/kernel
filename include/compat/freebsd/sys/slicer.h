/* SPDX-License-Identifier: MPL-2.0 */
/* FreeBSD flash-slicer contract used by imported storage drivers. */

#ifndef EDGEOS_COMPAT_FREEBSD_SYS_SLICER_H
#define EDGEOS_COMPAT_FREEBSD_SYS_SLICER_H

#include <stdbool.h>
#include <stdint.h>

#define FLASH_SLICES_MAX_NUM 8
#define FLASH_SLICES_MAX_NAME_LEN 33

#define FLASH_SLICES_FLAG_NONE 0
#define FLASH_SLICES_FLAG_RO 1

#define FLASH_SLICES_FMT "%ss.%s"

struct _device;
typedef struct _device *device_t;

struct flash_slice {
    int64_t base;
    int64_t size;
    const char *label;
    unsigned int flags;
};

typedef int (*flash_slicer_t)(device_t device, const char *provider,
    struct flash_slice *slices, int *slice_count);

#define FLASH_SLICES_TYPE_NAND 0
#define FLASH_SLICES_TYPE_CFI 1
#define FLASH_SLICES_TYPE_SPI 2
#define FLASH_SLICES_TYPE_MMC 3

void flash_register_slicer(flash_slicer_t slicer, unsigned int type,
    bool force);

#endif
