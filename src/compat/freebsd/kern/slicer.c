/* SPDX-License-Identifier: MPL-2.0 */
/* Thread-safe flash-slicer registry for imported BSD storage drivers. */

#include <stdbool.h>
#include <stdint.h>

#include "compat/freebsd/edgeos/slicer.h"
#include "compat/freebsd/sys/module.h"

#define BSD_FLASH_SLICER_TYPE_COUNT 4u

static flash_slicer_t g_flash_slicers[BSD_FLASH_SLICER_TYPE_COUNT];

void
flash_register_slicer(flash_slicer_t slicer, unsigned int type, bool force)
{
    flash_slicer_t expected = 0;

    if (type >= BSD_FLASH_SLICER_TYPE_COUNT)
        return;
    if (force) {
        __atomic_store_n(&g_flash_slicers[type], slicer, __ATOMIC_RELEASE);
        return;
    }
    (void)__atomic_compare_exchange_n(&g_flash_slicers[type], &expected,
        slicer, false, __ATOMIC_RELEASE, __ATOMIC_ACQUIRE);
}

flash_slicer_t
bsd_flash_slicer_lookup(unsigned int type)
{
    if (type >= BSD_FLASH_SLICER_TYPE_COUNT)
        return 0;
    return __atomic_load_n(&g_flash_slicers[type], __ATOMIC_ACQUIRE);
}

MODULE_VERSION(geom_flashmap, 0);
