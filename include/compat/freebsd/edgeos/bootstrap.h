/* SPDX-License-Identifier: MPL-2.0 */
/* Shared startup contract for the EdgeOS BSD Driver Bridge. */

#ifndef EDGEOS_COMPAT_FREEBSD_BOOTSTRAP_H
#define EDGEOS_COMPAT_FREEBSD_BOOTSTRAP_H

#include <stdint.h>

#include "allocator.h"
#include "block.h"
#include "bus_dma.h"
#include "bus_space.h"
#include "callout.h"
#include "fdt_inventory.h"
#include "interrupt.h"
#include "kthread.h"
#include "newbus.h"
#include "pci.h"
#include "sync.h"
#include "taskqueue.h"

#define BSD_BRIDGE_BOOTSTRAP_RUN_MODULES 0x00000001u
#define BSD_BRIDGE_BOOTSTRAP_CREATE_ROOT 0x00000002u
#define BSD_BRIDGE_BOOTSTRAP_ATTACH_PCI 0x00000004u

#define BSD_BRIDGE_BOOTSTRAP_DEFAULT_FLAGS \
    (BSD_BRIDGE_BOOTSTRAP_RUN_MODULES | BSD_BRIDGE_BOOTSTRAP_CREATE_ROOT)

typedef enum bsd_bridge_bootstrap_state {
    BSD_BRIDGE_BOOTSTRAP_UNINITIALIZED = 0,
    BSD_BRIDGE_BOOTSTRAP_INITIALIZING = 1,
    BSD_BRIDGE_BOOTSTRAP_READY = 2,
    BSD_BRIDGE_BOOTSTRAP_FAILED = 3,
} bsd_bridge_bootstrap_state_t;

typedef enum bsd_bridge_bootstrap_stage {
    BSD_BRIDGE_STAGE_NONE = 0,
    BSD_BRIDGE_STAGE_ALLOCATOR,
    BSD_BRIDGE_STAGE_SYNCHRONIZATION,
    BSD_BRIDGE_STAGE_KERNEL_WORKERS,
    BSD_BRIDGE_STAGE_TASKQUEUES,
    BSD_BRIDGE_STAGE_CALLOUTS,
    BSD_BRIDGE_STAGE_BUS_SPACE,
    BSD_BRIDGE_STAGE_BUS_DMA,
    BSD_BRIDGE_STAGE_BLOCK,
    BSD_BRIDGE_STAGE_INTERRUPTS,
    BSD_BRIDGE_STAGE_DRIVER_ADAPTERS,
    BSD_BRIDGE_STAGE_BUILTIN_MODULES,
    BSD_BRIDGE_STAGE_ROOT_BUS,
    BSD_BRIDGE_STAGE_FDT_INVENTORY,
    BSD_BRIDGE_STAGE_MODULES,
    BSD_BRIDGE_STAGE_EXTERNAL_MODULES,
    BSD_BRIDGE_STAGE_PCI_BUS,
    BSD_BRIDGE_STAGE_COMPLETE,
} bsd_bridge_bootstrap_stage_t;

typedef struct bsd_bridge_bootstrap_options {
    uint32_t flags;
    const char *root_name;
    int root_unit;
    const bsd_allocator_ops_t *allocator_ops;
    const bsd_sync_ops_t *sync_ops;
    const bsd_bus_space_ops_t *memory_space_ops;
    const bsd_bus_space_ops_t *io_space_ops;
    const bsd_bus_dma_ops_t *bus_dma_ops;
    const bsd_block_backend_ops_t *block_ops;
    const bsd_interrupt_backend_ops_t *interrupt_ops;
    const bsd_pci_backend_ops_t *pci_ops;
} bsd_bridge_bootstrap_options_t;

typedef struct bsd_bridge_bootstrap_status {
    bsd_bridge_bootstrap_state_t state;
    bsd_bridge_bootstrap_stage_t stage;
    int error;
    uint32_t flags;
    device_t root;
    device_t pci_bus;
    bsd_fdt_inventory_status_t fdt;
} bsd_bridge_bootstrap_status_t;

int bsd_bridge_bootstrap(
    const bsd_bridge_bootstrap_options_t *options);
void bsd_bridge_bootstrap_get_status(
    bsd_bridge_bootstrap_status_t *status);

#endif
