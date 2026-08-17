/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Shared, idempotent startup sequencing for imported BSD drivers.
 *
 * Module registration is intentionally separate from device discovery.
 * EdgeOS may start the compatibility runtime while native drivers still own
 * devices, then enable bridge bus attachment only after an explicit handoff.
 */

#include <stdint.h>

#include "compat/freebsd/edgeos/acpica.h"
#include "compat/freebsd/edgeos/bootstrap.h"
#include "compat/freebsd/edgeos/audio.h"
#include "compat/freebsd/edgeos/cpu.h"
#include "compat/freebsd/edgeos/driver_adapters.h"
#include "compat/freebsd/edgeos/driver_loader.h"
#include "compat/freebsd/edgeos/keyboard.h"
#include "compat/freebsd/edgeos/module.h"
#include "compat/freebsd/edgeos/ofw.h"
#include "compat/freebsd/edgeos/vm_page.h"
#include "compat/freebsd/sys/kernel.h"

#define BSD_BRIDGE_ENXIO 6
#define BSD_BRIDGE_EINVAL 22

static volatile int g_bootstrap_state;
static volatile int g_bootstrap_stage;
static int g_bootstrap_error;
static uint32_t g_bootstrap_flags;
static device_t g_bootstrap_root;
static device_t g_bootstrap_pci_bus;
static bsd_fdt_inventory_status_t g_bootstrap_fdt;

static void
bootstrap_relax(void)
{
#if defined(__x86_64__)
    __asm__ __volatile__("pause");
#elif defined(__aarch64__)
    __asm__ __volatile__("yield");
#endif
}

static int
bootstrap_error_normalize(int error)
{
    if (error > 0)
        return error;
    return BSD_BRIDGE_ENXIO;
}

static void
bootstrap_set_stage(bsd_bridge_bootstrap_stage_t stage)
{
    __atomic_store_n(&g_bootstrap_stage, (int)stage, __ATOMIC_RELEASE);
}

static int
bootstrap_finish_failure(int error)
{
    g_bootstrap_error = bootstrap_error_normalize(error);
    __atomic_store_n(&g_bootstrap_state, BSD_BRIDGE_BOOTSTRAP_FAILED,
        __ATOMIC_RELEASE);
    return g_bootstrap_error;
}

static int
bootstrap_initialize_allocator(const bsd_allocator_ops_t *operations)
{
    if (bsd_allocator_is_initialized())
        return 0;
    if (bsd_allocator_initialize(operations) == 0)
        return 0;
    return bsd_allocator_is_initialized() ? 0 : BSD_BRIDGE_ENXIO;
}

static int
bootstrap_initialize_sync(const bsd_sync_ops_t *operations)
{
    if (bsd_sync_is_initialized())
        return 0;
    if (bsd_sync_initialize(operations) == 0)
        return 0;
    return bsd_sync_is_initialized() ? 0 : BSD_BRIDGE_ENXIO;
}

static int
bootstrap_initialize_bus_space(
    const bsd_bus_space_ops_t *memory_operations,
    const bsd_bus_space_ops_t *io_operations)
{
    if (bsd_bus_space_is_initialized())
        return 0;
    if (memory_operations) {
        if (bsd_bus_space_initialize(memory_operations,
            io_operations) == 0)
            return 0;
        return bsd_bus_space_is_initialized() ? 0 : BSD_BRIDGE_ENXIO;
    }
    return bsd_bus_space_ensure_initialized();
}

static int
bootstrap_initialize_bus_dma(const bsd_bus_dma_ops_t *operations)
{
    if (bsd_bus_dma_is_initialized())
        return 0;
    if (operations) {
        if (bsd_bus_dma_initialize(operations) == 0)
            return 0;
        return bsd_bus_dma_is_initialized() ? 0 : BSD_BRIDGE_ENXIO;
    }
    return bsd_bus_dma_ensure_initialized();
}

static int
bootstrap_initialize_block(const bsd_block_backend_ops_t *operations)
{
    if (bsd_block_is_initialized())
        return 0;
    if (operations) {
        if (bsd_block_initialize(operations) == 0)
            return 0;
        return bsd_block_is_initialized() ? 0 : BSD_BRIDGE_ENXIO;
    }
    return bsd_block_ensure_initialized();
}

static int
bootstrap_initialize_interrupts(
    const bsd_interrupt_backend_ops_t *operations)
{
    if (bsd_interrupt_is_initialized())
        return 0;
    if (operations) {
        if (bsd_interrupt_initialize(operations) == 0)
            return 0;
        return bsd_interrupt_is_initialized() ? 0 : BSD_BRIDGE_ENXIO;
    }
    return bsd_interrupt_ensure_initialized();
}

static int
bootstrap_initialize_pci(const bsd_pci_backend_ops_t *operations)
{
    if (bsd_pci_is_initialized())
        return 0;
    if (operations) {
        if (bsd_pci_initialize(operations) == 0)
            return 0;
        return bsd_pci_is_initialized() ? 0 : BSD_BRIDGE_ENXIO;
    }
    return bsd_pci_ensure_initialized();
}

int
bsd_bridge_bootstrap(const bsd_bridge_bootstrap_options_t *options)
{
    bsd_bridge_bootstrap_options_t selected = {
        .flags = BSD_BRIDGE_BOOTSTRAP_DEFAULT_FLAGS,
        .root_name = "nexus",
        .root_unit = 0,
    };
    int expected = BSD_BRIDGE_BOOTSTRAP_UNINITIALIZED;
    int state;
    int error;

    if (options)
        selected = *options;
    if ((selected.flags & ~(BSD_BRIDGE_BOOTSTRAP_RUN_MODULES |
        BSD_BRIDGE_BOOTSTRAP_CREATE_ROOT |
        BSD_BRIDGE_BOOTSTRAP_ATTACH_PCI)) != 0 ||
        ((selected.flags & BSD_BRIDGE_BOOTSTRAP_ATTACH_PCI) != 0 &&
        (selected.flags & BSD_BRIDGE_BOOTSTRAP_CREATE_ROOT) == 0))
        return BSD_BRIDGE_EINVAL;
    if (!selected.root_name)
        selected.root_name = "nexus";

    if (!__atomic_compare_exchange_n(&g_bootstrap_state, &expected,
        BSD_BRIDGE_BOOTSTRAP_INITIALIZING, 0, __ATOMIC_ACQ_REL,
        __ATOMIC_ACQUIRE)) {
        do {
            state = __atomic_load_n(&g_bootstrap_state, __ATOMIC_ACQUIRE);
            if (state != BSD_BRIDGE_BOOTSTRAP_INITIALIZING)
                return state == BSD_BRIDGE_BOOTSTRAP_READY ?
                    0 : g_bootstrap_error;
            bootstrap_relax();
        } while (1);
    }

    g_bootstrap_flags = selected.flags;
    bootstrap_set_stage(BSD_BRIDGE_STAGE_ALLOCATOR);
    error = bootstrap_initialize_allocator(selected.allocator_ops);
    if (error)
        return bootstrap_finish_failure(error);

    bootstrap_set_stage(BSD_BRIDGE_STAGE_SYNCHRONIZATION);
    error = bootstrap_initialize_sync(selected.sync_ops);
    if (error)
        return bootstrap_finish_failure(error);

    bootstrap_set_stage(BSD_BRIDGE_STAGE_KERNEL_WORKERS);
    error = bsd_kthread_runtime_initialize();
    if (error)
        return bootstrap_finish_failure(error);
    error = bsd_cpu_runtime_initialize();
    if (error)
        return bootstrap_finish_failure(error);

    bootstrap_set_stage(BSD_BRIDGE_STAGE_TASKQUEUES);
    error = bsd_taskqueue_runtime_initialize();
    if (error)
        return bootstrap_finish_failure(error);

    bootstrap_set_stage(BSD_BRIDGE_STAGE_CALLOUTS);
    error = bsd_callout_runtime_initialize();
    if (error)
        return bootstrap_finish_failure(error);

    bootstrap_set_stage(BSD_BRIDGE_STAGE_BUS_SPACE);
    error = bootstrap_initialize_bus_space(selected.memory_space_ops,
        selected.io_space_ops);
    if (error)
        return bootstrap_finish_failure(error);

    bootstrap_set_stage(BSD_BRIDGE_STAGE_BUS_DMA);
    error = bootstrap_initialize_bus_dma(selected.bus_dma_ops);
    if (error)
        return bootstrap_finish_failure(error);
    error = bsd_vm_page_runtime_initialize();
    if (error)
        return bootstrap_finish_failure(error);

    bootstrap_set_stage(BSD_BRIDGE_STAGE_BLOCK);
    error = bootstrap_initialize_block(selected.block_ops);
    if (error)
        return bootstrap_finish_failure(error);

    bootstrap_set_stage(BSD_BRIDGE_STAGE_INTERRUPTS);
    error = bootstrap_initialize_interrupts(selected.interrupt_ops);
    if (error)
        return bootstrap_finish_failure(error);

    bootstrap_set_stage(BSD_BRIDGE_STAGE_DRIVER_ADAPTERS);
    error = bsd_driver_adapters_initialize();
    if (error)
        return bootstrap_finish_failure(error);
    kbdinit();

    bootstrap_set_stage(BSD_BRIDGE_STAGE_BUILTIN_MODULES);
    error = bsd_module_provide("pci", 1);
    if (error)
        return bootstrap_finish_failure(error);
    error = bsd_module_provide("ether", 1);
    if (error)
        return bootstrap_finish_failure(error);
    error = bsd_module_provide("random_device", 1);
    if (error)
        return bootstrap_finish_failure(error);
    /*
     * Some complete FreeBSD platform drivers retain the historical
     * randomdev dependency name while the random core declares itself as
     * random_device.  Both names describe the same bridge-owned random(9)
     * contract, so publish the compatibility name at the same version.
     */
    error = bsd_module_provide("randomdev", 1);
    if (error)
        return bootstrap_finish_failure(error);
    error = bsd_module_provide("random_harvestq", 1);
    if (error)
        return bootstrap_finish_failure(error);
    error = bsd_module_provide("efirt", 1);
    if (error)
        return bootstrap_finish_failure(error);
    error = bsd_module_provide("acpi", 1);
    if (error)
        return bootstrap_finish_failure(error);
    error = bsd_module_provide("simplebus", 1);
    if (error)
        return bootstrap_finish_failure(error);
    error = bsd_module_provide("ofwbus", 1);
    if (error)
        return bootstrap_finish_failure(error);
    error = bsd_module_provide("cam", 1);
    if (error)
        return bootstrap_finish_failure(error);
    error = bsd_module_provide("evdev", 1);
    if (error)
        return bootstrap_finish_failure(error);
    error = bsd_module_provide("firmware", 1);
    if (error)
        return bootstrap_finish_failure(error);
    error = bsd_module_provide("upgtfw_fw", 1);
    if (error)
        return bootstrap_finish_failure(error);
    error = bsd_module_provide("sound", BSD_AUDIO_MODULE_VERSION);
    if (error)
        return bootstrap_finish_failure(error);

    if ((selected.flags & BSD_BRIDGE_BOOTSTRAP_CREATE_ROOT) != 0) {
        bootstrap_set_stage(BSD_BRIDGE_STAGE_ROOT_BUS);
        g_bootstrap_root = bsd_newbus_create_root(selected.root_name,
            selected.root_unit, 0);
        if (!g_bootstrap_root)
            return bootstrap_finish_failure(BSD_BRIDGE_ENXIO);
#ifdef CONFIG_BSD_DRIVER_FDT_INVENTORY
        if (bsd_ofw_fdt_available()) {
            bootstrap_set_stage(BSD_BRIDGE_STAGE_FDT_INVENTORY);
            error = bsd_fdt_inventory_register(g_bootstrap_root,
                &g_bootstrap_fdt);
            if (error)
                return bootstrap_finish_failure(error);
        }
#endif
    }

    if ((selected.flags & BSD_BRIDGE_BOOTSTRAP_RUN_MODULES) != 0) {
        bootstrap_set_stage(BSD_BRIDGE_STAGE_MODULES);
#ifdef CONFIG_BSD_DRIVER_ACPICA
        error = bsd_sysinit_run_through(SI_SUB_DRIVERS);
        if (!error)
            (void)bsd_acpica_runtime_initialize();
        if (!error)
            error = bsd_sysinit_run_remaining();
#else
        error = bsd_sysinit_run_all();
#endif
        if (error)
            return bootstrap_finish_failure(error);
#ifdef CONFIG_BSD_DRIVER_MODULE_AUTOLOAD
        bootstrap_set_stage(BSD_BRIDGE_STAGE_EXTERNAL_MODULES);
        error = bsd_driver_modules_load_default();
        if (error)
            return bootstrap_finish_failure(error);
#endif
    }

    if ((selected.flags & BSD_BRIDGE_BOOTSTRAP_ATTACH_PCI) != 0) {
        bootstrap_set_stage(BSD_BRIDGE_STAGE_PCI_BUS);
        error = bootstrap_initialize_pci(selected.pci_ops);
        if (error)
            return bootstrap_finish_failure(error);
        g_bootstrap_pci_bus = bsd_pci_attach_bus(g_bootstrap_root);
        if (!g_bootstrap_pci_bus)
            return bootstrap_finish_failure(BSD_BRIDGE_ENXIO);
    }

    bootstrap_set_stage(BSD_BRIDGE_STAGE_COMPLETE);
    __atomic_store_n(&g_bootstrap_state, BSD_BRIDGE_BOOTSTRAP_READY,
        __ATOMIC_RELEASE);
    return 0;
}

void
bsd_bridge_bootstrap_get_status(bsd_bridge_bootstrap_status_t *status)
{
    if (!status)
        return;
    status->state = (bsd_bridge_bootstrap_state_t)__atomic_load_n(
        &g_bootstrap_state, __ATOMIC_ACQUIRE);
    status->stage = (bsd_bridge_bootstrap_stage_t)__atomic_load_n(
        &g_bootstrap_stage, __ATOMIC_ACQUIRE);
    status->error = g_bootstrap_error;
    status->flags = g_bootstrap_flags;
    status->root = g_bootstrap_root;
    status->pci_bus = g_bootstrap_pci_bus;
    status->fdt = g_bootstrap_fdt;
}
