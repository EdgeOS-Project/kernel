/* SPDX-License-Identifier: MPL-2.0 */
/* Unit tests for the shared BSD bridge PCI runtime. */

#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "compat/freebsd/edgeos/allocator.h"
#include "compat/freebsd/edgeos/bus_space.h"
#include "compat/freebsd/edgeos/interrupt.h"
#include "compat/freebsd/edgeos/malloc.h"
#include "compat/freebsd/edgeos/newbus.h"
#include "compat/freebsd/edgeos/pci.h"
#include "compat/freebsd/edgeos/resource.h"
#include "compat/freebsd/edgeos/taskqueue.h"
#include "compat/freebsd/machine/resource.h"
#include "compat/freebsd/sys/kobj.h"

struct pci_device_table {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    uint16_t match_flag_vendor:1;
    uint16_t match_flag_device:1;
    uint16_t match_flag_subvendor:1;
    uint16_t match_flag_subdevice:1;
    uint16_t match_flag_class:1;
    uint16_t match_flag_subclass:1;
    uint16_t match_flag_revid:1;
    uint16_t match_flag_unused:9;
#else
    uint16_t match_flag_unused:9;
    uint16_t match_flag_revid:1;
    uint16_t match_flag_subclass:1;
    uint16_t match_flag_class:1;
    uint16_t match_flag_subdevice:1;
    uint16_t match_flag_subvendor:1;
    uint16_t match_flag_device:1;
    uint16_t match_flag_vendor:1;
#endif
    uint16_t vendor;
    uint16_t device;
    uint16_t subvendor;
    uint16_t subdevice;
    uint16_t class_id;
    uint16_t subclass;
    uint16_t revid;
    uint16_t unused;
    uintptr_t driver_data;
    char *descr;
};

struct pci_map {
    uint64_t pm_value;
    uint64_t pm_size;
    uint16_t pm_reg;
    struct {
        struct pci_map *stqe_next;
    } pm_link;
};

bool pci_has_pm(device_t device);
void pci_enable_pme(device_t device);
int pci_get_max_read_req(device_t device);
int pci_set_max_read_req(device_t device, int size);
bool pcie_flr(device_t device, unsigned int max_delay, bool force);
bool pcie_wait_for_pending_transactions(device_t device,
    unsigned int max_delay);
int pcie_get_max_completion_timeout(device_t device);
device_t pci_find_device(uint16_t vendor, uint16_t device);
device_t pci_find_bsf(uint8_t bus, uint8_t slot, uint8_t function_number);
device_t pci_find_dbsf(uint32_t domain, uint8_t bus, uint8_t slot,
    uint8_t function_number);
const struct pci_device_table *pci_match_device(device_t child,
    const struct pci_device_table *entry, size_t entry_count);
bool is_pci_device(device_t device);
struct pci_map *pci_find_bar(device_t device, int register_offset);
struct pci_devinfo;
void pci_cfg_save(device_t device, struct pci_devinfo *device_info,
    int set_power_state);
void pci_cfg_restore(device_t device, struct pci_devinfo *device_info);
void pci_save_state(device_t device);
void pci_restore_state(device_t device);
extern int cfgmech;
uint32_t pci_cfgregread(int domain, int bus, int slot, int function,
    int register_offset, int width);
void pci_cfgregwrite(int domain, int bus, int slot, int function,
    int register_offset, uint32_t value, int width);

void
bsd_kthread_sleeping_forbid(void)
{
}

void
bsd_kthread_sleeping_allow(void)
{
}

int
bsd_taskqueue_runtime_is_initialized(void)
{
    return 1;
}

struct taskqueue *
bsd_taskqueue_worker_create(const char *name)
{
    assert(name != 0);
    return (struct taskqueue *)(uintptr_t)1;
}

int
bsd_taskqueue_worker_schedule(struct taskqueue *queue, struct task *task)
{
    assert(queue == (struct taskqueue *)(uintptr_t)1);
    (void)task;
    return 0;
}

void
bsd_taskqueue_worker_drain(struct taskqueue *queue, struct task *task)
{
    assert(queue == (struct taskqueue *)(uintptr_t)1);
    (void)task;
}

void
bsd_taskqueue_worker_destroy(struct taskqueue *queue)
{
    assert(queue == (struct taskqueue *)(uintptr_t)1);
}

void
bsd_taskqueue_task_init(struct task *task, uint8_t priority,
    bsd_taskqueue_task_fn_t *function, void *context)
{
    task->ta_priority = priority;
    task->ta_func = function;
    task->ta_context = context;
}

int
bsd_taskqueue_task_schedule(struct task *task)
{
    (void)task;
    return 0;
}

void
bsd_taskqueue_task_drain(struct task *task)
{
    (void)task;
}

int
bsd_pause(const char *wait_message, int timeout_ticks)
{
    (void)wait_message;
    (void)timeout_ticks;
    return 0;
}

#define DEFINE_DESCRIPTOR(name) \
    struct kobjop_desc name##_desc = { \
        0, { &name##_desc, (kobjop_t)kobj_error_method } \
    }

DEFINE_DESCRIPTOR(device_probe);
DEFINE_DESCRIPTOR(device_attach);
DEFINE_DESCRIPTOR(device_detach);
DEFINE_DESCRIPTOR(device_shutdown);
DEFINE_DESCRIPTOR(device_suspend);
DEFINE_DESCRIPTOR(device_resume);
DEFINE_DESCRIPTOR(bus_read_ivar);
DEFINE_DESCRIPTOR(bus_write_ivar);
DEFINE_DESCRIPTOR(pci_read_config);
DEFINE_DESCRIPTOR(pci_write_config);
DEFINE_DESCRIPTOR(pci_enable_busmaster);
DEFINE_DESCRIPTOR(pci_disable_busmaster);
DEFINE_DESCRIPTOR(pci_enable_io);
DEFINE_DESCRIPTOR(pci_disable_io);
DEFINE_DESCRIPTOR(pci_find_cap);
DEFINE_DESCRIPTOR(pci_find_next_cap);
DEFINE_DESCRIPTOR(pci_find_htcap);
DEFINE_DESCRIPTOR(pci_find_next_htcap);
DEFINE_DESCRIPTOR(pci_alloc_msi);
DEFINE_DESCRIPTOR(pci_alloc_msix);
DEFINE_DESCRIPTOR(pci_release_msi);
DEFINE_DESCRIPTOR(pci_msi_count);
DEFINE_DESCRIPTOR(pci_msix_count);
DEFINE_DESCRIPTOR(pci_msix_pba_bar);
DEFINE_DESCRIPTOR(pci_msix_table_bar);

typedef struct {
    uint8_t config[256];
    uint8_t bar_probe;
    uint32_t next_vector;
    int vectors_allocated;
    int vectors_released;
    int msi_enable_count;
    int msi_disable_count;
    int msix_enable_count;
    int msix_disable_count;
    int msix_disable_all_count;
    uint32_t last_vector;
    int prepare_count;
    int translate_count;
} test_pci_backend_t;

typedef struct {
    bsd_interrupt_backend_callback_t callback;
    void *argument;
} test_interrupt_backend_t;

typedef struct {
    uint8_t memory[8192];
} test_bus_space_t;

static void *
test_allocate_pages(uint64_t page_count, void *context)
{
    void *memory = 0;

    (void)context;
    if (page_count > SIZE_MAX / 4096U ||
        posix_memalign(&memory, 4096U, (size_t)page_count * 4096U) != 0)
        return 0;
    return memory;
}

static void
test_release_pages(void *base, uint64_t page_count, void *context)
{
    (void)page_count;
    (void)context;
    free(base);
}

static int
test_bus_map(void *opaque_bus, bus_addr_t address, bus_size_t size,
    int flags, bus_space_handle_t *handle)
{
    test_bus_space_t *bus = opaque_bus;

    (void)flags;
    if (address < UINT64_C(0x10001000) ||
        address - UINT64_C(0x10001000) > sizeof(bus->memory) ||
        size > sizeof(bus->memory) -
            (address - UINT64_C(0x10001000)))
        return 22;
    *handle = (bus_space_handle_t)(uintptr_t)
        &bus->memory[address - UINT64_C(0x10001000)];
    return 0;
}

static void
test_bus_unmap(void *context, bus_space_handle_t handle, bus_size_t size)
{
    (void)context;
    (void)handle;
    (void)size;
}

static uint64_t
test_bus_read(void *context, bus_space_handle_t handle, bus_size_t offset,
    unsigned int width)
{
    uint64_t value = 0;

    (void)context;
    memcpy(&value, (void *)(uintptr_t)(handle + offset), width);
    return value;
}

static void
test_bus_write(void *context, bus_space_handle_t handle, bus_size_t offset,
    unsigned int width, uint64_t value)
{
    (void)context;
    memcpy((void *)(uintptr_t)(handle + offset), &value, width);
}

static uint32_t
test_config_read(void *opaque_backend,
    const bsd_pci_location_t *location, uint16_t register_offset,
    unsigned int width)
{
    test_pci_backend_t *backend = opaque_backend;
    uint32_t value = 0;

    assert(location->domain == 0);
    assert(location->bus == 0);
    assert(location->slot == 1);
    assert(location->function == 0);
    if (register_offset == 0x10 && backend->bar_probe)
        return UINT32_C(0xfffff000);
    assert(register_offset + width <= sizeof(backend->config));
    memcpy(&value, &backend->config[register_offset], width);
    return value;
}

static void
test_config_write(void *opaque_backend,
    const bsd_pci_location_t *location, uint16_t register_offset,
    uint32_t value, unsigned int width)
{
    test_pci_backend_t *backend = opaque_backend;

    (void)location;
    if (register_offset == 0x10 && width == 4) {
        if (value == UINT32_MAX) {
            backend->bar_probe = 1;
            return;
        }
        backend->bar_probe = 0;
    }
    assert(register_offset + width <= sizeof(backend->config));
    memcpy(&backend->config[register_offset], &value, width);
}

static size_t
test_function_count(void *context)
{
    (void)context;
    return 1;
}

static int
test_function_at(void *context, size_t index, bsd_pci_location_t *location)
{
    (void)context;
    if (index != 0)
        return 2;
    location->domain = 0;
    location->bus = 0;
    location->slot = 1;
    location->function = 0;
    return 0;
}

static int
test_prepare_device(void *opaque_backend,
    const bsd_pci_location_t *location)
{
    test_pci_backend_t *backend = opaque_backend;

    assert(location->domain == 0);
    assert(location->bus == 0);
    assert(location->slot == 1);
    assert(location->function == 0);
    backend->prepare_count++;
    return 0;
}

static int
test_translate_resource(void *opaque_backend,
    const bsd_pci_location_t *location, int resource_type,
    uint64_t bus_address, uint64_t size, uint64_t *host_address)
{
    test_pci_backend_t *backend = opaque_backend;

    (void)location;
    assert(resource_type == SYS_RES_MEMORY);
    assert(bus_address == UINT64_C(0x1000));
    assert(size == UINT64_C(0x1000));
    assert(host_address != 0);
    *host_address = bus_address + UINT64_C(0x10000000);
    backend->translate_count++;
    return 0;
}

static int
test_legacy_interrupt(void *context,
    const bsd_pci_location_t *location, uint8_t interrupt_line,
    uint32_t *interrupt, uint32_t *interrupt_flags)
{
    (void)context;
    (void)location;
    *interrupt = 32u + interrupt_line;
    *interrupt_flags = 4;
    return 0;
}

static int
test_allocate_vectors(void *opaque_backend, unsigned int requested,
    int contiguous, uint32_t *vectors, unsigned int *allocated)
{
    test_pci_backend_t *backend = opaque_backend;

    (void)contiguous;
    assert(*allocated >= requested);
    for (unsigned int index = 0; index < requested; ++index)
        vectors[index] = backend->next_vector++;
    backend->vectors_allocated += (int)requested;
    *allocated = requested;
    return 0;
}

static void
test_release_vectors(void *opaque_backend, const uint32_t *vectors,
    unsigned int count)
{
    test_pci_backend_t *backend = opaque_backend;

    (void)vectors;
    backend->vectors_released += (int)count;
}

static int
test_enable_msi(void *opaque_backend,
    const bsd_pci_location_t *location, const uint32_t *vectors,
    unsigned int count)
{
    test_pci_backend_t *backend = opaque_backend;

    (void)location;
    assert(count == 1);
    backend->last_vector = vectors[0];
    backend->msi_enable_count++;
    return 0;
}

static int
test_disable_msi(void *opaque_backend,
    const bsd_pci_location_t *location)
{
    test_pci_backend_t *backend = opaque_backend;

    (void)location;
    backend->msi_disable_count++;
    return 0;
}

static int
test_enable_msix(void *opaque_backend,
    const bsd_pci_location_t *location, unsigned int table_index,
    uint32_t vector)
{
    test_pci_backend_t *backend = opaque_backend;

    (void)location;
    assert(table_index < 2);
    backend->last_vector = vector;
    backend->msix_enable_count++;
    return 0;
}

static int
test_disable_msix(void *opaque_backend,
    const bsd_pci_location_t *location, unsigned int table_index)
{
    test_pci_backend_t *backend = opaque_backend;

    (void)location;
    assert(table_index < 2);
    backend->msix_disable_count++;
    return 0;
}

static int
test_disable_msix_all(void *opaque_backend,
    const bsd_pci_location_t *location)
{
    test_pci_backend_t *backend = opaque_backend;

    (void)location;
    backend->msix_disable_all_count++;
    return 0;
}

static int
test_interrupt_register(void *opaque_backend, uint32_t interrupt,
    uint32_t flags, uint32_t interrupt_flags,
    bsd_interrupt_backend_callback_t callback, void *argument,
    void **cookie)
{
    test_interrupt_backend_t *backend = opaque_backend;

    (void)interrupt;
    (void)flags;
    assert(interrupt_flags == 0);
    assert(backend->callback == 0);
    backend->callback = callback;
    backend->argument = argument;
    *cookie = backend;
    return 0;
}

static int
test_interrupt_unregister(void *opaque_backend, void *cookie)
{
    test_interrupt_backend_t *backend = opaque_backend;

    assert(cookie == backend);
    backend->callback = 0;
    backend->argument = 0;
    return 0;
}

static int
test_interrupt_schedule(void *opaque_backend, driver_intr_t *handler,
    void *argument)
{
    (void)opaque_backend;
    handler(argument);
    return 0;
}

static void
test_handler(void *opaque_count)
{
    int *count = opaque_count;

    (*count)++;
}

static void
config_write(test_pci_backend_t *backend, unsigned int offset,
    uint32_t value, unsigned int width)
{
    memcpy(&backend->config[offset], &value, width);
}

static int
test_reject_device(void *opaque_count,
    const bsd_pci_device_identity_t *identity)
{
    int *count = opaque_count;

    (*count)++;
    assert(identity->location.domain == 0);
    assert(identity->location.bus == 0);
    assert(identity->location.slot == 1);
    assert(identity->location.function == 0);
    assert(identity->vendor == UINT16_C(0x1af4));
    assert(identity->device == UINT16_C(0x1041));
    assert(identity->subvendor == UINT16_C(0x1af4));
    assert(identity->subdevice == UINT16_C(0x0001));
    assert(identity->class_code == UINT8_C(0x02));
    return 0;
}

int
main(void)
{
    static const struct pci_device_table match_table[] = {
        {
            .match_flag_vendor = 1,
            .match_flag_device = 1,
            .vendor = UINT16_C(0x1af4),
            .device = UINT16_C(0xffff),
        },
        {
            .match_flag_vendor = 1,
            .match_flag_device = 1,
            .match_flag_subvendor = 1,
            .match_flag_subdevice = 1,
            .match_flag_class = 1,
            .vendor = UINT16_C(0x1af4),
            .device = UINT16_C(0x1041),
            .subvendor = UINT16_C(0x1af4),
            .subdevice = UINT16_C(0x0001),
            .class_id = UINT16_C(0x0002),
        },
    };
    static const struct pci_device_table no_match_table[] = {
        {
            .match_flag_vendor = 1,
            .vendor = UINT16_C(0xffff),
        },
    };
    bsd_allocator_ops_t allocator_operations = {
        .allocate_pages = test_allocate_pages,
        .release_pages = test_release_pages,
    };
    test_pci_backend_t pci_backend = {.next_vector = 64};
    test_interrupt_backend_t interrupt_backend = {0};
    test_bus_space_t bus_space = {0};
    bsd_bus_space_ops_t bus_operations = {
        .map = test_bus_map,
        .unmap = test_bus_unmap,
        .read = test_bus_read,
        .write = test_bus_write,
        .context = &bus_space,
    };
    bsd_interrupt_backend_ops_t interrupt_operations = {
        .register_interrupt = test_interrupt_register,
        .unregister_interrupt = test_interrupt_unregister,
        .schedule_handler = test_interrupt_schedule,
        .context = &interrupt_backend,
    };
    bsd_pci_backend_ops_t pci_operations = {
        .read_config = test_config_read,
        .write_config = test_config_write,
        .function_count = test_function_count,
        .function_at = test_function_at,
        .prepare_device = test_prepare_device,
        .translate_resource = test_translate_resource,
        .legacy_interrupt = test_legacy_interrupt,
        .allocate_vectors = test_allocate_vectors,
        .release_vectors = test_release_vectors,
        .enable_msi = test_enable_msi,
        .disable_msi = test_disable_msi,
        .enable_msix = test_enable_msix,
        .disable_msix = test_disable_msix,
        .disable_msix_all = test_disable_msix_all,
        .context = &pci_backend,
    };
    device_t root;
    device_t pci_bus;
    device_t rejected_bus;
    device_t pci_device;
    device_t *children;
    bsd_pci_bus_status_t bus_status;
    bsd_pci_attach_options_t reject_options = {0};
    struct resource *bar;
    struct resource *interrupt;
    rman_res_t start;
    rman_res_t count_value;
    int child_count;
    int count;
    int handler_count = 0;
    int selector_count = 0;
    int capability;
    void *cookie;

    config_write(&pci_backend, 0x00, UINT32_C(0x10411af4), 4);
    config_write(&pci_backend, 0x06, UINT32_C(0x0010), 2);
    config_write(&pci_backend, 0x0b, UINT32_C(0x02), 1);
    config_write(&pci_backend, 0x0e, UINT32_C(0x00), 1);
    config_write(&pci_backend, 0x10, UINT32_C(0x1000), 4);
    config_write(&pci_backend, 0x2c, UINT32_C(0x00011af4), 4);
    config_write(&pci_backend, 0x34, UINT32_C(0x40), 1);
    config_write(&pci_backend, 0x3c, UINT32_C(0x010b), 2);
    config_write(&pci_backend, 0x40, UINT32_C(0x00005005), 4);
    config_write(&pci_backend, 0x50, UINT32_C(0x00016011), 4);
    config_write(&pci_backend, 0x54, UINT32_C(0x00000000), 4);
    config_write(&pci_backend, 0x58, UINT32_C(0x00000800), 4);
    config_write(&pci_backend, 0x60, UINT32_C(0x00007001), 4);
    config_write(&pci_backend, 0x64, UINT32_C(0x00000003), 2);
    config_write(&pci_backend, 0x70, UINT32_C(0x00000010), 4);
    config_write(&pci_backend, 0x74, UINT32_C(0x10000000), 4);
    config_write(&pci_backend, 0x78, UINT32_C(0x00002000), 2);

    assert(bsd_allocator_initialize(&allocator_operations) == 0);
    assert(bsd_bus_space_initialize(&bus_operations, 0) == 0);
    assert(bsd_interrupt_initialize(&interrupt_operations) == 0);
    assert(bsd_pci_initialize(&pci_operations) == 0);
    root = bsd_newbus_create_root("root", 0, 0);
    assert(root != 0);
    pci_bus = bsd_pci_attach_bus(root);
    assert(pci_bus != 0);
    assert(device_get_children(pci_bus, &children, &child_count) == 0);
    assert(child_count == 1);
    pci_device = children[0];
    bsd_free(children, M_TEMP);
    assert(bsd_pci_bus_get_status(pci_bus, &bus_status) == 0);
    assert(bus_status.discovered == 1);
    assert(bus_status.selected == 1);
    assert(bus_status.attached == 0);
    assert(bus_status.unclaimed == 1);
    assert(pci_backend.prepare_count == 1);
    assert(pci_backend.translate_count == 1);
    assert(pci_find_device(UINT16_C(0x1af4), UINT16_C(0x1041)) ==
        pci_device);
    assert(pci_find_device(UINT16_C(0x1af4), UINT16_C(0xffff)) == 0);
    assert(pci_find_bsf(0, 1, 0) == pci_device);
    assert(pci_find_dbsf(0, 0, 1, 0) == pci_device);
    assert(pci_find_bsf(0, 2, 0) == 0);
    assert(pci_find_dbsf(1, 0, 1, 0) == 0);
    assert(pci_find_bsf(0, 32, 0) == 0);
    assert(pci_find_bsf(0, 1, 8) == 0);
    assert(pci_match_device(pci_device, match_table,
        sizeof(match_table) / sizeof(match_table[0])) == &match_table[1]);
    assert(pci_match_device(pci_device, no_match_table,
        sizeof(no_match_table) / sizeof(no_match_table[0])) == 0);
    assert(is_pci_device(pci_device));
    assert(!is_pci_device(pci_bus));
    assert(cfgmech == 3);
    assert(pci_cfgregread(0, 0, 1, 0, 0, 2) ==
        UINT32_C(0x1af4));
    pci_cfgregwrite(0, 0, 1, 0, 0x80, UINT32_C(0x12345678), 4);
    assert(pci_cfgregread(0, 0, 1, 0, 0x80, 4) ==
        UINT32_C(0x12345678));
    assert(pci_cfgregread(-1, 0, 1, 0, 0, 4) == UINT32_MAX);

    assert(bsd_pci_read_config(pci_device, 0, 2) == UINT32_C(0x1af4));
    assert(bsd_pci_find_capability(pci_device, 0x05, 0,
        &capability) == 0);
    assert(capability == 0x40);
    assert(bsd_pci_find_capability(pci_device, 0x11, 0, 0) == 0);
    assert(bsd_pci_msi_count(pci_device) == 1);
    assert(bsd_pci_msix_count(pci_device) == 2);
    assert(bsd_pci_msix_table_bar(pci_device) == 0x10);
    assert(bsd_pci_msix_pba_bar(pci_device) == 0x10);
    assert(pci_has_pm(pci_device));
    pci_enable_pme(pci_device);
    assert(bsd_pci_read_config(pci_device, 0x64, 2) ==
        UINT32_C(0x8103));
    assert(pci_get_max_read_req(pci_device) == 512);
    assert(pci_set_max_read_req(pci_device, 3000) == 2048);
    assert(pci_get_max_read_req(pci_device) == 2048);
    assert(pci_set_max_read_req(pci_device, 64) == 128);
    assert(pci_get_max_read_req(pci_device) == 128);
    assert(pcie_wait_for_pending_transactions(pci_device, 0));
    assert(pcie_get_max_completion_timeout(pci_device) == 50 * 1000);
    assert(pcie_flr(pci_device, 0, false));
    assert((bsd_pci_read_config(pci_device, 0x78, 2) &
        UINT32_C(0x8000)) != 0);
    assert((bsd_pci_read_config(pci_device, 0x04, 2) &
        UINT32_C(0x0004)) == 0);
    assert(bus_get_resource(pci_device, SYS_RES_MEMORY, 0x10,
        &start, &count_value) == 0);
    assert(start == UINT64_C(0x10001000));
    assert(count_value == 0x1000);
    {
        struct pci_map *map = pci_find_bar(pci_device, 0x10);

        assert(map != 0);
        assert(map->pm_reg == 0x10);
        assert(map->pm_value == UINT64_C(0x1000));
        assert(map->pm_size == UINT64_C(0x1000));
        assert(pci_find_bar(pci_device, 0x14) == 0);
    }
    assert(bsd_pci_read_config(pci_device, 0x04, 2) &
        UINT32_C(0x0002));

    count = 1;
    assert(bsd_pci_alloc_msi(pci_device, &count) == 0);
    assert(count == 1);
    interrupt = bus_alloc_resource(pci_device, SYS_RES_IRQ, 1, 0,
        RM_MAX_END, 1, RF_ACTIVE);
    assert(interrupt != 0);
    assert(bus_setup_intr(pci_device, interrupt,
        INTR_TYPE_NET | INTR_MPSAFE, 0, test_handler,
        &handler_count, &cookie) == 0);
    assert(pci_backend.msi_enable_count == 1);
    assert(pci_backend.last_vector == 64);
    assert(bsd_pci_reprogram_interrupts() == 0);
    assert(pci_backend.msi_enable_count == 2);
    pci_cfg_save(pci_device, 0, 1);
    assert((bsd_pci_read_config(pci_device, 0x64, 2) & 3u) == 3u);
    bsd_pci_write_config(pci_device, 0x04, 0, 2);
    bsd_pci_write_config(pci_device, 0x0c, 0xaa, 1);
    bsd_pci_write_config(pci_device, 0x0d, 0xbb, 1);
    bsd_pci_write_config(pci_device, 0x10, 0, 4);
    bsd_pci_write_config(pci_device, 0x3c, 0xcc, 1);
    pci_cfg_restore(pci_device, 0);
    assert((bsd_pci_read_config(pci_device, 0x64, 2) & 3u) == 0);
    assert((bsd_pci_read_config(pci_device, 0x04, 2) & 2u) != 0);
    assert(bsd_pci_read_config(pci_device, 0x0c, 1) == 0);
    assert(bsd_pci_read_config(pci_device, 0x0d, 1) == 0);
    assert(bsd_pci_read_config(pci_device, 0x10, 4) ==
        UINT32_C(0x1000));
    assert(bsd_pci_read_config(pci_device, 0x3c, 1) ==
        UINT32_C(0x0b));
    assert(pci_backend.msi_enable_count == 3);
    pci_save_state(pci_device);
    bsd_pci_write_config(pci_device, 0x04, 0, 2);
    bsd_pci_write_config(pci_device, 0x10, 0, 4);
    pci_restore_state(pci_device);
    assert((bsd_pci_read_config(pci_device, 0x04, 2) & 2u) != 0);
    assert(bsd_pci_read_config(pci_device, 0x10, 4) ==
        UINT32_C(0x1000));
    assert(pci_backend.msi_enable_count == 4);
    interrupt_backend.callback(interrupt_backend.argument);
    assert(handler_count == 1);
    assert(bus_teardown_intr(pci_device, interrupt, cookie) == 0);
    assert(pci_backend.msi_disable_count == 1);
    assert(bus_release_resource(pci_device, interrupt) == 0);
    assert(bsd_pci_release_msi(pci_device) == 0);

    bar = bus_alloc_resource(pci_device, SYS_RES_MEMORY, 0x10, 0,
        RM_MAX_END, 1, RF_ACTIVE);
    assert(bar != 0);
    count = 2;
    assert(bsd_pci_alloc_msix(pci_device, &count) == 0);
    assert(count == 2);
    interrupt = bus_alloc_resource(pci_device, SYS_RES_IRQ, 1, 0,
        RM_MAX_END, 1, RF_ACTIVE);
    assert(interrupt != 0);
    assert(bus_setup_intr(pci_device, interrupt,
        INTR_TYPE_NET | INTR_MPSAFE, 0, test_handler,
        &handler_count, &cookie) == 0);
    assert(pci_backend.msix_enable_count == 1);
    assert(bsd_pci_reprogram_interrupts() == 0);
    assert(pci_backend.msix_enable_count == 2);
    assert(bus_teardown_intr(pci_device, interrupt, cookie) == 0);
    assert(pci_backend.msix_disable_count == 1);
    assert(bus_release_resource(pci_device, interrupt) == 0);
    assert(bsd_pci_release_msi(pci_device) == 0);
    assert(pci_backend.msix_disable_all_count == 1);
    assert(pci_backend.vectors_allocated == 3);
    assert(pci_backend.vectors_released == 3);
    assert(bus_release_resource(pci_device, bar) == 0);

    reject_options.select_device = test_reject_device;
    reject_options.context = &selector_count;
    rejected_bus = bsd_pci_attach_bus_selected(root, &reject_options);
    assert(rejected_bus != 0);
    assert(selector_count == 1);
    assert(device_get_children(rejected_bus, &children,
        &child_count) == 0);
    assert(children == 0);
    assert(child_count == 0);
    assert(bsd_pci_bus_get_status(rejected_bus, &bus_status) == 0);
    assert(bus_status.discovered == 1);
    assert(bus_status.selected == 0);
    assert(bus_status.attached == 0);
    assert(bus_status.unclaimed == 0);
    assert(device_detach(rejected_bus) == 0);
    assert(device_delete_child(root, rejected_bus) == 0);

    assert(device_detach(pci_bus) == 0);
    assert(device_delete_child(root, pci_bus) == 0);
    return 0;
}
