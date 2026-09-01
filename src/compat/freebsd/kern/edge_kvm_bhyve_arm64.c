/* SPDX-License-Identifier: MPL-2.0 */
/* EdgeOS-owned ARM64 KVM translation for the imported FreeBSD bhyve core. */

#include <stdint.h>

#include "compat/freebsd/edgeos/allocator.h"
#include "compat/freebsd/edgeos/kthread.h"
#include "compat/freebsd/edgeos/sleep.h"
#include "compat/freebsd/edgeos/newbus.h"
#include "kernel/edge_kvm_abi.h"
#include "kernel/edge_kvm_bhyve.h"
#include "kernel/edge_kvm_capability.h"
#include "kernel/boot_command_line.h"
#include "kernel/eventfd.h"
#include "kernel/edge_kvm_object.h"
#include "kernel/edge_kvm_runtime.h"
#include "kernel/linux_errno.h"
#include "kernel/mm_runtime.h"
#include "arch/arm64/vm.h"
#include "mm/arch_vm.h"
#include <sys/param.h>
#include <sys/mman.h>
#include <sys/sglist.h>
#include <sys/smp.h>
#include <sys/kthread.h>
#include <vm/vm_object.h>
#include <vm/vm_pager.h>
#include <dev/vmm/vmm_mem.h>
#include <dev/vmm/vmm_dev.h>
#include <dev/vmm/vmm_vm.h>
#include <dev/psci/psci.h>
#include <machine/vfp.h>
#include <machine/pcb.h>
#include <machine/armreg.h>
#include <machine/cpu.h>
#include <machine/vmm.h>
#include <arm64/vmm/arm64.h>
#include <arm64/vmm/reset.h>
#include <arm64/vmm/io/vgic.h>
#include <arm64/vmm/io/vgic_v3.h>
#include <arm64/vmm/io/vtimer.h>

#define EDGE_KVM_ARM64_TARGET_GENERIC_V8 0u
#define EDGE_KVM_ARM64_SUPPORTED_FEATURES \
    (EDGE_KVM_ARM_VCPU_FEATURE(EDGE_KVM_ARM_VCPU_POWER_OFF) | \
     EDGE_KVM_ARM_VCPU_FEATURE(EDGE_KVM_ARM_VCPU_PSCI_0_2))
#define EDGE_KVM_BHYVE_ARM64_MAX_SLOTS VM_MAXSYSMEM
#define EDGE_KVM_BHYVE_ARM64_MAX_IOEVENTFDS 256u
#define EDGE_KVM_BHYVE_ARM64_MAX_IRQFDS 256u
#define EDGE_KVM_BHYVE_ARM64_PAGE_CHUNK_CAPACITY 2048u
#define EDGE_KVM_ARM_IRQ_TYPE_SHIFT 24u
#define EDGE_KVM_ARM_IRQ_VCPU_SHIFT 16u
#define EDGE_KVM_ARM_IRQ_TYPE_MASK 0x0fu
#define EDGE_KVM_ARM_IRQ_VCPU_MASK 0xffu
#define EDGE_KVM_ARM_IRQ_NUM_MASK 0xffffu
#define EDGE_KVM_ARM_IRQ_TYPE_SPI 1u
#define EDGE_KVM_ARM_IRQ_TYPE_PPI 2u

typedef struct edge_kvm_bhyve_arm64_page_chunk {
    struct edge_kvm_bhyve_arm64_page_chunk *next;
    uint32_t count;
    uint32_t reserved;
    uint64_t pages[EDGE_KVM_BHYVE_ARM64_PAGE_CHUNK_CAPACITY];
} edge_kvm_bhyve_arm64_page_chunk_t;

typedef struct edge_kvm_bhyve_arm64_memory_slot {
    uint8_t active;
    uint8_t reserved[7];
    uint64_t guest_physical_address;
    uint64_t memory_size;
    uint64_t userspace_address;
    edge_kvm_bhyve_arm64_page_chunk_t *page_chunks;
    uint32_t page_count;
    uint32_t flags;
} edge_kvm_bhyve_arm64_memory_slot_t;

typedef struct edge_kvm_bhyve_arm64_coalesced_zone {
    uint8_t active;
    uint8_t reserved[7];
    edge_kvm_coalesced_mmio_zone_t zone;
} edge_kvm_bhyve_arm64_coalesced_zone_t;

typedef struct edge_kvm_bhyve_arm64_ioeventfd {
    uint8_t active;
    uint8_t reserved[3];
    edge_kvm_ioeventfd_registration_t registration;
} edge_kvm_bhyve_arm64_ioeventfd_t;

struct edge_kvm_bhyve_arm64_vm;

typedef struct edge_kvm_bhyve_arm64_irqfd {
    uint8_t active;
    uint8_t reserved[3];
    edge_kvm_irqfd_registration_t registration;
    struct edge_kvm_bhyve_arm64_vm *vm;
} edge_kvm_bhyve_arm64_irqfd_t;

typedef struct edge_kvm_bhyve_arm64_vm {
    struct vm *vm;
    struct edge_kvm_bhyve_arm64_vcpu *vcpus[VM_MAXCPU];
    edge_kvm_bhyve_arm64_memory_slot_t
        slots[EDGE_KVM_BHYVE_ARM64_MAX_SLOTS];
    edge_kvm_bhyve_arm64_ioeventfd_t
        ioeventfds[EDGE_KVM_BHYVE_ARM64_MAX_IOEVENTFDS];
    edge_kvm_bhyve_arm64_irqfd_t
        irqfds[EDGE_KVM_BHYVE_ARM64_MAX_IRQFDS];
    edge_kvm_bhyve_arm64_coalesced_zone_t
        coalesced_zones[EDGE_KVM_MAX_COALESCED_MMIO_ZONES];
    void *coalesced_mmio_page;
    volatile uint8_t coalesced_mmio_lock;
} edge_kvm_bhyve_arm64_vm_t;

typedef struct edge_kvm_bhyve_arm64_vcpu {
    struct vcpu *vcpu;
    edge_kvm_bhyve_arm64_vm_t *vm;
    struct thread runtime_thread;
    void *run_pages[EDGE_KVM_VCPU_MMAP_PAGES];
    edge_kvm_vcpu_init_t init;
    uint8_t initialized;
    uint8_t powered_off;
    uint8_t pending_mmio_read;
    uint8_t pending_mmio_size;
    uint8_t pending_mmio_sign_extend;
    uint8_t system_event_pending;
    uint32_t system_event_type;
    uint32_t trace_run_count;
    uint32_t trace_exit_count;
    enum vm_reg_name pending_mmio_register;
    uint64_t auxiliary_spsr[4];
} edge_kvm_bhyve_arm64_vcpu_t;

typedef struct edge_kvm_bhyve_arm64_device {
    edge_kvm_bhyve_arm64_vm_t *vm;
    struct vm_vgic_descr descriptor;
    uint32_t interrupt_count;
    uint8_t dist_set;
    uint8_t redist_set;
    uint8_t attached;
    uint8_t init_requested;
} edge_kvm_bhyve_arm64_device_t;

u_int vm_maxcpu;

int vmm_modinit(void);
int vmm_modcleanup(void);
extern driver_t vgic_v3_driver;

static uint8_t g_bhyve_arm64_initialized;
static uint8_t g_bhyve_arm64_trace;
static volatile uint32_t g_bhyve_arm64_vm_sequence;
static device_t g_bhyve_arm64_vgic_device;

static void edge_kvm_bhyve_arm64_irqfd_notify(
    void *context, int event_id);

static void
edge_kvm_bhyve_arm64_irqfd_release(edge_kvm_bhyve_arm64_irqfd_t *irqfd)
{
    if (!irqfd || !irqfd->active)
        return;
    (void)kernel_eventfd_observer_unregister(
        irqfd->registration.event_id,
        edge_kvm_bhyve_arm64_irqfd_notify, irqfd);
    kernel_eventfd_release(irqfd->registration.event_id);
    if (irqfd->registration.resample_event_id >= 0)
        kernel_eventfd_release(irqfd->registration.resample_event_id);
    memset(irqfd, 0, sizeof(*irqfd));
}

static int
edge_kvm_bhyve_arm64_error(int error)
{
    switch (error) {
    case 0:
        return 0;
    case 2:
        return -EDGE_LINUX_ENOENT;
    case 12:
        return -EDGE_LINUX_ENOMEM;
    case 14:
        return -EDGE_LINUX_EFAULT;
    case 16:
        return -EDGE_LINUX_EBUSY;
    case 17:
        return -EDGE_LINUX_EEXIST;
    case 22:
        return -EDGE_LINUX_EINVAL;
    case 28:
        return -EDGE_LINUX_ENOSPC;
    default:
        return -EDGE_LINUX_EIO;
    }
}

static void
edge_kvm_bhyve_arm64_name(char name[VM_MAX_NAMELEN + 1])
{
    static const char digits[] = "0123456789abcdef";
    const char prefix[] = "edge-kvm-arm-";
    uint32_t value = __atomic_add_fetch(&g_bhyve_arm64_vm_sequence, 1u,
        __ATOMIC_RELAXED);
    uint32_t position = 0;

    for (; position < sizeof(prefix) - 1u; ++position)
        name[position] = prefix[position];
    for (int shift = 28; shift >= 0; shift -= 4)
        name[position++] = digits[(value >> shift) & 0xfu];
    name[position] = 0;
}

static void
edge_kvm_bhyve_arm64_release_pages(
    edge_kvm_bhyve_arm64_memory_slot_t *slot)
{
    edge_kvm_bhyve_arm64_page_chunk_t *chunk;

    if (!slot)
        return;
    chunk = slot->page_chunks;
    while (chunk) {
        edge_kvm_bhyve_arm64_page_chunk_t *next = chunk->next;

        for (uint32_t page = 0; page < chunk->count; ++page)
            arch_vm_free_page((void *)(uintptr_t)chunk->pages[page]);
        bsd_kfree(chunk);
        chunk = next;
    }
    slot->page_chunks = 0;
    slot->page_count = 0;
}

static int
edge_kvm_bhyve_arm64_build_object(
    const edge_kvm_memory_region_t *region, vm_object_t *object_out,
    edge_kvm_bhyve_arm64_page_chunk_t **chunks_out,
    uint32_t *page_count_out)
{
    struct sglist *sg;
    vm_object_t object;
    edge_kvm_bhyve_arm64_page_chunk_t *chunks = 0;
    edge_kvm_bhyve_arm64_page_chunk_t *tail = 0;
    uint64_t page_count64;
    uint32_t protection = ARCH_VM_PROT_READ;
    uint32_t page_count;
    uint32_t max_segments;
    int error = 0;

    if (!object_out || !chunks_out || !page_count_out)
        return -EDGE_LINUX_EFAULT;
    *page_count_out = 0;
    if ((region->flags & EDGE_KVM_MEMORY_READONLY) == 0)
        protection |= ARCH_VM_PROT_WRITE;
    page_count64 = region->memory_size / EDGE_KVM_PAGE_SIZE;
    if (page_count64 == 0 || page_count64 > UINT32_MAX)
        return -EDGE_LINUX_EINVAL;
    page_count = (uint32_t)page_count64;
    max_segments = page_count > UINT16_MAX ? UINT16_MAX : page_count;
    sg = sglist_alloc((int)max_segments, BSD_M_WAITOK);
    if (!sg)
        return -EDGE_LINUX_ENOMEM;
    for (uint32_t page = 0; page < page_count; ++page) {
        uint64_t user_address = region->userspace_address +
            (uint64_t)page * EDGE_KVM_PAGE_SIZE;
        uint64_t physical_address;

        if (g_bhyve_arm64_trace && (page & 4095u) == 0)
            bsd_printf("edge-kvm-arm64: pin pages=%u/%u\n",
                page, page_count);

        if (edgeos_arm64_kvm_pin_user_page(
                user_address, protection, &physical_address) < 0) {
            error = -EDGE_LINUX_EFAULT;
            break;
        }
        if (!tail ||
            tail->count == EDGE_KVM_BHYVE_ARM64_PAGE_CHUNK_CAPACITY) {
            edge_kvm_bhyve_arm64_page_chunk_t *chunk = bsd_kmalloc(
                sizeof(*chunk), BSD_M_WAITOK | BSD_M_ZERO);

            if (!chunk) {
                arch_vm_free_page((void *)(uintptr_t)physical_address);
                error = -EDGE_LINUX_ENOMEM;
                break;
            }
            if (tail)
                tail->next = chunk;
            else
                chunks = chunk;
            tail = chunk;
        }
        tail->pages[tail->count++] = physical_address;
        if (sglist_append_phys(sg, physical_address,
                EDGE_KVM_PAGE_SIZE) != 0) {
            arch_vm_free_page((void *)(uintptr_t)physical_address);
            --tail->count;
            error = -EDGE_LINUX_ENOSPC;
            break;
        }
        *page_count_out = page + 1u;
    }
    if (error < 0) {
        edge_kvm_bhyve_arm64_memory_slot_t failed = {
            .page_chunks = chunks,
            .page_count = *page_count_out,
        };

        edge_kvm_bhyve_arm64_release_pages(&failed);
        sglist_free(sg);
        *page_count_out = 0;
        return error;
    }
    object = vm_pager_allocate(OBJT_SG, sg, region->memory_size,
        protection, 0, 0);
    if (!object) {
        edge_kvm_bhyve_arm64_memory_slot_t failed = {
            .page_chunks = chunks,
            .page_count = page_count,
        };

        edge_kvm_bhyve_arm64_release_pages(&failed);
        sglist_free(sg);
        *page_count_out = 0;
        return -EDGE_LINUX_ENOMEM;
    }
    *object_out = object;
    *chunks_out = chunks;
    return 0;
}

static int
edge_kvm_bhyve_arm64_vm_create(void *context, uint32_t machine_type,
    uint64_t *cookie)
{
    edge_kvm_bhyve_arm64_vm_t *backend_vm;
    char name[VM_MAX_NAMELEN + 1];
    int error;

    (void)context;
    if (!cookie || machine_type != 0)
        return -EDGE_LINUX_EINVAL;
    backend_vm = bsd_kmalloc(sizeof(*backend_vm),
        BSD_M_WAITOK | BSD_M_ZERO);
    if (!backend_vm)
        return -EDGE_LINUX_ENOMEM;
    edge_kvm_bhyve_arm64_name(name);
    error = vm_create(name, &backend_vm->vm);
    if (error != 0) {
        bsd_kfree(backend_vm);
        return edge_kvm_bhyve_arm64_error(error);
    }
    backend_vm->coalesced_mmio_page = arch_vm_alloc_page();
    if (!backend_vm->coalesced_mmio_page) {
        vm_destroy(backend_vm->vm);
        bsd_kfree(backend_vm);
        return -EDGE_LINUX_ENOMEM;
    }
    memset(backend_vm->coalesced_mmio_page, 0, EDGE_KVM_PAGE_SIZE);
    if (g_bhyve_arm64_trace)
        bsd_printf("edge-kvm-arm64: vm created\n");
    *cookie = (uint64_t)(uintptr_t)backend_vm;
    return 0;
}

static void
edge_kvm_bhyve_arm64_vm_destroy(void *context, uint64_t cookie)
{
    edge_kvm_bhyve_arm64_vm_t *backend_vm =
        (edge_kvm_bhyve_arm64_vm_t *)(uintptr_t)cookie;

    (void)context;
    if (!backend_vm)
        return;
    for (uint32_t index = 0;
         index < EDGE_KVM_BHYVE_ARM64_MAX_IOEVENTFDS; ++index) {
        if (backend_vm->ioeventfds[index].active) {
            kernel_eventfd_release(
                backend_vm->ioeventfds[index].registration.event_id);
        }
    }
    for (uint32_t index = 0;
         index < EDGE_KVM_BHYVE_ARM64_MAX_IRQFDS; ++index)
        edge_kvm_bhyve_arm64_irqfd_release(&backend_vm->irqfds[index]);
    vm_destroy(backend_vm->vm);
    for (uint32_t slot = 0; slot < EDGE_KVM_BHYVE_ARM64_MAX_SLOTS;
         ++slot)
        edge_kvm_bhyve_arm64_release_pages(&backend_vm->slots[slot]);
    arch_vm_free_page(backend_vm->coalesced_mmio_page);
    bsd_kfree(backend_vm);
}

static void
edge_kvm_bhyve_arm64_coalesced_lock(edge_kvm_bhyve_arm64_vm_t *backend_vm)
{
    while (__atomic_test_and_set(&backend_vm->coalesced_mmio_lock,
        __ATOMIC_ACQUIRE))
        __asm__ __volatile__("yield" ::: "memory");
}

static void
edge_kvm_bhyve_arm64_coalesced_unlock(edge_kvm_bhyve_arm64_vm_t *backend_vm)
{
    __atomic_clear(&backend_vm->coalesced_mmio_lock, __ATOMIC_RELEASE);
}

static int
edge_kvm_bhyve_arm64_vm_coalesced_mmio(void *context,
    uint64_t backend_cookie, const edge_kvm_coalesced_mmio_zone_t *zone,
    uint8_t unregister)
{
    edge_kvm_bhyve_arm64_vm_t *backend_vm =
        (edge_kvm_bhyve_arm64_vm_t *)(uintptr_t)backend_cookie;
    int empty = -1;

    (void)context;
    if (!backend_vm || !zone || !zone->size || zone->pio ||
        zone->address > UINT64_MAX - zone->size)
        return -EDGE_LINUX_EINVAL;
    edge_kvm_bhyve_arm64_coalesced_lock(backend_vm);
    for (uint32_t index = 0;
         index < EDGE_KVM_MAX_COALESCED_MMIO_ZONES; ++index) {
        edge_kvm_bhyve_arm64_coalesced_zone_t *entry =
            &backend_vm->coalesced_zones[index];

        if (!entry->active) {
            if (empty < 0)
                empty = (int)index;
            continue;
        }
        if (entry->zone.address == zone->address &&
            entry->zone.size == zone->size &&
            entry->zone.pio == zone->pio) {
            if (!unregister) {
                edge_kvm_bhyve_arm64_coalesced_unlock(backend_vm);
                return -EDGE_LINUX_EEXIST;
            }
            memset(entry, 0, sizeof(*entry));
            edge_kvm_bhyve_arm64_coalesced_unlock(backend_vm);
            return 0;
        }
    }
    if (unregister) {
        edge_kvm_bhyve_arm64_coalesced_unlock(backend_vm);
        return -EDGE_LINUX_ENOENT;
    }
    if (empty < 0) {
        edge_kvm_bhyve_arm64_coalesced_unlock(backend_vm);
        return -EDGE_LINUX_ENOSPC;
    }
    backend_vm->coalesced_zones[empty].active = 1;
    backend_vm->coalesced_zones[empty].zone = *zone;
    edge_kvm_bhyve_arm64_coalesced_unlock(backend_vm);
    return 0;
}

static int
edge_kvm_bhyve_arm64_coalesced_mmio_write(
    edge_kvm_bhyve_arm64_vm_t *backend_vm, uint64_t address,
    uint64_t value, uint32_t length)
{
    edge_kvm_coalesced_mmio_ring_t *ring;
    uint32_t first;
    uint32_t last;
    uint32_t next;
    int matched = 0;

    if (!backend_vm || !backend_vm->coalesced_mmio_page ||
        !length || length > 8)
        return 0;
    edge_kvm_bhyve_arm64_coalesced_lock(backend_vm);
    for (uint32_t index = 0;
         index < EDGE_KVM_MAX_COALESCED_MMIO_ZONES; ++index) {
        const edge_kvm_bhyve_arm64_coalesced_zone_t *entry =
            &backend_vm->coalesced_zones[index];
        uint64_t offset;

        if (!entry->active || address < entry->zone.address)
            continue;
        offset = address - entry->zone.address;
        if (offset <= entry->zone.size &&
            length <= entry->zone.size - offset) {
            matched = 1;
            break;
        }
    }
    if (!matched) {
        edge_kvm_bhyve_arm64_coalesced_unlock(backend_vm);
        return 0;
    }
    ring = backend_vm->coalesced_mmio_page;
    first = __atomic_load_n(&ring->first, __ATOMIC_ACQUIRE);
    last = __atomic_load_n(&ring->last, __ATOMIC_RELAXED);
    next = (last + 1u) % EDGE_KVM_COALESCED_MMIO_MAX;
    if (next == first) {
        edge_kvm_bhyve_arm64_coalesced_unlock(backend_vm);
        return 0;
    }
    ring->entries[last].physical_address = address;
    ring->entries[last].length = length;
    ring->entries[last].pio = 0;
    memcpy(ring->entries[last].data, &value, length);
    __atomic_store_n(&ring->last, next, __ATOMIC_RELEASE);
    edge_kvm_bhyve_arm64_coalesced_unlock(backend_vm);
    return 1;
}

static int
edge_kvm_bhyve_arm64_ioeventfd_key_matches(
    const edge_kvm_ioeventfd_registration_t *left,
    const edge_kvm_ioeventfd_registration_t *right)
{
    uint32_t key_flags = EDGE_KVM_IOEVENTFD_FLAG_DATAMATCH |
        EDGE_KVM_IOEVENTFD_FLAG_PIO;

    return left->address == right->address &&
        left->length == right->length &&
        (left->flags & key_flags) == (right->flags & key_flags) &&
        ((left->flags & EDGE_KVM_IOEVENTFD_FLAG_DATAMATCH) == 0 ||
         left->datamatch == right->datamatch);
}

static int
edge_kvm_bhyve_arm64_vm_ioeventfd(void *context, uint64_t cookie,
    const edge_kvm_ioeventfd_registration_t *event)
{
    edge_kvm_bhyve_arm64_vm_t *backend_vm =
        (edge_kvm_bhyve_arm64_vm_t *)(uintptr_t)cookie;
    edge_kvm_bhyve_arm64_ioeventfd_t *free_entry = NULL;

    (void)context;
    if (!backend_vm || !event)
        return -EDGE_LINUX_EINVAL;
    if ((event->flags & EDGE_KVM_IOEVENTFD_FLAG_PIO) != 0)
        return -EDGE_LINUX_EOPNOTSUPP;
    for (uint32_t index = 0;
         index < EDGE_KVM_BHYVE_ARM64_MAX_IOEVENTFDS; ++index) {
        edge_kvm_bhyve_arm64_ioeventfd_t *entry =
            &backend_vm->ioeventfds[index];

        if (!entry->active) {
            if (!free_entry)
                free_entry = entry;
            continue;
        }
        if (!edge_kvm_bhyve_arm64_ioeventfd_key_matches(
                &entry->registration, event))
            continue;
        if ((event->flags & EDGE_KVM_IOEVENTFD_FLAG_DEASSIGN) == 0)
            return -EDGE_LINUX_EEXIST;
        kernel_eventfd_release(entry->registration.event_id);
        memset(entry, 0, sizeof(*entry));
        return 0;
    }
    if ((event->flags & EDGE_KVM_IOEVENTFD_FLAG_DEASSIGN) != 0)
        return -EDGE_LINUX_ENOENT;
    if (!free_entry)
        return -EDGE_LINUX_ENOSPC;
    free_entry->registration = *event;
    free_entry->active = 1u;
    return 0;
}

static void
edge_kvm_bhyve_arm64_irqfd_notify(void *context, int event_id)
{
    edge_kvm_bhyve_arm64_irqfd_t *irqfd = context;
    uint64_t value;

    if (!irqfd || !irqfd->active ||
        irqfd->registration.event_id != event_id ||
        kernel_eventfd_consume_value(event_id, &value) < 0)
        return;
    if (vm_assert_irq(irqfd->vm->vm, irqfd->registration.gsi) == 0)
        (void)vm_deassert_irq(irqfd->vm->vm, irqfd->registration.gsi);
}

static int
edge_kvm_bhyve_arm64_vm_irqfd(void *context, uint64_t cookie,
    const edge_kvm_irqfd_registration_t *registration)
{
    edge_kvm_bhyve_arm64_vm_t *backend_vm =
        (edge_kvm_bhyve_arm64_vm_t *)(uintptr_t)cookie;
    edge_kvm_bhyve_arm64_irqfd_t *free_irqfd = NULL;
    int error;

    (void)context;
    if (!backend_vm || !registration)
        return -EDGE_LINUX_EINVAL;
    if ((registration->flags & EDGE_KVM_IRQFD_FLAG_RESAMPLE) != 0)
        return -EDGE_LINUX_EOPNOTSUPP;
    for (uint32_t index = 0;
         index < EDGE_KVM_BHYVE_ARM64_MAX_IRQFDS; ++index) {
        edge_kvm_bhyve_arm64_irqfd_t *irqfd =
            &backend_vm->irqfds[index];

        if (!irqfd->active) {
            if (!free_irqfd)
                free_irqfd = irqfd;
            continue;
        }
        if (irqfd->registration.event_id != registration->event_id ||
            irqfd->registration.gsi != registration->gsi)
            continue;
        if ((registration->flags & EDGE_KVM_IRQFD_FLAG_DEASSIGN) == 0)
            return -EDGE_LINUX_EEXIST;
        edge_kvm_bhyve_arm64_irqfd_release(irqfd);
        return 0;
    }
    if ((registration->flags & EDGE_KVM_IRQFD_FLAG_DEASSIGN) != 0)
        return -EDGE_LINUX_ENOENT;
    if (!free_irqfd)
        return -EDGE_LINUX_ENOSPC;
    free_irqfd->registration = *registration;
    free_irqfd->vm = backend_vm;
    free_irqfd->active = 1u;
    error = kernel_eventfd_observer_register(
        registration->event_id, edge_kvm_bhyve_arm64_irqfd_notify,
        free_irqfd);
    if (error < 0) {
        memset(free_irqfd, 0, sizeof(*free_irqfd));
        return error;
    }
    return 0;
}

static int
edge_kvm_bhyve_arm64_preferred_target(void *context, uint64_t cookie,
    edge_kvm_vcpu_init_t *init)
{
    (void)context;
    if (!cookie || !init)
        return -EDGE_LINUX_EINVAL;
    memset(init, 0, sizeof(*init));
    init->target = EDGE_KVM_ARM64_TARGET_GENERIC_V8;
    return 0;
}

static int
edge_kvm_bhyve_arm64_vcpu_create(void *context, uint64_t vm_cookie,
    uint32_t vcpu_id, uint64_t *cookie)
{
    edge_kvm_bhyve_arm64_vm_t *backend_vm =
        (edge_kvm_bhyve_arm64_vm_t *)(uintptr_t)vm_cookie;
    edge_kvm_bhyve_arm64_vcpu_t *backend_vcpu;
    struct vcpu *vcpu;
    int error;

    (void)context;
    if (!backend_vm || !cookie || vcpu_id >= vm_maxcpu)
        return -EDGE_LINUX_EINVAL;
    vcpu = vm_alloc_vcpu(backend_vm->vm, (int)vcpu_id);
    if (!vcpu)
        return -EDGE_LINUX_ENOMEM;
    error = vm_activate_cpu(vcpu);
    if (error != 0)
        return edge_kvm_bhyve_arm64_error(error);
    backend_vcpu = bsd_kmalloc(sizeof(*backend_vcpu),
        BSD_M_WAITOK | BSD_M_ZERO);
    if (!backend_vcpu)
        return -EDGE_LINUX_ENOMEM;
    backend_vcpu->vcpu = vcpu;
    backend_vcpu->vm = backend_vm;
    backend_vcpu->runtime_thread.td_pcb =
        (struct pcb *)(void *)backend_vcpu->runtime_thread.td_pcb_storage;
    for (uint32_t page = 0; page < EDGE_KVM_VCPU_MMAP_PAGES; ++page) {
        if (page == EDGE_KVM_ARM64_COALESCED_MMIO_PAGE_OFFSET) {
            backend_vcpu->run_pages[page] =
                backend_vm->coalesced_mmio_page;
            continue;
        }
        backend_vcpu->run_pages[page] = arch_vm_alloc_page();
        if (!backend_vcpu->run_pages[page]) {
            for (uint32_t rollback = 0; rollback < page; ++rollback) {
                if (rollback != EDGE_KVM_ARM64_COALESCED_MMIO_PAGE_OFFSET)
                    arch_vm_free_page(backend_vcpu->run_pages[rollback]);
            }
            bsd_kfree(backend_vcpu);
            return -EDGE_LINUX_ENOMEM;
        }
        memset(backend_vcpu->run_pages[page], 0, EDGE_KVM_PAGE_SIZE);
    }
    backend_vm->vcpus[vcpu_id] = backend_vcpu;
    if (g_bhyve_arm64_trace)
        bsd_printf("edge-kvm-arm64: vcpu %u created\n", vcpu_id);
    *cookie = (uint64_t)(uintptr_t)backend_vcpu;
    return 0;
}

static void
edge_kvm_bhyve_arm64_vcpu_destroy(void *context, uint64_t cookie)
{
    edge_kvm_bhyve_arm64_vcpu_t *backend_vcpu =
        (edge_kvm_bhyve_arm64_vcpu_t *)(uintptr_t)cookie;

    (void)context;
    if (!backend_vcpu)
        return;
    if (backend_vcpu->vm && backend_vcpu->vcpu) {
        uint32_t vcpu_id = (uint32_t)vcpu_vcpuid(backend_vcpu->vcpu);
        if (vcpu_id < VM_MAXCPU &&
            backend_vcpu->vm->vcpus[vcpu_id] == backend_vcpu)
            backend_vcpu->vm->vcpus[vcpu_id] = NULL;
    }
    for (uint32_t page = 0; page < EDGE_KVM_VCPU_MMAP_PAGES; ++page) {
        if (page != EDGE_KVM_ARM64_COALESCED_MMIO_PAGE_OFFSET &&
            backend_vcpu->run_pages[page])
            arch_vm_free_page(backend_vcpu->run_pages[page]);
    }
    bsd_kfree(backend_vcpu);
}

static int
edge_kvm_bhyve_arm64_vcpu_init(void *context, uint64_t cookie,
    const edge_kvm_vcpu_init_t *init)
{
    edge_kvm_bhyve_arm64_vcpu_t *backend_vcpu =
        (edge_kvm_bhyve_arm64_vcpu_t *)(uintptr_t)cookie;

    (void)context;
    if (!backend_vcpu || !init ||
        init->target != EDGE_KVM_ARM64_TARGET_GENERIC_V8 ||
        (init->features[0] & ~EDGE_KVM_ARM64_SUPPORTED_FEATURES) != 0)
        return -EDGE_LINUX_EINVAL;
    for (uint32_t index = 1; index < 7; ++index) {
        if (init->features[index] != 0)
            return -EDGE_LINUX_EINVAL;
    }
    if (backend_vcpu->initialized) {
        struct hypctx *hypctx = vcpu_get_cookie(backend_vcpu->vcpu);

        reset_vm_el01_regs(hypctx);
        reset_vm_el2_regs(hypctx);
        fpu_save_area_reset(backend_vcpu->vcpu->guestfpu);
        memset(backend_vcpu->auxiliary_spsr, 0,
            sizeof(backend_vcpu->auxiliary_spsr));
        backend_vcpu->pending_mmio_read = 0;
    }
    backend_vcpu->init = *init;
    backend_vcpu->powered_off =
        (init->features[0] &
         EDGE_KVM_ARM_VCPU_FEATURE(EDGE_KVM_ARM_VCPU_POWER_OFF)) != 0;
    backend_vcpu->initialized = 1;
    if (g_bhyve_arm64_trace)
        bsd_printf("edge-kvm-arm64: vcpu initialized features=0x%lx\n",
            init->features[0]);
    return 0;
}

static int
edge_kvm_bhyve_arm64_core_register(uint64_t id, enum vm_reg_name *reg)
{
    for (uint32_t index = 0; index < 30; ++index) {
        if (id == EDGE_KVM_REG_ARM64_X(index)) {
            *reg = (enum vm_reg_name)(VM_REG_GUEST_X0 + index);
            return 1;
        }
    }
    if (id == EDGE_KVM_REG_ARM64_LR)
        *reg = VM_REG_GUEST_LR;
    else if (id == EDGE_KVM_REG_ARM64_SP_EL1)
        *reg = VM_REG_GUEST_SP;
    else if (id == EDGE_KVM_REG_ARM64_PC)
        *reg = VM_REG_GUEST_PC;
    else if (id == EDGE_KVM_REG_ARM64_PSTATE)
        *reg = VM_REG_GUEST_CPSR;
    else if (id == EDGE_KVM_REG_ARM64_MPIDR_EL1)
        *reg = VM_REG_GUEST_MPIDR_EL1;
    else if (id == EDGE_KVM_REG_ARM64_SCTLR_EL1)
        *reg = VM_REG_GUEST_SCTLR_EL1;
    else if (id == EDGE_KVM_REG_ARM64_TTBR0_EL1)
        *reg = VM_REG_GUEST_TTBR0_EL1;
    else if (id == EDGE_KVM_REG_ARM64_TTBR1_EL1)
        *reg = VM_REG_GUEST_TTBR1_EL1;
    else if (id == EDGE_KVM_REG_ARM64_TCR_EL1)
        *reg = VM_REG_GUEST_TCR_EL1;
    else
        return 0;
    return 1;
}

static uint64_t *
edge_kvm_bhyve_arm64_extended_register(
    edge_kvm_bhyve_arm64_vcpu_t *backend_vcpu, uint64_t id)
{
    struct hypctx *hypctx = vcpu_get_cookie(backend_vcpu->vcpu);

    if (id == EDGE_KVM_REG_ARM64_SP)
        return hypctx_sys_reg(hypctx, SP_EL0);
    if (id == EDGE_KVM_REG_ARM64_ELR_EL1)
        return hypctx_sys_reg(hypctx, ELR_EL1);
    if (id == EDGE_KVM_REG_ARM64_SPSR(0))
        return hypctx_sys_reg(hypctx, SPSR_EL1);
    for (uint32_t index = 1; index < 5; ++index) {
        if (id == EDGE_KVM_REG_ARM64_SPSR(index))
            return &backend_vcpu->auxiliary_spsr[index - 1u];
    }
    return 0;
}

static int
edge_kvm_bhyve_arm64_id_register(uint64_t id, uint64_t *value)
{
#define EDGE_ARM64_ID_CASE(name) \
    case EDGE_KVM_REG_ARM64_SYSREG_ID(name##_op0, name##_op1, \
        name##_CRn, name##_CRm, name##_op2): \
        get_kernel_reg_iss(name##_ISS, value); \
        return 1
    switch (id) {
    EDGE_ARM64_ID_CASE(ID_AA64AFR0_EL1);
    EDGE_ARM64_ID_CASE(ID_AA64AFR1_EL1);
    EDGE_ARM64_ID_CASE(ID_AA64DFR0_EL1);
    EDGE_ARM64_ID_CASE(ID_AA64DFR1_EL1);
    EDGE_ARM64_ID_CASE(ID_AA64ISAR0_EL1);
    EDGE_ARM64_ID_CASE(ID_AA64ISAR1_EL1);
    EDGE_ARM64_ID_CASE(ID_AA64ISAR2_EL1);
    EDGE_ARM64_ID_CASE(ID_AA64MMFR0_EL1);
    EDGE_ARM64_ID_CASE(ID_AA64MMFR1_EL1);
    EDGE_ARM64_ID_CASE(ID_AA64MMFR2_EL1);
    EDGE_ARM64_ID_CASE(ID_AA64PFR0_EL1);
    EDGE_ARM64_ID_CASE(ID_AA64PFR1_EL1);
    default:
        return 0;
    }
#undef EDGE_ARM64_ID_CASE
}

static int
edge_kvm_bhyve_arm64_one_reg(void *context, uint64_t cookie, uint64_t id,
    void *value, uint32_t size, int write)
{
    edge_kvm_bhyve_arm64_vcpu_t *backend_vcpu =
        (edge_kvm_bhyve_arm64_vcpu_t *)(uintptr_t)cookie;
    enum vm_reg_name reg;
    uint64_t *extended;
    uint64_t scalar;
    int error;

    (void)context;
    if (!backend_vcpu || !value || size != edge_kvm_register_size(id))
        return -EDGE_LINUX_EINVAL;
    if (edge_kvm_bhyve_arm64_core_register(id, &reg)) {
        if (size != sizeof(scalar))
            return -EDGE_LINUX_EINVAL;
        if (write) {
            memcpy(&scalar, value, sizeof(scalar));
            error = vm_set_register(backend_vcpu->vcpu, reg, scalar);
        } else {
            error = vm_get_register(backend_vcpu->vcpu, reg, &scalar);
            if (error == 0)
                memcpy(value, &scalar, sizeof(scalar));
        }
        return edge_kvm_bhyve_arm64_error(error);
    }
    extended = edge_kvm_bhyve_arm64_extended_register(backend_vcpu, id);
    if (extended) {
        if (size != sizeof(*extended))
            return -EDGE_LINUX_EINVAL;
        if (write)
            memcpy(extended, value, sizeof(*extended));
        else
            memcpy(value, extended, sizeof(*extended));
        return 0;
    }
    for (uint32_t index = 0; index < 32; ++index) {
        if (id != EDGE_KVM_REG_ARM64_V(index))
            continue;
        if (size != sizeof(backend_vcpu->vcpu->guestfpu->vfp_regs[index]))
            return -EDGE_LINUX_EINVAL;
        if (write)
            memcpy(&backend_vcpu->vcpu->guestfpu->vfp_regs[index], value,
                size);
        else
            memcpy(value, &backend_vcpu->vcpu->guestfpu->vfp_regs[index],
                size);
        return 0;
    }
    if (id == EDGE_KVM_REG_ARM64_FPSR && size == sizeof(uint32_t)) {
        if (write)
            memcpy(&backend_vcpu->vcpu->guestfpu->vfp_fpsr, value, size);
        else
            memcpy(value, &backend_vcpu->vcpu->guestfpu->vfp_fpsr, size);
        return 0;
    }
    if (id == EDGE_KVM_REG_ARM64_FPCR && size == sizeof(uint32_t)) {
        if (write)
            memcpy(&backend_vcpu->vcpu->guestfpu->vfp_fpcr, value, size);
        else
            memcpy(value, &backend_vcpu->vcpu->guestfpu->vfp_fpcr, size);
        return 0;
    }
    if (size == sizeof(uint64_t) &&
        (id == EDGE_KVM_REG_ARM_PTIMER_CTL ||
         id == EDGE_KVM_REG_ARM_PTIMER_CVAL ||
         id == EDGE_KVM_REG_ARM_PTIMER_CNT)) {
        if (id == EDGE_KVM_REG_ARM_PTIMER_CTL)
            error = write ? vtimer_phys_ctl_write(backend_vcpu->vcpu,
                *(const uint64_t *)value, NULL) :
                vtimer_phys_ctl_read(backend_vcpu->vcpu, value, NULL);
        else if (id == EDGE_KVM_REG_ARM_PTIMER_CVAL)
            error = write ? vtimer_phys_cval_write(backend_vcpu->vcpu,
                *(const uint64_t *)value, NULL) :
                vtimer_phys_cval_read(backend_vcpu->vcpu, value, NULL);
        else
            error = write ? vtimer_phys_cnt_write(backend_vcpu->vcpu,
                *(const uint64_t *)value, NULL) :
                vtimer_phys_cnt_read(backend_vcpu->vcpu, value, NULL);
        return edge_kvm_bhyve_arm64_error(error);
    }
    if (size == sizeof(uint64_t) &&
        (id == EDGE_KVM_REG_ARM_TIMER_CTL ||
         id == EDGE_KVM_REG_ARM_TIMER_CVAL ||
         id == EDGE_KVM_REG_ARM_TIMER_CNT)) {
        struct hypctx *hypctx = vcpu_get_cookie(backend_vcpu->vcpu);
        struct vtimer_timer *timer = &hypctx->vtimer_cpu.virt_timer;

        if (id == EDGE_KVM_REG_ARM_TIMER_CTL) {
            if (write)
                memcpy(&timer->cntx_ctl_el0, value, sizeof(uint64_t));
            else
                memcpy(value, &timer->cntx_ctl_el0, sizeof(uint64_t));
        } else if (id == EDGE_KVM_REG_ARM_TIMER_CVAL) {
            if (write)
                memcpy(&timer->cntx_cval_el0, value, sizeof(uint64_t));
            else
                memcpy(value, &timer->cntx_cval_el0, sizeof(uint64_t));
        } else if (write) {
            uint64_t offset;

            memcpy(&scalar, value, sizeof(scalar));
            offset = READ_SPECIALREG(cntpct_el0) - scalar;
            hypctx->hyp->cntvoff_el2 = offset;
            for (uint32_t index = 0; index < VM_MAXCPU; ++index) {
                edge_kvm_bhyve_arm64_vcpu_t *candidate =
                    backend_vcpu->vm->vcpus[index];

                if (candidate)
                    hypctx_write_sys_reg(vcpu_get_cookie(candidate->vcpu),
                        HOST_CNTVOFF_EL2, offset);
            }
        } else {
            scalar = READ_SPECIALREG(cntpct_el0) -
                hypctx_read_sys_reg(hypctx, HOST_CNTVOFF_EL2);
            memcpy(value, &scalar, sizeof(scalar));
        }
        return 0;
    }
    if (!write &&
        (id & UINT64_C(0x000000000fff0000)) ==
            EDGE_KVM_REG_ARM64_SYSREG &&
        ((id >> 7) & UINT64_C(0xf)) == 0 &&
        (size == sizeof(uint32_t) || size == sizeof(uint64_t))) {
        scalar = 0;
        if (size == sizeof(uint64_t)) {
            (void)edge_kvm_bhyve_arm64_id_register(id, &scalar);
            if (id == EDGE_KVM_REG_ARM64_SYSREG_ID(
                    ID_AA64ISAR1_EL1_op0, ID_AA64ISAR1_EL1_op1,
                    ID_AA64ISAR1_EL1_CRn, ID_AA64ISAR1_EL1_CRm,
                    ID_AA64ISAR1_EL1_op2)) {
                scalar &= ~(ID_AA64ISAR1_APA_MASK |
                    ID_AA64ISAR1_API_MASK | ID_AA64ISAR1_GPA_MASK |
                    ID_AA64ISAR1_GPI_MASK);
            } else if (id == EDGE_KVM_REG_ARM64_SYSREG_ID(
                    ID_AA64ISAR2_EL1_op0, ID_AA64ISAR2_EL1_op1,
                    ID_AA64ISAR2_EL1_CRn, ID_AA64ISAR2_EL1_CRm,
                    ID_AA64ISAR2_EL1_op2)) {
                scalar &= ~(ID_AA64ISAR2_APA3_MASK |
                    ID_AA64ISAR2_GPA3_MASK);
            }
        }
        memcpy(value, &scalar, size);
        return 0;
    }
    if (id == EDGE_KVM_REG_ARM_PSCI_VERSION && size == sizeof(uint64_t)) {
        scalar = PSCI_VER(1, 0);
        if (write) {
            uint64_t requested;

            memcpy(&requested, value, sizeof(requested));
            if (requested < PSCI_VER(0, 2) || requested > scalar)
                return -EDGE_LINUX_EINVAL;
        } else {
            memcpy(value, &scalar, sizeof(scalar));
        }
        return 0;
    }
    return -EDGE_LINUX_ENOENT;
}

static int
edge_kvm_bhyve_arm64_get_one_reg(void *context, uint64_t cookie,
    uint64_t id, void *value, uint32_t size)
{
    return edge_kvm_bhyve_arm64_one_reg(
        context, cookie, id, value, size, 0);
}

static int
edge_kvm_bhyve_arm64_set_one_reg(void *context, uint64_t cookie,
    uint64_t id, const void *value, uint32_t size)
{
    return edge_kvm_bhyve_arm64_one_reg(
        context, cookie, id, (void *)(uintptr_t)value, size, 1);
}

static void
edge_kvm_bhyve_arm64_append_register(uint64_t *ids, uint32_t capacity,
    uint32_t *count, uint64_t id)
{
    if (*count < capacity)
        ids[*count] = id;
    ++*count;
}

static int
edge_kvm_bhyve_arm64_get_reg_list(void *context, uint64_t cookie,
    uint64_t *ids, uint32_t capacity, uint32_t *count)
{
    (void)context;
    if (!cookie || !count || (capacity != 0 && !ids))
        return -EDGE_LINUX_EINVAL;
    *count = 0;
    for (uint32_t index = 0; index < 31; ++index)
        edge_kvm_bhyve_arm64_append_register(
            ids, capacity, count, EDGE_KVM_REG_ARM64_X(index));
    edge_kvm_bhyve_arm64_append_register(
        ids, capacity, count, EDGE_KVM_REG_ARM64_SP);
    edge_kvm_bhyve_arm64_append_register(
        ids, capacity, count, EDGE_KVM_REG_ARM64_PC);
    edge_kvm_bhyve_arm64_append_register(
        ids, capacity, count, EDGE_KVM_REG_ARM64_PSTATE);
    edge_kvm_bhyve_arm64_append_register(
        ids, capacity, count, EDGE_KVM_REG_ARM64_SP_EL1);
    edge_kvm_bhyve_arm64_append_register(
        ids, capacity, count, EDGE_KVM_REG_ARM64_ELR_EL1);
    for (uint32_t index = 0; index < 5; ++index)
        edge_kvm_bhyve_arm64_append_register(
            ids, capacity, count, EDGE_KVM_REG_ARM64_SPSR(index));
    for (uint32_t index = 0; index < 32; ++index)
        edge_kvm_bhyve_arm64_append_register(
            ids, capacity, count, EDGE_KVM_REG_ARM64_V(index));
    edge_kvm_bhyve_arm64_append_register(
        ids, capacity, count, EDGE_KVM_REG_ARM64_FPSR);
    edge_kvm_bhyve_arm64_append_register(
        ids, capacity, count, EDGE_KVM_REG_ARM64_FPCR);
    edge_kvm_bhyve_arm64_append_register(
        ids, capacity, count, EDGE_KVM_REG_ARM64_MPIDR_EL1);
    edge_kvm_bhyve_arm64_append_register(
        ids, capacity, count, EDGE_KVM_REG_ARM64_SCTLR_EL1);
    edge_kvm_bhyve_arm64_append_register(
        ids, capacity, count, EDGE_KVM_REG_ARM64_TTBR0_EL1);
    edge_kvm_bhyve_arm64_append_register(
        ids, capacity, count, EDGE_KVM_REG_ARM64_TTBR1_EL1);
    edge_kvm_bhyve_arm64_append_register(
        ids, capacity, count, EDGE_KVM_REG_ARM64_TCR_EL1);
    edge_kvm_bhyve_arm64_append_register(
        ids, capacity, count, EDGE_KVM_REG_ARM_PTIMER_CTL);
    edge_kvm_bhyve_arm64_append_register(
        ids, capacity, count, EDGE_KVM_REG_ARM_PTIMER_CVAL);
    edge_kvm_bhyve_arm64_append_register(
        ids, capacity, count, EDGE_KVM_REG_ARM_PTIMER_CNT);
    edge_kvm_bhyve_arm64_append_register(
        ids, capacity, count, EDGE_KVM_REG_ARM_TIMER_CTL);
    edge_kvm_bhyve_arm64_append_register(
        ids, capacity, count, EDGE_KVM_REG_ARM_TIMER_CVAL);
    edge_kvm_bhyve_arm64_append_register(
        ids, capacity, count, EDGE_KVM_REG_ARM_TIMER_CNT);
    return 0;
}

static int
edge_kvm_bhyve_arm64_complete_mmio(
    edge_kvm_bhyve_arm64_vcpu_t *backend_vcpu, edge_kvm_run_t *run)
{
    uint64_t value = 0;
    uint32_t bits;

    if (!backend_vcpu->pending_mmio_read)
        return 0;
    memcpy(&value, run->exit.mmio.data, backend_vcpu->pending_mmio_size);
    bits = backend_vcpu->pending_mmio_size * 8u;
    if (backend_vcpu->pending_mmio_sign_extend && bits < 64u &&
        (value & (UINT64_C(1) << (bits - 1u))) != 0)
        value |= UINT64_MAX << bits;
    backend_vcpu->pending_mmio_read = 0;
    return edge_kvm_bhyve_arm64_error(vm_set_register(
        backend_vcpu->vcpu, backend_vcpu->pending_mmio_register, value));
}

static uint64_t
edge_kvm_bhyve_arm64_affinity_info(edge_kvm_bhyve_arm64_vm_t *backend_vm,
    uint64_t target, uint32_t level)
{
    static const uint64_t masks[] = {
        UINT64_C(0xff), UINT64_C(0xffff), UINT64_C(0xffffff),
        UINT64_C(0xff00000000) | UINT64_C(0xffffff),
    };

    if (!backend_vm || level >= sizeof(masks) / sizeof(masks[0]))
        return (uint64_t)(int64_t)PSCI_RETVAL_INVALID_PARAMS;
    for (uint32_t index = 0; index < VM_MAXCPU; ++index) {
        edge_kvm_bhyve_arm64_vcpu_t *candidate = backend_vm->vcpus[index];
        uint64_t mpidr;

        if (!candidate || !candidate->initialized ||
            __atomic_load_n(&candidate->powered_off, __ATOMIC_ACQUIRE))
            continue;
        if (vm_get_register(candidate->vcpu, VM_REG_GUEST_MPIDR_EL1,
            &mpidr) == 0 && (mpidr & masks[level]) ==
            (target & masks[level]))
            return PSCI_AFFINITY_INFO_ON;
    }
    return PSCI_AFFINITY_INFO_OFF;
}

static int
edge_kvm_bhyve_arm64_smccc(edge_kvm_bhyve_arm64_vcpu_t *backend_vcpu,
    const struct vm_exit *vm_exit)
{
    edge_kvm_bhyve_arm64_vm_t *backend_vm = backend_vcpu->vm;
    uint64_t result = (uint64_t)(int64_t)PSCI_RETVAL_NOT_SUPPORTED;
    int error = 0;

    switch (vm_exit->u.smccc_call.func_id) {
    case PSCI_FNID_VERSION:
        result = PSCI_VER(1, 0);
        break;
    case PSCI_FNID_FEATURES:
        switch ((uint32_t)vm_exit->u.smccc_call.args[0]) {
        case PSCI_FNID_VERSION:
        case PSCI_FNID_CPU_SUSPEND:
        case PSCI_FNID_CPU_OFF:
        case PSCI_FNID_CPU_ON:
        case PSCI_FNID_AFFINITY_INFO:
        case PSCI_FNID_SYSTEM_OFF:
        case PSCI_FNID_SYSTEM_RESET:
        case PSCI_FNID_FEATURES:
            result = PSCI_RETVAL_SUCCESS;
            break;
        default:
            break;
        }
        break;
    case PSCI_FNID_CPU_SUSPEND:
        break;
    case PSCI_FNID_CPU_OFF:
        __atomic_store_n(&backend_vcpu->powered_off, 1u,
            __ATOMIC_RELEASE);
        result = PSCI_RETVAL_SUCCESS;
        break;
    case PSCI_FNID_CPU_ON: {
        edge_kvm_bhyve_arm64_vcpu_t *target_vcpu = NULL;
        uint64_t target_mpidr = vm_exit->u.smccc_call.args[0];

        for (uint32_t index = 0; index < VM_MAXCPU; ++index) {
            edge_kvm_bhyve_arm64_vcpu_t *candidate =
                backend_vm->vcpus[index];
            uint64_t candidate_mpidr;

            if (candidate && candidate->initialized &&
                vm_get_register(candidate->vcpu, VM_REG_GUEST_MPIDR_EL1,
                    &candidate_mpidr) == 0 &&
                candidate_mpidr == target_mpidr) {
                target_vcpu = candidate;
                break;
            }
        }
        if (!target_vcpu) {
            result = (uint64_t)(int64_t)PSCI_RETVAL_INVALID_PARAMS;
            break;
        }
        if (!__atomic_load_n(&target_vcpu->powered_off,
            __ATOMIC_ACQUIRE)) {
            result = (uint64_t)(int64_t)PSCI_RETVAL_ALREADY_ON;
            break;
        }
        error = vm_set_register(target_vcpu->vcpu, VM_REG_GUEST_X0,
            vm_exit->u.smccc_call.args[2]);
        if (error == 0)
            error = vm_set_register(target_vcpu->vcpu, VM_REG_GUEST_PC,
                vm_exit->u.smccc_call.args[1]);
        if (error != 0)
            return edge_kvm_bhyve_arm64_error(error);
        __atomic_store_n(&target_vcpu->powered_off, 0u,
            __ATOMIC_RELEASE);
        bsd_wakeup(&target_vcpu->powered_off);
        result = PSCI_RETVAL_SUCCESS;
        break;
    }
    case PSCI_FNID_AFFINITY_INFO:
        result = edge_kvm_bhyve_arm64_affinity_info(backend_vm,
            vm_exit->u.smccc_call.args[0],
            (uint32_t)vm_exit->u.smccc_call.args[1]);
        break;
    case PSCI_FNID_SYSTEM_OFF:
        error = vm_suspend(backend_vm->vm, VM_SUSPEND_POWEROFF);
        if (error != 0 && error != EALREADY)
            return edge_kvm_bhyve_arm64_error(error);
        result = PSCI_RETVAL_SUCCESS;
        break;
    case PSCI_FNID_SYSTEM_RESET:
        error = vm_suspend(backend_vm->vm, VM_SUSPEND_RESET);
        if (error != 0 && error != EALREADY)
            return edge_kvm_bhyve_arm64_error(error);
        result = PSCI_RETVAL_SUCCESS;
        break;
    default:
        break;
    }
    return edge_kvm_bhyve_arm64_error(vm_set_register(
        backend_vcpu->vcpu, VM_REG_GUEST_X0, result));
}

static int
edge_kvm_bhyve_arm64_signal_mmioeventfd(
    edge_kvm_bhyve_arm64_vcpu_t *backend_vcpu, uint64_t address,
    uint32_t length, uint64_t value)
{
    edge_kvm_bhyve_arm64_vm_t *backend_vm = backend_vcpu->vm;
    uint64_t mask = length == 8 ? UINT64_MAX :
        ((UINT64_C(1) << (length * 8u)) - 1u);

    for (uint32_t index = 0;
         index < EDGE_KVM_BHYVE_ARM64_MAX_IOEVENTFDS; ++index) {
        const edge_kvm_bhyve_arm64_ioeventfd_t *entry =
            &backend_vm->ioeventfds[index];
        const edge_kvm_ioeventfd_registration_t *registration =
            &entry->registration;
        int64_t result;

        if (!entry->active ||
            (registration->flags & EDGE_KVM_IOEVENTFD_FLAG_PIO) != 0 ||
            registration->address != address ||
            (registration->length != 0 &&
             registration->length != length) ||
            ((registration->flags & EDGE_KVM_IOEVENTFD_FLAG_DATAMATCH) != 0 &&
             (registration->datamatch & mask) != (value & mask)))
            continue;
        result = kernel_eventfd_write_value(
            registration->event_id, 1, 1u);
        return result < 0 ? (int)result : 1;
    }
    return 0;
}

static int
edge_kvm_bhyve_arm64_vcpu_run(void *context, uint64_t cookie,
    edge_kvm_run_t *run)
{
    edge_kvm_bhyve_arm64_vcpu_t *backend_vcpu =
        (edge_kvm_bhyve_arm64_vcpu_t *)(uintptr_t)cookie;
    struct vm_exit *vm_exit;
    struct thread *previous_thread;
    uint64_t host_daif;
    uint64_t value;
    int error;

    (void)context;
    if (!backend_vcpu || !run)
        return -EDGE_LINUX_EINVAL;
    if (!backend_vcpu->initialized)
        return -EDGE_LINUX_ENOEXEC;
    if (g_bhyve_arm64_trace && backend_vcpu->trace_run_count++ == 0)
        bsd_printf("edge-kvm-arm64: first KVM_RUN\n");
    if (backend_vcpu->system_event_pending) {
        memset(&run->exit, 0, sizeof(run->exit));
        run->exit_reason = EDGE_KVM_EXIT_SYSTEM_EVENT;
        run->exit.system_event.type = backend_vcpu->system_event_type;
        return 0;
    }
run_again:
    while (__atomic_load_n(&backend_vcpu->powered_off, __ATOMIC_ACQUIRE)) {
        if (run->immediate_exit)
            return -EDGE_LINUX_EINTR;
        (void)bsd_msleep(&backend_vcpu->powered_off, NULL, 0,
            "kvmoff", 1);
    }
    if (run->immediate_exit)
        return -EDGE_LINUX_EINTR;
    error = edge_kvm_bhyve_arm64_complete_mmio(backend_vcpu, run);
    if (error < 0)
        return error;
    memset(&run->exit, 0, sizeof(run->exit));
    run->exit_reason = EDGE_KVM_EXIT_UNKNOWN;
    error = vcpu_set_state(backend_vcpu->vcpu, VCPU_FROZEN, true);
    if (error != 0)
        return edge_kvm_bhyve_arm64_error(error);
enter_guest_again:
    if (run->immediate_exit) {
        (void)vcpu_set_state(backend_vcpu->vcpu, VCPU_IDLE, false);
        return -EDGE_LINUX_EINTR;
    }
    bsd_kthread_pump();
    previous_thread = bsd_kthread_public_context_enter(
        &backend_vcpu->runtime_thread);
    __asm__ __volatile__(
        "mrs %0, daif\n"
        "msr daifclr, #2"
        : "=r"(host_daif) : : "memory");
    error = vm_run(backend_vcpu->vcpu);
    __asm__ __volatile__("msr daif, %0" : : "r"(host_daif) : "memory");
    vfp_enable();
    vfp_restore(backend_vcpu->runtime_thread.td_pcb->pcb_fpusaved);
    bsd_kthread_public_context_leave(previous_thread);
    if (error != 0) {
        (void)vcpu_set_state(backend_vcpu->vcpu, VCPU_IDLE, false);
        return edge_kvm_bhyve_arm64_error(error);
    }
    vm_exit = vm_exitinfo(backend_vcpu->vcpu);
    if (g_bhyve_arm64_trace && backend_vcpu->trace_exit_count < 16u) {
        bsd_printf("edge-kvm-arm64: vm exit code=%d exception=%u\n",
            vm_exit->exitcode, vm_exit->u.hyp.exception_nr);
        backend_vcpu->trace_exit_count++;
    }
    switch (vm_exit->exitcode) {
    case VM_EXITCODE_BOGUS:
        if (vm_exit->u.hyp.exception_nr == EXCP_TYPE_EL1_IRQ ||
            vm_exit->u.hyp.exception_nr == EXCP_TYPE_EL1_FIQ)
            goto enter_guest_again;
        error = vcpu_set_state(backend_vcpu->vcpu, VCPU_IDLE, false);
        if (error == 0)
            return -EDGE_LINUX_EIO;
        break;
    case VM_EXITCODE_INST_EMUL:
        run->exit_reason = EDGE_KVM_EXIT_MMIO;
        run->exit.mmio.physical_address = vm_exit->u.inst_emul.gpa;
        run->exit.mmio.length = vm_exit->u.inst_emul.vie.access_size;
        run->exit.mmio.is_write =
            vm_exit->u.inst_emul.vie.dir == VM_DIR_WRITE;
        if (run->exit.mmio.is_write) {
            error = vm_get_register(backend_vcpu->vcpu,
                vm_exit->u.inst_emul.vie.reg, &value);
            if (error == 0) {
                memcpy(run->exit.mmio.data, &value,
                    run->exit.mmio.length);
                error = edge_kvm_bhyve_arm64_signal_mmioeventfd(
                    backend_vcpu, run->exit.mmio.physical_address,
                    run->exit.mmio.length, value);
                if (error != 0) {
                    int state_error = vcpu_set_state(
                        backend_vcpu->vcpu, VCPU_IDLE, false);

                    if (error < 0)
                        return error;
                    if (state_error != 0)
                        return edge_kvm_bhyve_arm64_error(state_error);
                    goto run_again;
                }
                if (edge_kvm_bhyve_arm64_coalesced_mmio_write(
                        backend_vcpu->vm,
                        run->exit.mmio.physical_address,
                        value, run->exit.mmio.length) > 0) {
                    int state_error = vcpu_set_state(
                        backend_vcpu->vcpu, VCPU_IDLE, false);

                    if (state_error != 0)
                        return edge_kvm_bhyve_arm64_error(state_error);
                    goto run_again;
                }
            }
        } else {
            backend_vcpu->pending_mmio_read = 1;
            backend_vcpu->pending_mmio_size = run->exit.mmio.length;
            backend_vcpu->pending_mmio_sign_extend =
                vm_exit->u.inst_emul.vie.sign_extend;
            backend_vcpu->pending_mmio_register =
                vm_exit->u.inst_emul.vie.reg;
        }
        break;
    case VM_EXITCODE_WFI:
        run->exit_reason = EDGE_KVM_EXIT_HLT;
        break;
    case VM_EXITCODE_SUSPENDED:
        run->exit_reason = EDGE_KVM_EXIT_SYSTEM_EVENT;
        run->exit.system_event.type =
            vm_exit->u.suspended.how == VM_SUSPEND_RESET ?
            EDGE_KVM_SYSTEM_EVENT_RESET : EDGE_KVM_SYSTEM_EVENT_SHUTDOWN;
        break;
    case VM_EXITCODE_SMCCC:
        error = edge_kvm_bhyve_arm64_smccc(backend_vcpu, vm_exit);
        if (error == 0 &&
            (vm_exit->u.smccc_call.func_id == PSCI_FNID_SYSTEM_OFF ||
             vm_exit->u.smccc_call.func_id == PSCI_FNID_SYSTEM_RESET)) {
            run->exit_reason = EDGE_KVM_EXIT_SYSTEM_EVENT;
            run->exit.system_event.type =
                vm_exit->u.smccc_call.func_id == PSCI_FNID_SYSTEM_RESET ?
                EDGE_KVM_SYSTEM_EVENT_RESET :
                EDGE_KVM_SYSTEM_EVENT_SHUTDOWN;
            backend_vcpu->system_event_type = run->exit.system_event.type;
            backend_vcpu->system_event_pending = 1u;
            break;
        }
        if (error == 0) {
            error = vcpu_set_state(backend_vcpu->vcpu, VCPU_IDLE, false);
            if (error == 0)
                goto run_again;
        }
        break;
    default:
        run->exit_reason = EDGE_KVM_EXIT_INTERNAL_ERROR;
        run->exit.internal.suberror = EDGE_KVM_INTERNAL_ERROR_EMULATION;
        run->exit.internal.data_count = 2;
        run->exit.internal.data[0] = (uint64_t)vm_exit->exitcode;
        run->exit.internal.data[1] = vm_exit->pc;
        break;
    }
    if (error == 0)
        error = vcpu_set_state(backend_vcpu->vcpu, VCPU_IDLE, false);
    return edge_kvm_bhyve_arm64_error(error);
}

static int
edge_kvm_bhyve_arm64_vcpu_mmap_page(void *context, uint64_t cookie,
    uint32_t page, uint64_t *physical_address)
{
    edge_kvm_bhyve_arm64_vcpu_t *backend_vcpu =
        (edge_kvm_bhyve_arm64_vcpu_t *)(uintptr_t)cookie;

    (void)context;
    if (!backend_vcpu || !physical_address ||
        page >= EDGE_KVM_VCPU_MMAP_PAGES)
        return -EDGE_LINUX_EINVAL;
    *physical_address =
        (uint64_t)(uintptr_t)backend_vcpu->run_pages[page];
    return 0;
}

static int
edge_kvm_bhyve_arm64_device_create(void *context, uint64_t vm_cookie,
    uint32_t type, uint32_t flags, uint64_t *cookie)
{
    edge_kvm_bhyve_arm64_vm_t *backend_vm =
        (edge_kvm_bhyve_arm64_vm_t *)(uintptr_t)vm_cookie;
    edge_kvm_bhyve_arm64_device_t *device;

    (void)context;
    if (!backend_vm || !cookie || type != EDGE_KVM_DEVICE_ARM_VGIC_V3 ||
        (flags != 0 && flags != EDGE_KVM_CREATE_DEVICE_TEST))
        return -EDGE_LINUX_EINVAL;
    if (flags == EDGE_KVM_CREATE_DEVICE_TEST) {
        *cookie = 0;
        return 0;
    }
    device = bsd_kmalloc(sizeof(*device), BSD_M_WAITOK | BSD_M_ZERO);
    if (!device)
        return -EDGE_LINUX_ENOMEM;
    device->vm = backend_vm;
    device->descriptor.ver.version = 3;
    device->descriptor.ver.flags = 0;
    device->descriptor.v3_regs.dist_size = UINT64_C(0x10000);
    device->descriptor.v3_regs.redist_size =
        (uint64_t)vm_maxcpu * UINT64_C(0x20000);
    device->interrupt_count = 256;
    *cookie = (uint64_t)(uintptr_t)device;
    return 0;
}

static void
edge_kvm_bhyve_arm64_device_destroy(void *context, uint64_t cookie)
{
    (void)context;
    bsd_kfree((void *)(uintptr_t)cookie);
}

static int
edge_kvm_bhyve_arm64_device_has_attr(void *context, uint64_t cookie,
    const edge_kvm_device_attr_t *attribute)
{
    (void)context;
    if (!cookie || !attribute || attribute->flags != 0)
        return -EDGE_LINUX_EINVAL;
    if (attribute->group == EDGE_KVM_DEVICE_ARM_VGIC_GROUP_ADDRESS &&
        (attribute->attribute == EDGE_KVM_DEVICE_ARM_VGIC_ADDRESS_DIST ||
         attribute->attribute == EDGE_KVM_DEVICE_ARM_VGIC_ADDRESS_REDIST))
        return 0;
    if (attribute->group == EDGE_KVM_DEVICE_ARM_VGIC_GROUP_NR_IRQS &&
        attribute->attribute == 0)
        return 0;
    if (attribute->group == EDGE_KVM_DEVICE_ARM_VGIC_GROUP_DIST_REGS ||
        attribute->group == EDGE_KVM_DEVICE_ARM_VGIC_GROUP_REDIST_REGS ||
        attribute->group == EDGE_KVM_DEVICE_ARM_VGIC_GROUP_CPU_SYSREGS ||
        attribute->group == EDGE_KVM_DEVICE_ARM_VGIC_GROUP_LEVEL_INFO)
        return 0;
    if (attribute->group == EDGE_KVM_DEVICE_ARM_VGIC_GROUP_CONTROL &&
        (attribute->attribute == EDGE_KVM_DEVICE_ARM_VGIC_CONTROL_INIT ||
         attribute->attribute ==
             EDGE_KVM_DEVICE_ARM_VGIC_SAVE_PENDING_TABLES))
        return 0;
    return -EDGE_LINUX_ENXIO;
}

static int
edge_kvm_bhyve_arm64_device_try_attach(
    edge_kvm_bhyve_arm64_device_t *device)
{
    uint32_t vcpu_count = 0;
    int error;

    if (!device->init_requested || device->attached || !device->dist_set ||
        !device->redist_set)
        return 0;
    for (uint32_t index = 0; index < VM_MAXCPU; ++index) {
        if (device->vm->vcpus[index])
            vcpu_count = index + 1u;
    }
    if (vcpu_count == 0)
        vcpu_count = 1;
    device->descriptor.v3_regs.redist_size =
        (uint64_t)vcpu_count * UINT64_C(0x20000);
    error = vm_attach_vgic(device->vm->vm, &device->descriptor);
    if (error != 0)
        return edge_kvm_bhyve_arm64_error(error);
    device->attached = 1;
    if (g_bhyve_arm64_trace)
        bsd_printf("edge-kvm-arm64: vgic attached vcpus=%u irqs=%u\n",
            vcpu_count, device->interrupt_count);
    return 0;
}

static int
edge_kvm_bhyve_arm64_device_set_attr(void *context, uint64_t cookie,
    const edge_kvm_device_attr_t *attribute, const void *value,
    uint32_t value_size)
{
    edge_kvm_bhyve_arm64_device_t *device =
        (edge_kvm_bhyve_arm64_device_t *)(uintptr_t)cookie;
    uint64_t address;
    uint32_t interrupt_count;
    uint32_t register_value;
    uint64_t system_register_value;

    (void)context;
    if (!device || !attribute || attribute->flags != 0)
        return -EDGE_LINUX_EINVAL;
    if (attribute->group == EDGE_KVM_DEVICE_ARM_VGIC_GROUP_ADDRESS) {
        if (!value || value_size != sizeof(address) || device->attached)
            return -EDGE_LINUX_EINVAL;
        memcpy(&address, value, sizeof(address));
        if ((address & (EDGE_KVM_PAGE_SIZE - 1u)) != 0)
            return -EDGE_LINUX_EINVAL;
        if (attribute->attribute == EDGE_KVM_DEVICE_ARM_VGIC_ADDRESS_DIST) {
            device->descriptor.v3_regs.dist_start = address;
            device->dist_set = 1;
            return edge_kvm_bhyve_arm64_device_try_attach(device);
        }
        if (attribute->attribute == EDGE_KVM_DEVICE_ARM_VGIC_ADDRESS_REDIST) {
            device->descriptor.v3_regs.redist_start = address;
            device->redist_set = 1;
            return edge_kvm_bhyve_arm64_device_try_attach(device);
        }
        return -EDGE_LINUX_ENXIO;
    }
    if (attribute->group == EDGE_KVM_DEVICE_ARM_VGIC_GROUP_NR_IRQS &&
        attribute->attribute == 0) {
        if (!value || value_size != sizeof(interrupt_count) ||
            device->attached)
            return -EDGE_LINUX_EINVAL;
        memcpy(&interrupt_count, value, sizeof(interrupt_count));
        if (interrupt_count < 64 || interrupt_count > 1024 ||
            (interrupt_count & 31u) != 0)
            return -EDGE_LINUX_EINVAL;
        device->interrupt_count = interrupt_count;
        return 0;
    }
    if (attribute->group == EDGE_KVM_DEVICE_ARM_VGIC_GROUP_CONTROL &&
        attribute->attribute == EDGE_KVM_DEVICE_ARM_VGIC_CONTROL_INIT) {
        if (value_size != 0 || device->init_requested)
            return -EDGE_LINUX_EINVAL;
        device->init_requested = 1;
        return edge_kvm_bhyve_arm64_device_try_attach(device);
    }
    if (attribute->group == EDGE_KVM_DEVICE_ARM_VGIC_GROUP_CONTROL &&
        attribute->attribute ==
            EDGE_KVM_DEVICE_ARM_VGIC_SAVE_PENDING_TABLES)
        return value_size == 0 && device->attached ? 0 :
            -EDGE_LINUX_EINVAL;
    if (value && value_size == sizeof(register_value) && device->attached &&
        (attribute->group == EDGE_KVM_DEVICE_ARM_VGIC_GROUP_DIST_REGS ||
         attribute->group == EDGE_KVM_DEVICE_ARM_VGIC_GROUP_REDIST_REGS ||
         attribute->group == EDGE_KVM_DEVICE_ARM_VGIC_GROUP_LEVEL_INFO)) {
        int error;

        memcpy(&register_value, value, sizeof(register_value));
        if (attribute->group == EDGE_KVM_DEVICE_ARM_VGIC_GROUP_DIST_REGS)
            error = vgic_v3_kvm_dist_access(device->vm->vm,
                (uint32_t)attribute->attribute, &register_value, 1);
        else if (attribute->group ==
                 EDGE_KVM_DEVICE_ARM_VGIC_GROUP_REDIST_REGS)
            error = vgic_v3_kvm_redist_access(device->vm->vm, 0,
                (uint32_t)attribute->attribute, &register_value, 1);
        else
            error = vgic_v3_kvm_level_access(device->vm->vm, 0,
                (uint32_t)attribute->attribute & 0x3ffu,
                &register_value, 1);
        return error == 0 ? 0 : edge_kvm_bhyve_arm64_error(error);
    }
    if (value && value_size == sizeof(system_register_value) &&
        device->attached && attribute->group ==
            EDGE_KVM_DEVICE_ARM_VGIC_GROUP_CPU_SYSREGS) {
        int error;

        memcpy(&system_register_value, value,
            sizeof(system_register_value));
        error = vgic_v3_kvm_cpu_sysreg_access(device->vm->vm, 0,
            (uint32_t)attribute->attribute, &system_register_value, 1);
        return error == 0 ? 0 : edge_kvm_bhyve_arm64_error(error);
    }
    return -EDGE_LINUX_ENXIO;
}

static int
edge_kvm_bhyve_arm64_device_get_attr(void *context, uint64_t cookie,
    const edge_kvm_device_attr_t *attribute, void *value,
    uint32_t value_size)
{
    edge_kvm_bhyve_arm64_device_t *device =
        (edge_kvm_bhyve_arm64_device_t *)(uintptr_t)cookie;
    uint64_t address;
    uint32_t register_value;
    uint64_t system_register_value;

    (void)context;
    if (!device || !attribute || !value)
        return -EDGE_LINUX_EINVAL;
    if (attribute->group == EDGE_KVM_DEVICE_ARM_VGIC_GROUP_ADDRESS &&
        value_size == sizeof(address)) {
        if (attribute->attribute == EDGE_KVM_DEVICE_ARM_VGIC_ADDRESS_DIST)
            address = device->descriptor.v3_regs.dist_start;
        else if (attribute->attribute ==
                 EDGE_KVM_DEVICE_ARM_VGIC_ADDRESS_REDIST)
            address = device->descriptor.v3_regs.redist_start;
        else
            return -EDGE_LINUX_ENXIO;
        memcpy(value, &address, sizeof(address));
        return 0;
    }
    if (attribute->group == EDGE_KVM_DEVICE_ARM_VGIC_GROUP_NR_IRQS &&
        attribute->attribute == 0 &&
        value_size == sizeof(device->interrupt_count)) {
        memcpy(value, &device->interrupt_count,
            sizeof(device->interrupt_count));
        return 0;
    }
    if (value_size == sizeof(register_value) && device->attached &&
        (attribute->group == EDGE_KVM_DEVICE_ARM_VGIC_GROUP_DIST_REGS ||
         attribute->group == EDGE_KVM_DEVICE_ARM_VGIC_GROUP_REDIST_REGS ||
         attribute->group == EDGE_KVM_DEVICE_ARM_VGIC_GROUP_LEVEL_INFO)) {
        int error;

        if (attribute->group == EDGE_KVM_DEVICE_ARM_VGIC_GROUP_DIST_REGS)
            error = vgic_v3_kvm_dist_access(device->vm->vm,
                (uint32_t)attribute->attribute, &register_value, 0);
        else if (attribute->group ==
                 EDGE_KVM_DEVICE_ARM_VGIC_GROUP_REDIST_REGS)
            error = vgic_v3_kvm_redist_access(device->vm->vm, 0,
                (uint32_t)attribute->attribute, &register_value, 0);
        else
            error = vgic_v3_kvm_level_access(device->vm->vm, 0,
                (uint32_t)attribute->attribute & 0x3ffu,
                &register_value, 0);
        if (error != 0)
            return edge_kvm_bhyve_arm64_error(error);
        memcpy(value, &register_value, sizeof(register_value));
        return 0;
    }
    if (value_size == sizeof(system_register_value) && device->attached &&
        attribute->group == EDGE_KVM_DEVICE_ARM_VGIC_GROUP_CPU_SYSREGS) {
        int error = vgic_v3_kvm_cpu_sysreg_access(device->vm->vm, 0,
            (uint32_t)attribute->attribute, &system_register_value, 0);

        if (error != 0)
            return edge_kvm_bhyve_arm64_error(error);
        memcpy(value, &system_register_value,
            sizeof(system_register_value));
        return 0;
    }
    return -EDGE_LINUX_ENXIO;
}

static int
edge_kvm_bhyve_arm64_unsupported(void)
{
    return -EDGE_LINUX_ENOTTY;
}

#define EDGE_ARM64_UNSUPPORTED_VM_VALUE(name, type) \
    static int name(void *context, uint64_t cookie, type value) \
    { (void)context; (void)cookie; (void)value; \
      return edge_kvm_bhyve_arm64_unsupported(); }
#define EDGE_ARM64_UNSUPPORTED_VM_POINTER(name, type) \
    static int name(void *context, uint64_t cookie, type *value) \
    { (void)context; (void)cookie; (void)value; \
      return edge_kvm_bhyve_arm64_unsupported(); }
#define EDGE_ARM64_UNSUPPORTED_VM_CONST_POINTER(name, type) \
    static int name(void *context, uint64_t cookie, const type *value) \
    { (void)context; (void)cookie; (void)value; \
      return edge_kvm_bhyve_arm64_unsupported(); }

EDGE_ARM64_UNSUPPORTED_VM_VALUE(edge_arm64_vm_address, uint64_t)
EDGE_ARM64_UNSUPPORTED_VM_POINTER(edge_arm64_irqchip_get, edge_kvm_irqchip_t)
EDGE_ARM64_UNSUPPORTED_VM_CONST_POINTER(edge_arm64_irqchip_set,
    edge_kvm_irqchip_t)
EDGE_ARM64_UNSUPPORTED_VM_CONST_POINTER(edge_arm64_pit_create,
    edge_kvm_pit_config_t)
EDGE_ARM64_UNSUPPORTED_VM_POINTER(edge_arm64_pit_get, edge_kvm_pit_state2_t)
EDGE_ARM64_UNSUPPORTED_VM_CONST_POINTER(edge_arm64_pit_set,
    edge_kvm_pit_state2_t)

static int edge_arm64_vm_noarg(void *context, uint64_t cookie)
{ (void)context; (void)cookie; return edge_kvm_bhyve_arm64_unsupported(); }
static int edge_arm64_irq_line(void *context, uint64_t cookie,
    edge_kvm_irq_level_t *line)
{
    edge_kvm_bhyve_arm64_vm_t *backend_vm =
        (edge_kvm_bhyve_arm64_vm_t *)(uintptr_t)cookie;
    uint32_t type;
    uint32_t vcpu_id;
    uint32_t irq;
    int error;

    (void)context;
    if (!backend_vm || !line || line->level > 1)
        return -EDGE_LINUX_EINVAL;
    type = (line->irq >> EDGE_KVM_ARM_IRQ_TYPE_SHIFT) &
        EDGE_KVM_ARM_IRQ_TYPE_MASK;
    vcpu_id = (line->irq >> EDGE_KVM_ARM_IRQ_VCPU_SHIFT) &
        EDGE_KVM_ARM_IRQ_VCPU_MASK;
    irq = line->irq & EDGE_KVM_ARM_IRQ_NUM_MASK;
    if (type == EDGE_KVM_ARM_IRQ_TYPE_SPI) {
        if (vcpu_id != 0)
            return -EDGE_LINUX_EINVAL;
        error = line->level ? vm_assert_irq(backend_vm->vm, irq) :
            vm_deassert_irq(backend_vm->vm, irq);
    } else if (type == EDGE_KVM_ARM_IRQ_TYPE_PPI) {
        if (vcpu_id >= vm_maxcpu || irq < 16 || irq > 31)
            return -EDGE_LINUX_EINVAL;
        error = vgic_inject_irq(backend_vm->vm->cookie, (int)vcpu_id,
            irq, line->level != 0);
    } else {
        return -EDGE_LINUX_EINVAL;
    }
    return edge_kvm_bhyve_arm64_error(error);
}
static int edge_arm64_gsi(void *context, uint64_t cookie,
    const edge_kvm_irq_routing_entry_t *entries, uint32_t count)
{ (void)context; (void)cookie; (void)entries; (void)count;
  return edge_kvm_bhyve_arm64_unsupported(); }
static int edge_arm64_cpuid(void *context, edge_kvm_cpuid_entry2_t *entries,
    uint32_t capacity, uint32_t *count)
{ (void)context; (void)entries; (void)capacity; if (count) *count = 0;
  return count ? 0 : -EDGE_LINUX_EINVAL; }
static int edge_arm64_msr_list(void *context, uint32_t *indices,
    uint32_t capacity, uint32_t *count)
{ (void)context; (void)indices; (void)capacity; if (count) *count = 0;
  return count ? 0 : -EDGE_LINUX_EINVAL; }
static int
edge_arm64_memory(void *context, uint64_t cookie,
    const edge_kvm_memory_region_t *region)
{
    edge_kvm_bhyve_arm64_vm_t *backend_vm =
        (edge_kvm_bhyve_arm64_vm_t *)(uintptr_t)cookie;
    edge_kvm_bhyve_arm64_memory_slot_t replacement = {0};
    edge_kvm_bhyve_arm64_memory_slot_t previous;
    struct vm_mem_seg *segment;
    vm_object_t previous_object = 0;
    vm_object_t object = 0;
    int vm_protection;
    int rollback_error;
    int error = 0;

    (void)context;
    if (!backend_vm || !region ||
        region->slot >= EDGE_KVM_BHYVE_ARM64_MAX_SLOTS)
        return -EDGE_LINUX_EINVAL;
    if (g_bhyve_arm64_trace)
        bsd_printf("edge-kvm-arm64: memory slot=%u gpa=0x%lx size=0x%lx\n",
            region->slot, region->guest_physical_address,
            region->memory_size);
    previous = backend_vm->slots[region->slot];
    if (region->memory_size != 0 && previous.active &&
        previous.guest_physical_address == region->guest_physical_address &&
        previous.memory_size == region->memory_size &&
        previous.userspace_address == region->userspace_address &&
        ((previous.flags ^ region->flags) & EDGE_KVM_MEMORY_READONLY) == 0) {
        pmap_t pmap = vmspace_pmap(vm_vmspace(backend_vm->vm));
        uint32_t previous_dirty =
            previous.flags & EDGE_KVM_MEMORY_LOG_DIRTY_PAGES;
        uint32_t requested_dirty =
            region->flags & EDGE_KVM_MEMORY_LOG_DIRTY_PAGES;

        if (!previous_dirty && requested_dirty)
            error = edgeos_pmap_enable_dirty_tracking(pmap,
                previous.guest_physical_address, previous.page_count);
        else if (previous_dirty && !requested_dirty)
            error = edgeos_pmap_disable_dirty_tracking(pmap,
                previous.guest_physical_address, previous.page_count);
        if (error != 0)
            return edge_kvm_bhyve_arm64_error(error);
        previous.flags = region->flags;
        backend_vm->slots[region->slot] = previous;
        if (g_bhyve_arm64_trace)
            bsd_printf("edge-kvm-arm64: memory slot=%u flags updated\n",
                region->slot);
        return 0;
    }
    if (region->memory_size != 0) {
        error = edge_kvm_bhyve_arm64_build_object(region, &object,
            &replacement.page_chunks, &replacement.page_count);
        if (error < 0)
            return error;
        replacement.active = 1;
        replacement.guest_physical_address =
            region->guest_physical_address;
        replacement.memory_size = region->memory_size;
        replacement.userspace_address = region->userspace_address;
        replacement.flags = region->flags;
    }
    vm_xlock_memsegs(backend_vm->vm);
    segment = &vm_mem(backend_vm->vm)->mem_segs[region->slot];
    if (previous.active) {
        previous_object = segment->object;
        error = vm_munmap_memseg(backend_vm->vm,
            previous.guest_physical_address, previous.memory_size);
        if (error != 0)
            goto out_unlock;
        segment->len = 0;
        segment->sysmem = false;
        segment->object = 0;
    }
    if (replacement.active) {
        segment->len = region->memory_size;
        segment->sysmem = true;
        segment->object = object;
        vm_protection = VM_PROT_READ | VM_PROT_EXECUTE;
        if ((region->flags & EDGE_KVM_MEMORY_READONLY) == 0)
            vm_protection |= VM_PROT_WRITE;
        error = vm_mmap_memseg(backend_vm->vm,
            region->guest_physical_address, (int)region->slot, 0,
            region->memory_size, vm_protection, VM_MEMMAP_F_WIRED);
        if (error == 0 &&
            (region->flags & EDGE_KVM_MEMORY_LOG_DIRTY_PAGES) != 0) {
            error = edgeos_pmap_enable_dirty_tracking(
                vmspace_pmap(vm_vmspace(backend_vm->vm)),
                region->guest_physical_address, replacement.page_count);
        }
        if (error != 0) {
            (void)vm_munmap_memseg(backend_vm->vm,
                region->guest_physical_address, region->memory_size);
            segment->len = 0;
            segment->sysmem = false;
            segment->object = 0;
            vm_object_deallocate(object);
            object = 0;
            if (previous.active) {
                int previous_protection = VM_PROT_READ | VM_PROT_EXECUTE;

                if ((previous.flags & EDGE_KVM_MEMORY_READONLY) == 0)
                    previous_protection |= VM_PROT_WRITE;
                segment->len = previous.memory_size;
                segment->sysmem = true;
                segment->object = previous_object;
                rollback_error = vm_mmap_memseg(backend_vm->vm,
                    previous.guest_physical_address, (int)region->slot,
                    0, previous.memory_size, previous_protection,
                    VM_MEMMAP_F_WIRED);
                if (rollback_error == 0 &&
                    (previous.flags &
                     EDGE_KVM_MEMORY_LOG_DIRTY_PAGES) != 0) {
                    rollback_error = edgeos_pmap_enable_dirty_tracking(
                        vmspace_pmap(vm_vmspace(backend_vm->vm)),
                        previous.guest_physical_address,
                        previous.page_count);
                }
                if (rollback_error != 0)
                    error = rollback_error;
            }
            goto out_unlock;
        }
        object = 0;
    }
    backend_vm->slots[region->slot] = replacement;
    if (previous_object)
        vm_object_deallocate(previous_object);

out_unlock:
    vm_unlock_memsegs(backend_vm->vm);
    if (error != 0) {
        if (object)
            vm_object_deallocate(object);
        edge_kvm_bhyve_arm64_release_pages(&replacement);
        return edge_kvm_bhyve_arm64_error(error);
    }
    edge_kvm_bhyve_arm64_release_pages(&previous);
    if (g_bhyve_arm64_trace)
        bsd_printf("edge-kvm-arm64: memory slot=%u ready\n", region->slot);
    return 0;
}

static int
edge_kvm_bhyve_arm64_vcpu_pre_fault_memory(void *context,
    uint64_t vcpu_cookie, edge_kvm_pre_fault_memory_t *request)
{
    edge_kvm_bhyve_arm64_vcpu_t *backend_vcpu =
        (edge_kvm_bhyve_arm64_vcpu_t *)(uintptr_t)vcpu_cookie;
    uint32_t processed = 0;

    (void)context;
    if (!backend_vcpu || !backend_vcpu->vm || !backend_vcpu->vm->vm ||
        !request)
        return -EDGE_LINUX_EINVAL;
    vm_xlock_memsegs(backend_vcpu->vm->vm);
    while (request->size != 0 && processed < 1024u) {
        void *cookie = 0;
        void *mapping = vm_gpa_hold_global(backend_vcpu->vm->vm,
            request->guest_physical_address, EDGE_KVM_PAGE_SIZE,
            VM_PROT_READ, &cookie);

        if (!mapping)
            break;
        vm_gpa_release(cookie);
        request->guest_physical_address += EDGE_KVM_PAGE_SIZE;
        request->size -= EDGE_KVM_PAGE_SIZE;
        ++processed;
    }
    vm_unlock_memsegs(backend_vcpu->vm->vm);
    return processed != 0 ? 0 : -EDGE_LINUX_ENOENT;
}

static int
edge_arm64_memory_dirty_log_get(void *context, uint64_t cookie,
    uint32_t slot_index, uint32_t first_page, uint32_t page_count,
    uint64_t *bitmap, uint32_t bitmap_words, uint8_t clear)
{
    edge_kvm_bhyve_arm64_vm_t *backend_vm =
        (edge_kvm_bhyve_arm64_vm_t *)(uintptr_t)cookie;
    edge_kvm_bhyve_arm64_memory_slot_t *slot;
    uint32_t required_words = (page_count + 63u) / 64u;
    uint64_t start;
    int error;

    (void)context;
    if (!backend_vm || !bitmap ||
        slot_index >= EDGE_KVM_BHYVE_ARM64_MAX_SLOTS ||
        bitmap_words < required_words)
        return -EDGE_LINUX_EINVAL;
    slot = &backend_vm->slots[slot_index];
    if (!slot->active ||
        (slot->flags & EDGE_KVM_MEMORY_LOG_DIRTY_PAGES) == 0 ||
        first_page > slot->page_count ||
        page_count > slot->page_count - first_page)
        return -EDGE_LINUX_EINVAL;
    start = slot->guest_physical_address +
        (uint64_t)first_page * PAGE_SIZE;
    if (g_bhyve_arm64_trace)
        bsd_printf("edge-kvm-arm64: dirty get slot=%u first=%u pages=%u clear=%u\n",
            slot_index, first_page, page_count, clear);
    error = edgeos_pmap_get_dirty(
        vmspace_pmap(vm_vmspace(backend_vm->vm)), start, page_count,
        bitmap, bitmap_words, clear != 0);
    if (g_bhyve_arm64_trace)
        bsd_printf("edge-kvm-arm64: dirty get slot=%u result=%d\n",
            slot_index, error);
    return error == 0 ? 0 : edge_kvm_bhyve_arm64_error(error);
}

static int
edge_arm64_memory_dirty_log_clear(void *context, uint64_t cookie,
    uint32_t slot_index, uint32_t first_page, uint32_t page_count,
    const uint64_t *bitmap, uint32_t bitmap_words)
{
    edge_kvm_bhyve_arm64_vm_t *backend_vm =
        (edge_kvm_bhyve_arm64_vm_t *)(uintptr_t)cookie;
    edge_kvm_bhyve_arm64_memory_slot_t *slot;
    uint64_t start;
    int error;

    (void)context;
    if (!backend_vm || !bitmap ||
        slot_index >= EDGE_KVM_BHYVE_ARM64_MAX_SLOTS)
        return -EDGE_LINUX_EINVAL;
    slot = &backend_vm->slots[slot_index];
    if (!slot->active ||
        (slot->flags & EDGE_KVM_MEMORY_LOG_DIRTY_PAGES) == 0 ||
        first_page > slot->page_count ||
        page_count > slot->page_count - first_page)
        return -EDGE_LINUX_EINVAL;
    start = slot->guest_physical_address +
        (uint64_t)first_page * PAGE_SIZE;
    if (g_bhyve_arm64_trace)
        bsd_printf("edge-kvm-arm64: dirty clear slot=%u first=%u pages=%u\n",
            slot_index, first_page, page_count);
    error = edgeos_pmap_clear_dirty(
        vmspace_pmap(vm_vmspace(backend_vm->vm)), start, page_count,
        bitmap, bitmap_words);
    if (g_bhyve_arm64_trace)
        bsd_printf("edge-kvm-arm64: dirty clear slot=%u result=%d\n",
            slot_index, error);
    return error == 0 ? 0 : edge_kvm_bhyve_arm64_error(error);
}

#define EDGE_ARM64_UNSUPPORTED_VCPU_POINTER(name, type) \
    static int name(void *context, uint64_t cookie, type *value) \
    { (void)context; (void)cookie; (void)value; \
      return edge_kvm_bhyve_arm64_unsupported(); }
#define EDGE_ARM64_UNSUPPORTED_VCPU_CONST_POINTER(name, type) \
    static int name(void *context, uint64_t cookie, const type *value) \
    { (void)context; (void)cookie; (void)value; \
      return edge_kvm_bhyve_arm64_unsupported(); }

EDGE_ARM64_UNSUPPORTED_VCPU_POINTER(edge_arm64_regs_get, edge_kvm_regs_t)
EDGE_ARM64_UNSUPPORTED_VCPU_CONST_POINTER(edge_arm64_regs_set,
    edge_kvm_regs_t)
EDGE_ARM64_UNSUPPORTED_VCPU_POINTER(edge_arm64_sregs_get, edge_kvm_sregs_t)
EDGE_ARM64_UNSUPPORTED_VCPU_CONST_POINTER(edge_arm64_sregs_set,
    edge_kvm_sregs_t)
EDGE_ARM64_UNSUPPORTED_VCPU_POINTER(edge_arm64_sregs2_get, edge_kvm_sregs2_t)
EDGE_ARM64_UNSUPPORTED_VCPU_CONST_POINTER(edge_arm64_sregs2_set,
    edge_kvm_sregs2_t)
EDGE_ARM64_UNSUPPORTED_VCPU_POINTER(edge_arm64_fpu_get, edge_kvm_fpu_t)
EDGE_ARM64_UNSUPPORTED_VCPU_CONST_POINTER(edge_arm64_fpu_set, edge_kvm_fpu_t)
EDGE_ARM64_UNSUPPORTED_VCPU_POINTER(edge_arm64_lapic_get,
    edge_kvm_lapic_state_t)
EDGE_ARM64_UNSUPPORTED_VCPU_CONST_POINTER(edge_arm64_lapic_set,
    edge_kvm_lapic_state_t)
EDGE_ARM64_UNSUPPORTED_VCPU_POINTER(edge_arm64_debug_get,
    edge_kvm_debugregs_t)
EDGE_ARM64_UNSUPPORTED_VCPU_CONST_POINTER(edge_arm64_debug_set,
    edge_kvm_debugregs_t)
EDGE_ARM64_UNSUPPORTED_VCPU_CONST_POINTER(edge_arm64_guest_debug_set,
    edge_kvm_guest_debug_x86_t)
EDGE_ARM64_UNSUPPORTED_VCPU_POINTER(edge_arm64_xcrs_get, edge_kvm_xcrs_t)
EDGE_ARM64_UNSUPPORTED_VCPU_CONST_POINTER(edge_arm64_xcrs_set,
    edge_kvm_xcrs_t)
EDGE_ARM64_UNSUPPORTED_VCPU_POINTER(edge_arm64_xsave_get, edge_kvm_xsave_t)
EDGE_ARM64_UNSUPPORTED_VCPU_CONST_POINTER(edge_arm64_xsave_set,
    edge_kvm_xsave_t)
EDGE_ARM64_UNSUPPORTED_VCPU_POINTER(edge_arm64_mp_get, edge_kvm_mp_state_t)
EDGE_ARM64_UNSUPPORTED_VCPU_CONST_POINTER(edge_arm64_mp_set,
    edge_kvm_mp_state_t)
EDGE_ARM64_UNSUPPORTED_VCPU_POINTER(edge_arm64_events_get,
    edge_kvm_vcpu_events_t)
EDGE_ARM64_UNSUPPORTED_VCPU_CONST_POINTER(edge_arm64_events_set,
    edge_kvm_vcpu_events_t)

static int edge_arm64_msrs_get(void *context, uint64_t cookie,
    edge_kvm_msr_entry_t *entries, uint32_t count)
{ (void)context; (void)cookie; (void)entries; (void)count;
  return edge_kvm_bhyve_arm64_unsupported(); }
static int edge_arm64_msrs_set(void *context, uint64_t cookie,
    const edge_kvm_msr_entry_t *entries, uint32_t count)
{ (void)context; (void)cookie; (void)entries; (void)count;
  return edge_kvm_bhyve_arm64_unsupported(); }
static int64_t edge_arm64_tsc_get(void *context, uint64_t cookie)
{ (void)context; (void)cookie; return edge_kvm_bhyve_arm64_unsupported(); }
static int edge_arm64_tsc_set(void *context, uint64_t cookie, uint32_t value)
{ (void)context; (void)cookie; (void)value;
  return edge_kvm_bhyve_arm64_unsupported(); }
static int edge_arm64_mce(void *context, uint64_t cookie, uint64_t value)
{ (void)context; (void)cookie; (void)value;
  return edge_kvm_bhyve_arm64_unsupported(); }
static int edge_arm64_mce_set(void *context, uint64_t cookie,
    const edge_kvm_x86_mce_t *machine_check)
{ (void)context; (void)cookie; (void)machine_check;
  return edge_kvm_bhyve_arm64_unsupported(); }
static int edge_arm64_cpuid_set(void *context, uint64_t cookie,
    const edge_kvm_cpuid_entry2_t *entries, uint32_t count)
{ (void)context; (void)cookie; (void)entries; (void)count;
  return edge_kvm_bhyve_arm64_unsupported(); }
static int edge_arm64_cpuid_get(void *context, uint64_t cookie,
    edge_kvm_cpuid_entry2_t *entries, uint32_t capacity, uint32_t *count)
{ (void)context; (void)cookie; (void)entries; (void)capacity; (void)count;
  return edge_kvm_bhyve_arm64_unsupported(); }

int
edge_kvm_bhyve_arm64_register(void)
{
    edge_kvm_backend_ops_t backend = {
        .get_supported_cpuid = edge_arm64_cpuid,
        .get_msr_index_list = edge_arm64_msr_list,
        .vm_create = edge_kvm_bhyve_arm64_vm_create,
        .vm_destroy = edge_kvm_bhyve_arm64_vm_destroy,
        .vm_get_preferred_target = edge_kvm_bhyve_arm64_preferred_target,
        .vm_set_tss_address = edge_arm64_vm_address,
        .vm_set_identity_map_address = edge_arm64_vm_address,
        .vm_create_irqchip = edge_arm64_vm_noarg,
        .vm_set_gsi_routing = edge_arm64_gsi,
        .vm_set_irq_line = edge_arm64_irq_line,
        .vm_get_irqchip = edge_arm64_irqchip_get,
        .vm_set_irqchip = edge_arm64_irqchip_set,
        .vm_create_pit = edge_arm64_pit_create,
        .vm_get_pit = edge_arm64_pit_get,
        .vm_set_pit = edge_arm64_pit_set,
        .vm_coalesced_mmio = edge_kvm_bhyve_arm64_vm_coalesced_mmio,
        .vm_ioeventfd = edge_kvm_bhyve_arm64_vm_ioeventfd,
        .vm_irqfd = edge_kvm_bhyve_arm64_vm_irqfd,
        .vcpu_create = edge_kvm_bhyve_arm64_vcpu_create,
        .vcpu_destroy = edge_kvm_bhyve_arm64_vcpu_destroy,
        .vcpu_init = edge_kvm_bhyve_arm64_vcpu_init,
        .vcpu_get_one_reg = edge_kvm_bhyve_arm64_get_one_reg,
        .vcpu_set_one_reg = edge_kvm_bhyve_arm64_set_one_reg,
        .vcpu_get_reg_list = edge_kvm_bhyve_arm64_get_reg_list,
        .vcpu_run = edge_kvm_bhyve_arm64_vcpu_run,
        .vcpu_pre_fault_memory =
            edge_kvm_bhyve_arm64_vcpu_pre_fault_memory,
        .vcpu_get_regs = edge_arm64_regs_get,
        .vcpu_set_regs = edge_arm64_regs_set,
        .vcpu_get_sregs = edge_arm64_sregs_get,
        .vcpu_set_sregs = edge_arm64_sregs_set,
        .vcpu_get_sregs2 = edge_arm64_sregs2_get,
        .vcpu_set_sregs2 = edge_arm64_sregs2_set,
        .vcpu_get_fpu = edge_arm64_fpu_get,
        .vcpu_set_fpu = edge_arm64_fpu_set,
        .vcpu_get_lapic = edge_arm64_lapic_get,
        .vcpu_set_lapic = edge_arm64_lapic_set,
        .vcpu_get_debugregs = edge_arm64_debug_get,
        .vcpu_set_debugregs = edge_arm64_debug_set,
        .vcpu_set_guest_debug = edge_arm64_guest_debug_set,
        .vcpu_get_xcrs = edge_arm64_xcrs_get,
        .vcpu_set_xcrs = edge_arm64_xcrs_set,
        .vcpu_get_xsave = edge_arm64_xsave_get,
        .vcpu_set_xsave = edge_arm64_xsave_set,
        .vcpu_get_msrs = edge_arm64_msrs_get,
        .vcpu_set_msrs = edge_arm64_msrs_set,
        .vcpu_get_mp_state = edge_arm64_mp_get,
        .vcpu_set_mp_state = edge_arm64_mp_set,
        .vcpu_get_events = edge_arm64_events_get,
        .vcpu_set_events = edge_arm64_events_set,
        .vcpu_get_tsc_khz = edge_arm64_tsc_get,
        .vcpu_set_tsc_khz = edge_arm64_tsc_set,
        .vcpu_setup_mce = edge_arm64_mce,
        .vcpu_set_mce = edge_arm64_mce_set,
        .vcpu_set_cpuid = edge_arm64_cpuid_set,
        .vcpu_get_cpuid = edge_arm64_cpuid_get,
        .vcpu_mmap_page = edge_kvm_bhyve_arm64_vcpu_mmap_page,
        .device_create = edge_kvm_bhyve_arm64_device_create,
        .device_destroy = edge_kvm_bhyve_arm64_device_destroy,
        .device_set_attr = edge_kvm_bhyve_arm64_device_set_attr,
        .device_get_attr = edge_kvm_bhyve_arm64_device_get_attr,
        .device_has_attr = edge_kvm_bhyve_arm64_device_has_attr,
        .memory_region_set = edge_arm64_memory,
        .memory_dirty_log_get = edge_arm64_memory_dirty_log_get,
        .memory_dirty_log_clear = edge_arm64_memory_dirty_log_clear,
    };
    edge_kvm_capability_table_t capabilities;
    int error;

    if (g_bhyve_arm64_initialized)
        return -EDGE_LINUX_EBUSY;
    g_bhyve_arm64_trace =
        kernel_boot_option_enabled("kvm.trace", 0) ? 1u : 0u;
    vm_maxcpu = mp_ncpus > 0 ? (u_int)mp_ncpus : 1u;
    if (vm_maxcpu > VM_MAXCPU)
        vm_maxcpu = VM_MAXCPU;
    if (!vgic_present()) {
        error = bsd_newbus_attach_synthetic(root_bus, "vgic", 0,
            &vgic_v3_driver, &g_bhyve_arm64_vgic_device);
        if (error != 0)
            return edge_kvm_bhyve_arm64_error(error);
    }
    error = vmm_modinit();
    if (error != 0) {
        if (g_bhyve_arm64_vgic_device) {
            (void)device_delete_child(root_bus,
                g_bhyve_arm64_vgic_device);
            g_bhyve_arm64_vgic_device = 0;
        }
        return edge_kvm_bhyve_arm64_error(error);
    }
    edge_kvm_capability_table_init(&capabilities);
    if (edge_kvm_capability_set(&capabilities,
            EDGE_KVM_CAP_USER_MEMORY, 1) < 0 ||
        edge_kvm_capability_set(&capabilities,
            EDGE_KVM_CAP_USER_MEMORY2, 1) < 0 ||
        edge_kvm_capability_set(&capabilities,
            EDGE_KVM_CAP_PRE_FAULT_MEMORY, 1) < 0 ||
        edge_kvm_capability_set(&capabilities,
            EDGE_KVM_CAP_COALESCED_MMIO,
            EDGE_KVM_ARM64_COALESCED_MMIO_PAGE_OFFSET) < 0 ||
        edge_kvm_capability_set(&capabilities,
            EDGE_KVM_CAP_IRQCHIP, 1) < 0 ||
        edge_kvm_capability_set(&capabilities,
            EDGE_KVM_CAP_ARM_PSCI, 1) < 0 ||
        edge_kvm_capability_set(&capabilities,
            EDGE_KVM_CAP_ARM_PSCI_0_2, 1) < 0 ||
        edge_kvm_capability_set(&capabilities,
            EDGE_KVM_CAP_DEVICE_CTRL, 1) < 0 ||
        edge_kvm_capability_set(&capabilities,
            EDGE_KVM_CAP_NR_VCPUS, (int32_t)vm_maxcpu) < 0 ||
        edge_kvm_capability_set(&capabilities,
            EDGE_KVM_CAP_MAX_VCPUS, (int32_t)vm_maxcpu) < 0 ||
        edge_kvm_capability_set(&capabilities,
            EDGE_KVM_CAP_NR_MEMSLOTS, VM_MAXSYSMEM) < 0 ||
        edge_kvm_capability_set(&capabilities,
            EDGE_KVM_CAP_DESTROY_MEMORY_REGION_WORKS, 1) < 0 ||
        edge_kvm_capability_set(&capabilities,
            EDGE_KVM_CAP_JOIN_MEMORY_REGIONS_WORKS, 1) < 0 ||
        edge_kvm_capability_set(&capabilities,
            EDGE_KVM_CAP_INTERNAL_ERROR_DATA, 1) < 0 ||
        edge_kvm_capability_set(&capabilities,
            EDGE_KVM_CAP_IOEVENTFD, 1) < 0 ||
        edge_kvm_capability_set(&capabilities,
            EDGE_KVM_CAP_IOEVENTFD_ANY_LENGTH, 1) < 0 ||
        edge_kvm_capability_set(&capabilities,
            EDGE_KVM_CAP_IRQFD, 1) < 0 ||
        edge_kvm_capability_set(&capabilities,
            EDGE_KVM_CAP_MANUAL_DIRTY_LOG_PROTECT2,
            EDGE_KVM_DIRTY_LOG_MANUAL_SUPPORTED_FLAGS) < 0 ||
        edge_kvm_capability_set(&capabilities,
            EDGE_KVM_CAP_IMMEDIATE_EXIT, 1) < 0) {
        (void)vmm_modcleanup();
        return -EDGE_LINUX_ENOSPC;
    }
    error = kernel_edge_kvm_backend_register(&backend, &capabilities);
    if (error < 0) {
        (void)vmm_modcleanup();
        return error;
    }
    g_bhyve_arm64_initialized = 1;
    return 0;
}
