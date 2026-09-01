/* SPDX-License-Identifier: MPL-2.0 */
/* Kernel descriptor and usercopy boundary for the EdgeOS KVM ABI. */

#include "kernel/edge_kvm_abi.h"
#include "kernel/anonymous_fd.h"
#include "kernel/edge_kvm_runtime.h"
#include "kernel/eventfd.h"
#include "kernel/linux_errno.h"

static edge_kvm_facade_t g_edge_kvm_facade;
static const kernel_edge_kvm_descriptor_backend_ops_t *g_descriptor_ops;
static void *g_descriptor_context;
static volatile uint32_t g_runtime_lock;
static edge_kvm_cpuid_entry2_t
    g_runtime_cpuid_entries[EDGE_KVM_MAX_CPUID_ENTRIES];
static edge_kvm_msr_entry_t
    g_runtime_msr_entries[EDGE_KVM_MAX_MSR_ENTRIES];
static uint32_t g_runtime_msr_indices[EDGE_KVM_MAX_MSR_ENTRIES];
static uint64_t g_runtime_register_ids[EDGE_KVM_MAX_REG_ENTRIES];
#define EDGE_KVM_DIRTY_LOG_CHUNK_WORDS 512u
#define EDGE_KVM_DIRTY_LOG_CHUNK_PAGES \
    (EDGE_KVM_DIRTY_LOG_CHUNK_WORDS * 64u)
static uint64_t g_runtime_dirty_bitmap[EDGE_KVM_DIRTY_LOG_CHUNK_WORDS];
static edge_kvm_lapic_state_t g_runtime_lapic_state;
static edge_kvm_xsave_t g_runtime_xsave_state __attribute__((aligned(64)));
static edge_kvm_irq_routing_entry_t
    g_runtime_irq_routes[EDGE_KVM_MAX_IRQ_ROUTES];

static int edge_kvm_system_command_known_unsupported(uint32_t command) {
    return command == EDGE_KVM_IOCTL_GET_NR_MMU_PAGES ||
        command == EDGE_KVM_IOCTL_GET_SUPPORTED_HV_CPUID;
}

static int edge_kvm_vm_command_known_unsupported(uint32_t command) {
    return command == EDGE_KVM_IOCTL_SET_NR_MMU_PAGES ||
        command == EDGE_KVM_IOCTL_SET_BOOT_CPU_ID ||
        command == EDGE_KVM_IOCTL_ARM_SET_DEVICE_ADDR ||
        command == EDGE_KVM_IOCTL_SET_PMU_EVENT_FILTER_X86 ||
        command == EDGE_KVM_IOCTL_SET_PMU_EVENT_FILTER_ARM64 ||
        command == EDGE_KVM_IOCTL_ARM_MTE_COPY_TAGS ||
        command == EDGE_KVM_IOCTL_ARM_SET_COUNTER_OFFSET ||
        command == EDGE_KVM_IOCTL_ARM_GET_REG_WRITABLE_MASKS ||
        command == EDGE_KVM_IOCTL_HYPERV_EVENTFD ||
        command == EDGE_KVM_IOCTL_XEN_HVM_CONFIG ||
        command == EDGE_KVM_IOCTL_XEN_HVM_GET_ATTR ||
        command == EDGE_KVM_IOCTL_XEN_HVM_SET_ATTR ||
        command == EDGE_KVM_IOCTL_XEN_HVM_EVTCHN_SEND ||
        command == EDGE_KVM_IOCTL_REINJECT_CONTROL ||
        command == EDGE_KVM_IOCTL_MEMORY_ENCRYPT_OP ||
        command == EDGE_KVM_IOCTL_MEMORY_ENCRYPT_REG_REGION ||
        command == EDGE_KVM_IOCTL_MEMORY_ENCRYPT_UNREG_REGION ||
        command == EDGE_KVM_IOCTL_RESET_DIRTY_RINGS ||
        command == EDGE_KVM_IOCTL_X86_SET_MSR_FILTER;
}

static int edge_kvm_vcpu_command_known_unsupported(uint32_t command) {
    return command == EDGE_KVM_IOCTL_ENABLE_CAP ||
        command == EDGE_KVM_IOCTL_DIRTY_TLB ||
        command == EDGE_KVM_IOCTL_TPR_ACCESS_REPORTING ||
        command == EDGE_KVM_IOCTL_SET_GUEST_DEBUG_ARM64 ||
        command == EDGE_KVM_IOCTL_KVMCLOCK_CTRL ||
        command == EDGE_KVM_IOCTL_SMI ||
        command == EDGE_KVM_IOCTL_MEMORY_ENCRYPT_OP ||
        command == EDGE_KVM_IOCTL_GET_NESTED_STATE ||
        command == EDGE_KVM_IOCTL_SET_NESTED_STATE ||
        command == EDGE_KVM_IOCTL_GET_SUPPORTED_HV_CPUID ||
        command == EDGE_KVM_IOCTL_XEN_VCPU_GET_ATTR ||
        command == EDGE_KVM_IOCTL_XEN_VCPU_SET_ATTR ||
        command == EDGE_KVM_IOCTL_ARM_VCPU_FINALIZE;
}
static void edge_kvm_runtime_lock(void) {
    while (__atomic_exchange_n(&g_runtime_lock, 1u, __ATOMIC_ACQUIRE)) {
        while (__atomic_load_n(&g_runtime_lock, __ATOMIC_RELAXED))
            __asm__ __volatile__("" ::: "memory");
    }
}

static void edge_kvm_runtime_unlock(void) {
    __atomic_store_n(&g_runtime_lock, 0u, __ATOMIC_RELEASE);
}

static int edge_kvm_runtime_padding_is_zero(const uint8_t *padding,
                                            uint32_t length) {
    for (uint32_t index = 0; index < length; ++index) {
        if (padding[index] != 0) return 0;
    }
    return 1;
}

#define EDGE_KVM_STATS_BLOB_SIZE 512u
#define EDGE_KVM_STATS_DESCRIPTOR_STRIDE \
    (sizeof(edge_kvm_stats_descriptor_t) + EDGE_KVM_STATS_NAME_SIZE)

static void edge_kvm_stats_copy_text(char *destination, uint32_t capacity,
                                     const char *source) {
    uint32_t index = 0;

    if (!destination || !capacity) return;
    while (index + 1u < capacity && source[index] != 0) {
        destination[index] = source[index];
        ++index;
    }
    destination[index] = 0;
}

static void edge_kvm_stats_append_decimal(char *destination,
                                          uint32_t capacity,
                                          uint32_t value) {
    char digits[10];
    uint32_t count = 0;
    uint32_t length = 0;

    if (!destination || !capacity) return;
    while (length < capacity && destination[length] != 0) ++length;
    do {
        digits[count++] = (char)('0' + value % 10u);
        value /= 10u;
    } while (value != 0 && count < sizeof(digits));
    while (count != 0 && length + 1u < capacity)
        destination[length++] = digits[--count];
    destination[length] = 0;
}

static void edge_kvm_stats_set_descriptor(
        uint8_t *blob, uint32_t descriptor_offset, uint32_t index,
        uint32_t flags, uint32_t data_offset, const char *name) {
    uint8_t *entry = blob + descriptor_offset +
        index * EDGE_KVM_STATS_DESCRIPTOR_STRIDE;
    edge_kvm_stats_descriptor_t *descriptor =
        (edge_kvm_stats_descriptor_t *)(void *)entry;

    descriptor->flags = flags | EDGE_KVM_STATS_UNIT_NONE |
        EDGE_KVM_STATS_BASE_POW10;
    descriptor->exponent = 0;
    descriptor->size = 1;
    descriptor->offset = data_offset;
    descriptor->bucket_size = 0;
    edge_kvm_stats_copy_text(
        (char *)(entry + sizeof(*descriptor)), EDGE_KVM_STATS_NAME_SIZE,
        name);
}

static int edge_kvm_stats_build(kernel_edge_kvm_file_kind_t source_kind,
                                edge_kvm_handle_t handle, uint8_t *blob,
                                uint32_t *blob_size) {
    edge_kvm_stats_header_t *header;
    edge_kvm_vm_snapshot_t vm_snapshot;
    edge_kvm_vcpu_snapshot_t vcpu_snapshot;
    uint64_t *data;
    char *identifier;
    uint32_t descriptor_count;
    int status;

    if (!blob || !blob_size) return -EDGE_LINUX_EINVAL;
    __builtin_memset(blob, 0, EDGE_KVM_STATS_BLOB_SIZE);
    header = (edge_kvm_stats_header_t *)(void *)blob;
    header->name_size = EDGE_KVM_STATS_NAME_SIZE;
    header->id_offset = sizeof(*header);
    header->descriptor_offset =
        header->id_offset + EDGE_KVM_STATS_NAME_SIZE;
    identifier = (char *)(blob + header->id_offset);
    if (source_kind == KERNEL_EDGE_KVM_FILE_VM) {
        status = edge_kvm_vm_snapshot(
            &g_edge_kvm_facade.objects, handle, &vm_snapshot);
        if (status < 0) return status;
        descriptor_count = 3;
        edge_kvm_stats_copy_text(
            identifier, EDGE_KVM_STATS_NAME_SIZE, "edgeos-kvm-vm-");
        edge_kvm_stats_append_decimal(
            identifier, EDGE_KVM_STATS_NAME_SIZE, handle.slot);
        edge_kvm_stats_set_descriptor(
            blob, header->descriptor_offset, 0,
            EDGE_KVM_STATS_TYPE_INSTANT, 0, "vcpu_count");
        edge_kvm_stats_set_descriptor(
            blob, header->descriptor_offset, 1,
            EDGE_KVM_STATS_TYPE_INSTANT, sizeof(uint64_t),
            "device_count");
        edge_kvm_stats_set_descriptor(
            blob, header->descriptor_offset, 2,
            EDGE_KVM_STATS_TYPE_INSTANT, 2u * sizeof(uint64_t),
            "memory_slot_count");
        header->data_offset = header->descriptor_offset +
            descriptor_count * EDGE_KVM_STATS_DESCRIPTOR_STRIDE;
        data = (uint64_t *)(void *)(blob + header->data_offset);
        data[0] = vm_snapshot.vcpu_count;
        data[1] = vm_snapshot.device_count;
        data[2] = vm_snapshot.memory_slot_count;
    } else if (source_kind == KERNEL_EDGE_KVM_FILE_VCPU) {
        status = edge_kvm_vcpu_snapshot(
            &g_edge_kvm_facade.objects, handle, &vcpu_snapshot);
        if (status < 0) return status;
        descriptor_count = 2;
        edge_kvm_stats_copy_text(
            identifier, EDGE_KVM_STATS_NAME_SIZE, "edgeos-kvm-vcpu-");
        edge_kvm_stats_append_decimal(
            identifier, EDGE_KVM_STATS_NAME_SIZE, vcpu_snapshot.vcpu_id);
        edge_kvm_stats_set_descriptor(
            blob, header->descriptor_offset, 0,
            EDGE_KVM_STATS_TYPE_INSTANT, 0, "vcpu_id");
        edge_kvm_stats_set_descriptor(
            blob, header->descriptor_offset, 1,
            EDGE_KVM_STATS_TYPE_CUMULATIVE, sizeof(uint64_t),
            "run_calls");
        header->data_offset = header->descriptor_offset +
            descriptor_count * EDGE_KVM_STATS_DESCRIPTOR_STRIDE;
        data = (uint64_t *)(void *)(blob + header->data_offset);
        data[0] = vcpu_snapshot.vcpu_id;
        data[1] = vcpu_snapshot.run_calls;
    } else {
        return -EDGE_LINUX_EINVAL;
    }
    header->descriptor_count = descriptor_count;
    *blob_size = header->data_offset +
        descriptor_count * sizeof(uint64_t);
    if (*blob_size > EDGE_KVM_STATS_BLOB_SIZE)
        return -EDGE_LINUX_EOVERFLOW;
    return 0;
}

static int edge_kvm_runtime_install(void *context,
                                    edge_kvm_descriptor_kind_t kind,
                                    edge_kvm_handle_t handle) {
    kernel_edge_kvm_file_kind_t file_kind;
    (void)context;

    if (!g_descriptor_ops) return -EDGE_LINUX_ENODEV;
    if (kind == EDGE_KVM_DESCRIPTOR_VM)
        file_kind = KERNEL_EDGE_KVM_FILE_VM;
    else if (kind == EDGE_KVM_DESCRIPTOR_VCPU)
        file_kind = KERNEL_EDGE_KVM_FILE_VCPU;
    else
        file_kind = KERNEL_EDGE_KVM_FILE_DEVICE;
    return g_descriptor_ops->install(g_descriptor_context, file_kind, handle);
}

static int edge_kvm_runtime_install_stats(
        kernel_edge_kvm_file_kind_t source_kind,
        edge_kvm_handle_t handle) {
    edge_kvm_descriptor_kind_t descriptor_kind;
    int descriptor;
    int status;

    if (source_kind == KERNEL_EDGE_KVM_FILE_VM)
        descriptor_kind = EDGE_KVM_DESCRIPTOR_VM;
    else if (source_kind == KERNEL_EDGE_KVM_FILE_VCPU)
        descriptor_kind = EDGE_KVM_DESCRIPTOR_VCPU;
    else
        return -EDGE_LINUX_EINVAL;
    status = edge_kvm_facade_descriptor_retain(
        &g_edge_kvm_facade, descriptor_kind, handle);
    if (status < 0) return status;
    descriptor = g_descriptor_ops->install_stats(
        g_descriptor_context, source_kind, handle);
    if (descriptor < 0)
        (void)edge_kvm_facade_descriptor_release(
            &g_edge_kvm_facade, descriptor_kind, handle);
    return descriptor;
}

int kernel_edge_kvm_descriptor_backend_register(
        const kernel_edge_kvm_descriptor_backend_ops_t *ops, void *context) {
    if (!ops || !ops->install || !ops->resolve || !ops->install_stats ||
        !ops->install_guest_memfd || !ops->close)
        return -EDGE_LINUX_EINVAL;
    g_descriptor_ops = ops;
    g_descriptor_context = context;
    return 0;
}

int kernel_edge_kvm_backend_register(
        const edge_kvm_backend_ops_t *backend,
        const edge_kvm_capability_table_t *capabilities) {
    edge_kvm_descriptor_ops_t descriptors = {
        .context = 0,
        .install = edge_kvm_runtime_install,
    };
    int status;

    if (!g_descriptor_ops) return -EDGE_LINUX_ENODEV;
    edge_kvm_runtime_lock();
    if (g_edge_kvm_facade.initialized) {
        edge_kvm_runtime_unlock();
        return -EDGE_LINUX_EBUSY;
    }
    status = edge_kvm_facade_init(&g_edge_kvm_facade, backend,
                                  &descriptors, capabilities);
    edge_kvm_runtime_unlock();
    return status;
}

static int edge_kvm_copy_memory_region(
        const kernel_ioctl_request_t *request,
        edge_kvm_userspace_memory_region_t *region) {
    if (!request->argument || !request->copy_from_user)
        return -EDGE_LINUX_EFAULT;
    if (request->copy_from_user(
            request->copy_context, region, request->argument,
            sizeof(*region)) < 0)
        return -EDGE_LINUX_EFAULT;
    return 0;
}

static int edge_kvm_runtime_get_supported_cpuid(
        const kernel_ioctl_request_t *request) {
    edge_kvm_cpuid2_t header;
    uint32_t capacity;
    uint32_t count = 0;
    int status;

    if (!request->argument || !request->copy_from_user ||
        !request->copy_to_user)
        return -EDGE_LINUX_EFAULT;
    if (request->copy_from_user(request->copy_context, &header,
            request->argument, sizeof(header)) < 0)
        return -EDGE_LINUX_EFAULT;
    capacity = header.nent;
    status = edge_kvm_facade_get_supported_cpuid(
        &g_edge_kvm_facade, g_runtime_cpuid_entries,
        capacity < EDGE_KVM_MAX_CPUID_ENTRIES ? capacity :
            EDGE_KVM_MAX_CPUID_ENTRIES,
        &count);
    if (status < 0)
        return status;
    header.nent = count;
    header.padding = 0;
    if (request->copy_to_user(request->copy_context, request->argument,
            &header, sizeof(header)) < 0)
        return -EDGE_LINUX_EFAULT;
    if (capacity < count)
        return -EDGE_LINUX_E2BIG;
    if (count != 0 && request->copy_to_user(
            request->copy_context,
            request->argument + sizeof(header), g_runtime_cpuid_entries,
            (uint64_t)count * sizeof(g_runtime_cpuid_entries[0])) < 0)
        return -EDGE_LINUX_EFAULT;
    return 0;
}

static int edge_kvm_runtime_get_emulated_cpuid(
        const kernel_ioctl_request_t *request) {
    edge_kvm_cpuid2_t header;

    if (!request->argument || !request->copy_from_user ||
        !request->copy_to_user)
        return -EDGE_LINUX_EFAULT;
    if (request->copy_from_user(request->copy_context, &header,
            request->argument, sizeof(header)) < 0)
        return -EDGE_LINUX_EFAULT;
    header.nent = 0;
    header.padding = 0;
    if (request->copy_to_user(request->copy_context, request->argument,
            &header, sizeof(header)) < 0)
        return -EDGE_LINUX_EFAULT;
    return 0;
}

static int edge_kvm_runtime_get_cpuid2(
        const kernel_ioctl_request_t *request, edge_kvm_handle_t vcpu) {
    edge_kvm_cpuid2_t header;
    uint32_t capacity;
    uint32_t count = 0;
    int status;

    if (!request->argument || !request->copy_from_user ||
        !request->copy_to_user)
        return -EDGE_LINUX_EFAULT;
    if (request->copy_from_user(request->copy_context, &header,
            request->argument, sizeof(header)) < 0)
        return -EDGE_LINUX_EFAULT;
    capacity = header.nent;
    status = edge_kvm_facade_vcpu_get_cpuid(
        &g_edge_kvm_facade, vcpu, g_runtime_cpuid_entries,
        capacity < EDGE_KVM_MAX_CPUID_ENTRIES ? capacity :
            EDGE_KVM_MAX_CPUID_ENTRIES,
        &count);
    if (status < 0)
        return status;
    header.nent = count;
    header.padding = 0;
    if (request->copy_to_user(request->copy_context, request->argument,
            &header, sizeof(header)) < 0)
        return -EDGE_LINUX_EFAULT;
    if (capacity < count)
        return -EDGE_LINUX_E2BIG;
    if (count != 0 && request->copy_to_user(
            request->copy_context, request->argument + sizeof(header),
            g_runtime_cpuid_entries,
            (uint64_t)count * sizeof(g_runtime_cpuid_entries[0])) < 0)
        return -EDGE_LINUX_EFAULT;
    return 0;
}

static int edge_kvm_runtime_set_cpuid2(
        const kernel_ioctl_request_t *request,
        edge_kvm_handle_t vcpu) {
    edge_kvm_cpuid2_t header;
    uint64_t bytes;

    if (!request->argument || !request->copy_from_user)
        return -EDGE_LINUX_EFAULT;
    if (request->copy_from_user(request->copy_context, &header,
            request->argument, sizeof(header)) < 0)
        return -EDGE_LINUX_EFAULT;
    if (header.nent > EDGE_KVM_MAX_CPUID_ENTRIES)
        return -EDGE_LINUX_E2BIG;
    bytes = (uint64_t)header.nent * sizeof(g_runtime_cpuid_entries[0]);
    if (header.nent != 0 && request->copy_from_user(
            request->copy_context, g_runtime_cpuid_entries,
            request->argument + sizeof(header), bytes) < 0)
        return -EDGE_LINUX_EFAULT;
    return edge_kvm_facade_vcpu_set_cpuid(
        &g_edge_kvm_facade, vcpu, g_runtime_cpuid_entries, header.nent);
}

static int edge_kvm_runtime_set_cpuid(
        const kernel_ioctl_request_t *request, edge_kvm_handle_t vcpu) {
    edge_kvm_cpuid_t header;
    edge_kvm_cpuid_entry_t entry;

    if (!request->argument || !request->copy_from_user)
        return -EDGE_LINUX_EFAULT;
    if (request->copy_from_user(request->copy_context, &header,
            request->argument, sizeof(header)) < 0)
        return -EDGE_LINUX_EFAULT;
    if (header.padding != 0)
        return -EDGE_LINUX_EINVAL;
    if (header.nent > EDGE_KVM_MAX_CPUID_ENTRIES)
        return -EDGE_LINUX_E2BIG;
    for (uint32_t index = 0; index < header.nent; ++index) {
        if (request->copy_from_user(
                request->copy_context, &entry,
                request->argument + sizeof(header) +
                    (uint64_t)index * sizeof(entry),
                sizeof(entry)) < 0)
            return -EDGE_LINUX_EFAULT;
        g_runtime_cpuid_entries[index].function = entry.function;
        g_runtime_cpuid_entries[index].index = 0;
        g_runtime_cpuid_entries[index].flags = 0;
        g_runtime_cpuid_entries[index].eax = entry.eax;
        g_runtime_cpuid_entries[index].ebx = entry.ebx;
        g_runtime_cpuid_entries[index].ecx = entry.ecx;
        g_runtime_cpuid_entries[index].edx = entry.edx;
        g_runtime_cpuid_entries[index].padding[0] = 0;
        g_runtime_cpuid_entries[index].padding[1] = 0;
        g_runtime_cpuid_entries[index].padding[2] = 0;
    }
    return edge_kvm_facade_vcpu_set_cpuid(
        &g_edge_kvm_facade, vcpu, g_runtime_cpuid_entries, header.nent);
}

static int edge_kvm_runtime_set_gsi_routing(
        const kernel_ioctl_request_t *request, edge_kvm_handle_t vm) {
    edge_kvm_irq_routing_t header;
    uint64_t bytes;

    if (!request->argument || !request->copy_from_user)
        return -EDGE_LINUX_EFAULT;
    if (request->copy_from_user(request->copy_context, &header,
            request->argument, sizeof(header)) < 0)
        return -EDGE_LINUX_EFAULT;
    if (header.flags != 0 || header.nr > EDGE_KVM_MAX_IRQ_ROUTES)
        return -EDGE_LINUX_EINVAL;
    bytes = (uint64_t)header.nr * sizeof(g_runtime_irq_routes[0]);
    if (header.nr != 0 && request->copy_from_user(
            request->copy_context, g_runtime_irq_routes,
            request->argument + sizeof(header), bytes) < 0)
        return -EDGE_LINUX_EFAULT;
    return edge_kvm_facade_vm_set_gsi_routing(
        &g_edge_kvm_facade, vm, g_runtime_irq_routes, header.nr);
}

static int edge_kvm_runtime_get_dirty_log(
        const kernel_ioctl_request_t *request, edge_kvm_handle_t vm) {
    edge_kvm_dirty_log_t descriptor;
    uint32_t total_pages;
    uint32_t first_page = 0;
    int status;

    if (!request->argument || !request->copy_from_user ||
        !request->copy_to_user)
        return -EDGE_LINUX_EFAULT;
    if (request->copy_from_user(request->copy_context, &descriptor,
            request->argument, sizeof(descriptor)) < 0)
        return -EDGE_LINUX_EFAULT;
    if (descriptor.padding != 0 || descriptor.dirty_bitmap == 0)
        return -EDGE_LINUX_EINVAL;
    status = edge_kvm_facade_vm_dirty_log_page_count(
        &g_edge_kvm_facade, vm, descriptor.slot, &total_pages);
    if (status < 0)
        return status;
    while (first_page < total_pages) {
        uint32_t page_count = total_pages - first_page;
        uint32_t words;
        uint64_t destination;

        if (page_count > EDGE_KVM_DIRTY_LOG_CHUNK_PAGES)
            page_count = EDGE_KVM_DIRTY_LOG_CHUNK_PAGES;
        words = (page_count + 63u) / 64u;
        status = edge_kvm_facade_vm_get_dirty_log(
            &g_edge_kvm_facade, vm, descriptor.slot, first_page,
            page_count, g_runtime_dirty_bitmap, words);
        if (status < 0)
            return status;
        destination = descriptor.dirty_bitmap +
            (uint64_t)(first_page / 64u) * sizeof(uint64_t);
        if (destination < descriptor.dirty_bitmap ||
            request->copy_to_user(request->copy_context, destination,
                g_runtime_dirty_bitmap,
                (uint64_t)words * sizeof(uint64_t)) < 0)
            return -EDGE_LINUX_EFAULT;
        first_page += page_count;
    }
    return 0;
}

static int edge_kvm_runtime_clear_dirty_log(
        const kernel_ioctl_request_t *request, edge_kvm_handle_t vm) {
    edge_kvm_clear_dirty_log_t descriptor;
    uint32_t processed_pages = 0;

    if (!request->argument || !request->copy_from_user)
        return -EDGE_LINUX_EFAULT;
    if (request->copy_from_user(request->copy_context, &descriptor,
            request->argument, sizeof(descriptor)) < 0)
        return -EDGE_LINUX_EFAULT;
    if (descriptor.dirty_bitmap == 0 || descriptor.num_pages == 0 ||
        descriptor.first_page > UINT32_MAX ||
        descriptor.num_pages > UINT32_MAX - descriptor.first_page)
        return -EDGE_LINUX_EINVAL;
    while (processed_pages < descriptor.num_pages) {
        uint32_t page_count = descriptor.num_pages - processed_pages;
        uint32_t words;
        uint64_t source;
        int status;

        if (page_count > EDGE_KVM_DIRTY_LOG_CHUNK_PAGES)
            page_count = EDGE_KVM_DIRTY_LOG_CHUNK_PAGES;
        words = (page_count + 63u) / 64u;
        source = descriptor.dirty_bitmap +
            (uint64_t)(processed_pages / 64u) * sizeof(uint64_t);
        if (source < descriptor.dirty_bitmap ||
            request->copy_from_user(request->copy_context,
                g_runtime_dirty_bitmap, source,
                (uint64_t)words * sizeof(uint64_t)) < 0)
            return -EDGE_LINUX_EFAULT;
        status = edge_kvm_facade_vm_clear_dirty_log(
            &g_edge_kvm_facade, vm, descriptor.slot,
            (uint32_t)descriptor.first_page + processed_pages,
            page_count, g_runtime_dirty_bitmap, words);
        if (status < 0)
            return status;
        processed_pages += page_count;
    }
    return 0;
}

static int edge_kvm_runtime_get_msr_index_list(
        const kernel_ioctl_request_t *request, int features) {
    edge_kvm_msr_list_t header;
    uint32_t capacity;
    uint32_t count = 0;
    int status;

    if (!request->argument || !request->copy_from_user ||
        !request->copy_to_user)
        return -EDGE_LINUX_EFAULT;
    if (request->copy_from_user(request->copy_context, &header,
            request->argument, sizeof(header)) < 0)
        return -EDGE_LINUX_EFAULT;
    capacity = header.nmsrs;
    if (features)
        status = edge_kvm_facade_get_msr_feature_index_list(
            &g_edge_kvm_facade, g_runtime_msr_indices,
            capacity < EDGE_KVM_MAX_MSR_ENTRIES ? capacity :
                EDGE_KVM_MAX_MSR_ENTRIES,
            &count);
    else
        status = edge_kvm_facade_get_msr_index_list(
            &g_edge_kvm_facade, g_runtime_msr_indices,
            capacity < EDGE_KVM_MAX_MSR_ENTRIES ? capacity :
                EDGE_KVM_MAX_MSR_ENTRIES,
            &count);
    if (status < 0)
        return status;
    header.nmsrs = count;
    if (request->copy_to_user(request->copy_context, request->argument,
            &header, sizeof(header)) < 0)
        return -EDGE_LINUX_EFAULT;
    if (capacity < count)
        return -EDGE_LINUX_E2BIG;
    if (count != 0 && request->copy_to_user(
            request->copy_context, request->argument + sizeof(header),
            g_runtime_msr_indices,
            (uint64_t)count * sizeof(g_runtime_msr_indices[0])) < 0)
        return -EDGE_LINUX_EFAULT;
    return 0;
}

static int edge_kvm_runtime_feature_msrs(
        const kernel_ioctl_request_t *request) {
    edge_kvm_msrs_t header;
    uint64_t bytes;
    int processed;

    if (!request->argument || !request->copy_from_user ||
        !request->copy_to_user)
        return -EDGE_LINUX_EFAULT;
    if (request->copy_from_user(request->copy_context, &header,
            request->argument, sizeof(header)) < 0)
        return -EDGE_LINUX_EFAULT;
    if (header.padding != 0 || header.nmsrs > EDGE_KVM_MAX_MSR_ENTRIES)
        return -EDGE_LINUX_EINVAL;
    bytes = (uint64_t)header.nmsrs * sizeof(g_runtime_msr_entries[0]);
    if (header.nmsrs != 0 && request->copy_from_user(
            request->copy_context, g_runtime_msr_entries,
            request->argument + sizeof(header), bytes) < 0)
        return -EDGE_LINUX_EFAULT;
    processed = edge_kvm_facade_get_msr_features(
        &g_edge_kvm_facade, g_runtime_msr_entries, header.nmsrs);
    if (processed < 0)
        return processed;
    if ((uint32_t)processed > header.nmsrs)
        return -EDGE_LINUX_EIO;
    if (header.nmsrs != 0 && request->copy_to_user(
            request->copy_context, request->argument + sizeof(header),
            g_runtime_msr_entries, bytes) < 0)
        return -EDGE_LINUX_EFAULT;
    return processed;
}

static int edge_kvm_runtime_msrs(
        const kernel_ioctl_request_t *request, edge_kvm_handle_t vcpu,
        int write) {
    edge_kvm_msrs_t header;
    uint64_t bytes;
    int processed;

    if (!request->argument || !request->copy_from_user ||
        (!write && !request->copy_to_user))
        return -EDGE_LINUX_EFAULT;
    if (request->copy_from_user(request->copy_context, &header,
            request->argument, sizeof(header)) < 0)
        return -EDGE_LINUX_EFAULT;
    if (header.padding != 0 || header.nmsrs > EDGE_KVM_MAX_MSR_ENTRIES)
        return -EDGE_LINUX_EINVAL;
    bytes = (uint64_t)header.nmsrs * sizeof(g_runtime_msr_entries[0]);
    if (header.nmsrs != 0 && request->copy_from_user(
            request->copy_context, g_runtime_msr_entries,
            request->argument + sizeof(header), bytes) < 0)
        return -EDGE_LINUX_EFAULT;
    if (write)
        processed = edge_kvm_facade_vcpu_set_msrs(
            &g_edge_kvm_facade, vcpu, g_runtime_msr_entries, header.nmsrs);
    else
        processed = edge_kvm_facade_vcpu_get_msrs(
            &g_edge_kvm_facade, vcpu, g_runtime_msr_entries, header.nmsrs);
    if (processed < 0 || write)
        return processed;
    if (processed != 0 && request->copy_to_user(
            request->copy_context, request->argument + sizeof(header),
            g_runtime_msr_entries,
            (uint64_t)processed * sizeof(g_runtime_msr_entries[0])) < 0)
        return -EDGE_LINUX_EFAULT;
    return processed;
}

static int edge_kvm_runtime_one_reg(
        const kernel_ioctl_request_t *request, edge_kvm_handle_t vcpu,
        int write) {
    edge_kvm_one_reg_t descriptor;
    uint8_t value[16] __attribute__((aligned(16)));
    uint32_t size;
    int status;

    if (!request->argument || !request->copy_from_user ||
        (!write && !request->copy_to_user))
        return -EDGE_LINUX_EFAULT;
    if (request->copy_from_user(request->copy_context, &descriptor,
            request->argument, sizeof(descriptor)) < 0)
        return -EDGE_LINUX_EFAULT;
    size = edge_kvm_register_size(descriptor.id);
    if (size == 0 || size > sizeof(value) || descriptor.address == 0)
        return -EDGE_LINUX_EINVAL;
    if (write) {
        if (request->copy_from_user(request->copy_context, value,
                descriptor.address, size) < 0)
            return -EDGE_LINUX_EFAULT;
        return edge_kvm_facade_vcpu_set_one_reg(
            &g_edge_kvm_facade, vcpu, descriptor.id, value, size);
    }
    status = edge_kvm_facade_vcpu_get_one_reg(
        &g_edge_kvm_facade, vcpu, descriptor.id, value, size);
    if (status < 0) return status;
    if (request->copy_to_user(request->copy_context, descriptor.address,
            value, size) < 0)
        return -EDGE_LINUX_EFAULT;
    return 0;
}

static int edge_kvm_runtime_get_reg_list(
        const kernel_ioctl_request_t *request, edge_kvm_handle_t vcpu) {
    edge_kvm_reg_list_t header;
    uint32_t capacity;
    uint32_t backend_capacity;
    uint32_t count = 0;
    int status;

    if (!request->argument || !request->copy_from_user ||
        !request->copy_to_user)
        return -EDGE_LINUX_EFAULT;
    if (request->copy_from_user(request->copy_context, &header,
            request->argument, sizeof(header)) < 0)
        return -EDGE_LINUX_EFAULT;
    capacity = header.count > UINT32_MAX ? UINT32_MAX :
        (uint32_t)header.count;
    backend_capacity = capacity < EDGE_KVM_MAX_REG_ENTRIES ? capacity :
        EDGE_KVM_MAX_REG_ENTRIES;
    status = edge_kvm_facade_vcpu_get_reg_list(
        &g_edge_kvm_facade, vcpu, g_runtime_register_ids,
        backend_capacity, &count);
    if (status < 0) return status;
    header.count = count;
    if (request->copy_to_user(request->copy_context, request->argument,
            &header, sizeof(header)) < 0)
        return -EDGE_LINUX_EFAULT;
    if (capacity < count || count > EDGE_KVM_MAX_REG_ENTRIES)
        return -EDGE_LINUX_E2BIG;
    if (count != 0 && request->copy_to_user(
            request->copy_context, request->argument + sizeof(header),
            g_runtime_register_ids,
            (uint64_t)count * sizeof(g_runtime_register_ids[0])) < 0)
        return -EDGE_LINUX_EFAULT;
    return 0;
}

static uint32_t edge_kvm_runtime_device_attr_size(
        const edge_kvm_device_attr_t *attribute) {
    if (attribute->group == EDGE_KVM_DEVICE_VFIO_FILE_GROUP &&
        (attribute->attribute == EDGE_KVM_DEVICE_VFIO_FILE_ADD ||
         attribute->attribute == EDGE_KVM_DEVICE_VFIO_FILE_DEL))
        return sizeof(int32_t);
    if (attribute->group == EDGE_KVM_DEVICE_ARM_VGIC_GROUP_ADDRESS &&
        (attribute->attribute == EDGE_KVM_DEVICE_ARM_VGIC_ADDRESS_DIST ||
         attribute->attribute == EDGE_KVM_DEVICE_ARM_VGIC_ADDRESS_REDIST))
        return sizeof(uint64_t);
    if (attribute->group == EDGE_KVM_DEVICE_ARM_VGIC_GROUP_NR_IRQS &&
        attribute->attribute == 0)
        return sizeof(uint32_t);
    if (attribute->group == EDGE_KVM_DEVICE_ARM_VGIC_GROUP_DIST_REGS ||
        attribute->group == EDGE_KVM_DEVICE_ARM_VGIC_GROUP_REDIST_REGS ||
        attribute->group == EDGE_KVM_DEVICE_ARM_VGIC_GROUP_LEVEL_INFO)
        return sizeof(uint32_t);
    if (attribute->group == EDGE_KVM_DEVICE_ARM_VGIC_GROUP_CPU_SYSREGS)
        return sizeof(uint64_t);
    if (attribute->group == EDGE_KVM_DEVICE_ARM_VGIC_GROUP_CONTROL &&
        (attribute->attribute == EDGE_KVM_DEVICE_ARM_VGIC_CONTROL_INIT ||
         attribute->attribute ==
             EDGE_KVM_DEVICE_ARM_VGIC_SAVE_PENDING_TABLES))
        return 0;
    return UINT32_MAX;
}

static int edge_kvm_runtime_device_attr(
        const kernel_ioctl_request_t *request, edge_kvm_handle_t device,
        int operation) {
    edge_kvm_device_attr_t attribute;
    uint64_t value = 0;
    uint32_t value_size;
    int status;

    if (!request->argument || !request->copy_from_user)
        return -EDGE_LINUX_EFAULT;
    if (request->copy_from_user(request->copy_context, &attribute,
            request->argument, sizeof(attribute)) < 0)
        return -EDGE_LINUX_EFAULT;
    if (attribute.flags != 0)
        return -EDGE_LINUX_EINVAL;
    if (operation == 2)
        return edge_kvm_facade_device_has_attr(
            &g_edge_kvm_facade, device, &attribute);
    value_size = edge_kvm_runtime_device_attr_size(&attribute);
    if (value_size == UINT32_MAX)
        return -EDGE_LINUX_ENXIO;
    if (value_size != 0 && attribute.address == 0)
        return -EDGE_LINUX_EFAULT;
    if (operation == 0) {
        if (value_size != 0 && request->copy_from_user(
                request->copy_context, &value, attribute.address,
                value_size) < 0)
            return -EDGE_LINUX_EFAULT;
        return edge_kvm_facade_device_set_attr(
            &g_edge_kvm_facade, device, &attribute, &value, value_size);
    }
    if (!request->copy_to_user)
        return -EDGE_LINUX_EFAULT;
    status = edge_kvm_facade_device_get_attr(
        &g_edge_kvm_facade, device, &attribute, &value, value_size);
    if (status < 0) return status;
    if (value_size != 0 && request->copy_to_user(
            request->copy_context, attribute.address, &value,
            value_size) < 0)
        return -EDGE_LINUX_EFAULT;
    return 0;
}

int64_t kernel_edge_kvm_ioctl(const kernel_ioctl_request_t *request) {
    edge_kvm_userspace_memory_region_t region;
    edge_kvm_userspace_memory_region2_t region2;
    edge_kvm_coalesced_mmio_zone_t coalesced_mmio_zone;
    edge_kvm_enable_cap_t enable_cap;
    edge_kvm_pit_config_t pit_config;
    uint64_t identity_map_address;
    edge_kvm_regs_t registers;
    edge_kvm_sregs_t special_registers;
    edge_kvm_sregs2_t special_registers2;
    edge_kvm_fpu_t fpu_state;
    edge_kvm_mp_state_t mp_state;
    edge_kvm_vcpu_events_t vcpu_events;
    edge_kvm_vapic_addr_t vapic_address;
    edge_kvm_debugregs_t debug_registers;
    edge_kvm_guest_debug_x86_t guest_debug;
    edge_kvm_xcrs_t xcrs;
    edge_kvm_irq_level_t irq_level;
    edge_kvm_msi_t msi;
    edge_kvm_irqchip_t irqchip;
    edge_kvm_pit_state2_t pit_state;
    edge_kvm_pit_state_t legacy_pit_state;
    edge_kvm_clock_data_t clock_data;
    edge_kvm_ioeventfd_t ioeventfd;
    edge_kvm_ioeventfd_registration_t ioevent_registration;
    edge_kvm_irqfd_t irqfd;
    edge_kvm_irqfd_registration_t irqfd_registration;
    uint64_t mce_capability;
    uint64_t mce_supported;
    edge_kvm_x86_mce_t machine_check;
    edge_kvm_signal_mask_t signal_mask_header;
    edge_kvm_vcpu_init_t vcpu_init;
    edge_kvm_create_device_t create_device;
    edge_kvm_create_guest_memfd_t guest_memfd;
    edge_kvm_memory_attributes_t memory_attributes;
    edge_kvm_pre_fault_memory_t pre_fault_memory;
    uint64_t signal_mask;
    kernel_edge_kvm_file_t file;
    int32_t rollback_descriptor = -1;
    int64_t result;

    if (!request || !g_descriptor_ops) return -EDGE_LINUX_ENOTTY;
    result = g_descriptor_ops->resolve(
        g_descriptor_context, request->descriptor, &file);
    if (result < 0) return result == -EDGE_LINUX_EBADF ?
        -EDGE_LINUX_ENOTTY : result;

    edge_kvm_runtime_lock();
    if (!g_edge_kvm_facade.initialized) {
        edge_kvm_runtime_unlock();
        return -EDGE_LINUX_ENODEV;
    }
    if (file.kind == KERNEL_EDGE_KVM_FILE_VCPU &&
        request->command == EDGE_KVM_IOCTL_RUN) {
        int release_status;

        result = edge_kvm_facade_descriptor_retain(
            &g_edge_kvm_facade, EDGE_KVM_DESCRIPTOR_VCPU, file.handle);
        edge_kvm_runtime_unlock();
        if (result < 0)
            return result;

        result = edge_kvm_facade_vcpu_ioctl(
            &g_edge_kvm_facade, file.handle, request->command,
            request->argument);

        edge_kvm_runtime_lock();
        release_status = edge_kvm_facade_descriptor_release(
            &g_edge_kvm_facade, EDGE_KVM_DESCRIPTOR_VCPU, file.handle);
        edge_kvm_runtime_unlock();
        if (result == 0 && release_status < 0)
            result = release_status;
        return result;
    }
    if (file.kind == KERNEL_EDGE_KVM_FILE_SYSTEM) {
        if (request->command == EDGE_KVM_IOCTL_GET_STATS_FD)
            result = -EDGE_LINUX_EINVAL;
        else if (request->command == EDGE_KVM_IOCTL_GET_SUPPORTED_CPUID)
            result = edge_kvm_runtime_get_supported_cpuid(request);
        else if (request->command == EDGE_KVM_IOCTL_GET_EMULATED_CPUID)
            result = edge_kvm_runtime_get_emulated_cpuid(request);
        else if (request->command == EDGE_KVM_IOCTL_GET_MSR_INDEX_LIST)
            result = edge_kvm_runtime_get_msr_index_list(request, 0);
        else if (request->command ==
                 EDGE_KVM_IOCTL_GET_MSR_FEATURE_INDEX_LIST)
            result = edge_kvm_runtime_get_msr_index_list(request, 1);
        else if (request->command == EDGE_KVM_IOCTL_GET_MSRS)
            result = edge_kvm_runtime_feature_msrs(request);
        else if (request->command ==
                 EDGE_KVM_IOCTL_X86_GET_MCE_CAP_SUPPORTED) {
            result = edge_kvm_facade_get_mce_cap_supported(
                &g_edge_kvm_facade, &mce_supported);
            if (result == 0 &&
                (!request->argument || !request->copy_to_user ||
                 request->copy_to_user(
                     request->copy_context, request->argument,
                     &mce_supported, sizeof(mce_supported)) < 0))
                result = -EDGE_LINUX_EFAULT;
        }
        else if (edge_kvm_system_command_known_unsupported(
                     request->command))
            result = -EDGE_LINUX_EOPNOTSUPP;
        else
            result = edge_kvm_facade_system_ioctl(
                &g_edge_kvm_facade, request->command, request->argument);
    } else if (file.kind == KERNEL_EDGE_KVM_FILE_VM) {
        if (request->command == EDGE_KVM_IOCTL_CREATE_GUEST_MEMFD) {
            if (!request->argument || !request->copy_from_user ||
                request->copy_from_user(
                    request->copy_context, &guest_memfd,
                    request->argument, sizeof(guest_memfd)) < 0) {
                result = -EDGE_LINUX_EFAULT;
            } else if (!guest_memfd.size ||
                       (guest_memfd.size & (EDGE_KVM_PAGE_SIZE - 1u)) != 0 ||
                       guest_memfd.flags != 0) {
                result = -EDGE_LINUX_EINVAL;
            } else {
                result = g_descriptor_ops->install_guest_memfd(
                    g_descriptor_context, guest_memfd.size);
            }
        } else if (request->command == EDGE_KVM_IOCTL_SET_MEMORY_ATTRIBUTES) {
            if (!request->argument || !request->copy_from_user ||
                request->copy_from_user(
                    request->copy_context, &memory_attributes,
                    request->argument, sizeof(memory_attributes)) < 0) {
                result = -EDGE_LINUX_EFAULT;
            } else if (!memory_attributes.size || memory_attributes.flags ||
                       (memory_attributes.address &
                        (EDGE_KVM_PAGE_SIZE - 1u)) != 0 ||
                       (memory_attributes.size &
                        (EDGE_KVM_PAGE_SIZE - 1u)) != 0 ||
                       memory_attributes.address >
                           UINT64_MAX - memory_attributes.size) {
                result = -EDGE_LINUX_EINVAL;
            } else if (memory_attributes.attributes != 0) {
                result = -EDGE_LINUX_EOPNOTSUPP;
            } else {
                result = 0;
            }
        } else if (request->command == EDGE_KVM_IOCTL_CREATE_DEVICE) {
            if (!request->argument || !request->copy_from_user ||
                !request->copy_to_user || request->copy_from_user(
                    request->copy_context, &create_device,
                    request->argument, sizeof(create_device)) < 0) {
                result = -EDGE_LINUX_EFAULT;
            } else {
                if (create_device.flags == EDGE_KVM_CREATE_DEVICE_TEST) {
                    result = edge_kvm_facade_device_test(
                        &g_edge_kvm_facade, file.handle,
                        create_device.type);
                    if (result == 0 && request->copy_to_user(
                            request->copy_context, request->argument,
                            &create_device, sizeof(create_device)) < 0)
                        result = -EDGE_LINUX_EFAULT;
                } else if (create_device.flags != 0) {
                    result = -EDGE_LINUX_EINVAL;
                } else {
                    result = edge_kvm_facade_device_create(
                        &g_edge_kvm_facade, file.handle,
                        create_device.type, 0);
                }
                if (result >= 0 && create_device.flags == 0) {
                    create_device.descriptor = (uint32_t)result;
                    if (request->copy_to_user(
                            request->copy_context, request->argument,
                            &create_device, sizeof(create_device)) < 0) {
                        rollback_descriptor = (int32_t)result;
                        result = -EDGE_LINUX_EFAULT;
                    } else {
                        result = 0;
                    }
                }
            }
        } else if (request->command == EDGE_KVM_IOCTL_ARM_PREFERRED_TARGET) {
            result = edge_kvm_facade_vm_get_preferred_target(
                &g_edge_kvm_facade, file.handle, &vcpu_init);
            if (result == 0 &&
                (!request->argument || !request->copy_to_user ||
                 request->copy_to_user(
                     request->copy_context, request->argument,
                     &vcpu_init, sizeof(vcpu_init)) < 0))
                result = -EDGE_LINUX_EFAULT;
        } else if (request->command == EDGE_KVM_IOCTL_GET_IRQCHIP) {
            if (!request->argument || !request->copy_from_user ||
                !request->copy_to_user ||
                request->copy_from_user(
                    request->copy_context, &irqchip,
                    request->argument, sizeof(irqchip)) < 0) {
                result = -EDGE_LINUX_EFAULT;
            } else {
                result = edge_kvm_facade_vm_get_irqchip(
                    &g_edge_kvm_facade, file.handle, &irqchip);
                if (result == 0 && request->copy_to_user(
                        request->copy_context, request->argument,
                        &irqchip, sizeof(irqchip)) < 0)
                    result = -EDGE_LINUX_EFAULT;
            }
        } else if (request->command == EDGE_KVM_IOCTL_SET_IRQCHIP) {
            if (!request->argument || !request->copy_from_user ||
                request->copy_from_user(
                    request->copy_context, &irqchip,
                    request->argument, sizeof(irqchip)) < 0) {
                result = -EDGE_LINUX_EFAULT;
            } else {
                result = edge_kvm_facade_vm_set_irqchip(
                    &g_edge_kvm_facade, file.handle, &irqchip);
            }
        } else if (request->command == EDGE_KVM_IOCTL_CREATE_PIT) {
            pit_config.flags = 0;
            for (uint32_t index = 0;
                 index < sizeof(pit_config.padding) /
                     sizeof(pit_config.padding[0]); ++index)
                pit_config.padding[index] = 0;
            result = edge_kvm_facade_vm_ioctl(
                &g_edge_kvm_facade, file.handle,
                EDGE_KVM_IOCTL_CREATE_PIT2,
                (uint64_t)(uintptr_t)&pit_config);
        } else if (request->command == EDGE_KVM_IOCTL_GET_PIT) {
            result = edge_kvm_facade_vm_get_pit(
                &g_edge_kvm_facade, file.handle, &pit_state);
            if (result == 0) {
                for (uint32_t index = 0; index < 3u; ++index)
                    legacy_pit_state.channels[index] =
                        pit_state.channels[index];
                if (!request->argument || !request->copy_to_user ||
                    request->copy_to_user(
                        request->copy_context, request->argument,
                        &legacy_pit_state,
                        sizeof(legacy_pit_state)) < 0)
                    result = -EDGE_LINUX_EFAULT;
            }
        } else if (request->command == EDGE_KVM_IOCTL_SET_PIT) {
            if (!request->argument || !request->copy_from_user ||
                request->copy_from_user(
                    request->copy_context, &legacy_pit_state,
                    request->argument, sizeof(legacy_pit_state)) < 0) {
                result = -EDGE_LINUX_EFAULT;
            } else {
                for (uint32_t index = 0; index < 3u; ++index)
                    pit_state.channels[index] =
                        legacy_pit_state.channels[index];
                pit_state.flags = 0;
                for (uint32_t index = 0;
                     index < sizeof(pit_state.reserved) /
                         sizeof(pit_state.reserved[0]); ++index)
                    pit_state.reserved[index] = 0;
                result = edge_kvm_facade_vm_set_pit(
                    &g_edge_kvm_facade, file.handle, &pit_state);
            }
        } else if (request->command == EDGE_KVM_IOCTL_GET_PIT2) {
            result = edge_kvm_facade_vm_get_pit(
                &g_edge_kvm_facade, file.handle, &pit_state);
            if (result == 0 &&
                (!request->argument || !request->copy_to_user ||
                 request->copy_to_user(
                    request->copy_context, request->argument,
                    &pit_state, sizeof(pit_state)) < 0))
                result = -EDGE_LINUX_EFAULT;
        } else if (request->command == EDGE_KVM_IOCTL_SET_PIT2) {
            if (!request->argument || !request->copy_from_user ||
                request->copy_from_user(
                    request->copy_context, &pit_state,
                    request->argument, sizeof(pit_state)) < 0) {
                result = -EDGE_LINUX_EFAULT;
            } else {
                result = edge_kvm_facade_vm_set_pit(
                    &g_edge_kvm_facade, file.handle, &pit_state);
            }
        } else if (request->command == EDGE_KVM_IOCTL_GET_CLOCK) {
            result = edge_kvm_facade_vm_get_clock(
                &g_edge_kvm_facade, file.handle, &clock_data);
            if (result == 0 &&
                (!request->argument || !request->copy_to_user ||
                 request->copy_to_user(
                    request->copy_context, request->argument,
                    &clock_data, sizeof(clock_data)) < 0))
                result = -EDGE_LINUX_EFAULT;
        } else if (request->command == EDGE_KVM_IOCTL_SET_CLOCK) {
            if (!request->argument || !request->copy_from_user ||
                request->copy_from_user(
                    request->copy_context, &clock_data,
                    request->argument, sizeof(clock_data)) < 0) {
                result = -EDGE_LINUX_EFAULT;
            } else {
                result = edge_kvm_facade_vm_set_clock(
                    &g_edge_kvm_facade, file.handle, &clock_data);
            }
        } else if (request->command == EDGE_KVM_IOCTL_IOEVENTFD) {
            if (!request->argument || !request->copy_from_user ||
                request->copy_from_user(
                    request->copy_context, &ioeventfd,
                    request->argument, sizeof(ioeventfd)) < 0) {
                result = -EDGE_LINUX_EFAULT;
            } else if (!edge_kvm_runtime_padding_is_zero(
                           ioeventfd.padding, sizeof(ioeventfd.padding))) {
                result = -EDGE_LINUX_EINVAL;
            } else {
                ioevent_registration.datamatch = ioeventfd.datamatch;
                ioevent_registration.address = ioeventfd.address;
                ioevent_registration.length = ioeventfd.length;
                ioevent_registration.flags = ioeventfd.flags;
                ioevent_registration.event_id = -1;
                if ((ioeventfd.flags &
                     EDGE_KVM_IOEVENTFD_FLAG_DEASSIGN) == 0) {
                    ioevent_registration.event_id =
                        kernel_anonymous_fd_descriptor_object_id(
                            ioeventfd.descriptor,
                            KERNEL_ANONYMOUS_FD_EVENT);
                    if (ioevent_registration.event_id < 0) {
                        result = -EDGE_LINUX_EBADF;
                        goto vm_ioctl_done;
                    }
                    result = kernel_eventfd_retain(
                        ioevent_registration.event_id);
                    if (result < 0) goto vm_ioctl_done;
                }
                result = edge_kvm_facade_vm_ioeventfd(
                    &g_edge_kvm_facade, file.handle,
                    &ioevent_registration);
                if (result < 0 && ioevent_registration.event_id >= 0)
                    kernel_eventfd_release(ioevent_registration.event_id);
            }
        } else if (request->command == EDGE_KVM_IOCTL_IRQFD) {
            if (!request->argument || !request->copy_from_user ||
                request->copy_from_user(
                    request->copy_context, &irqfd,
                    request->argument, sizeof(irqfd)) < 0) {
                result = -EDGE_LINUX_EFAULT;
            } else if (!edge_kvm_runtime_padding_is_zero(
                           irqfd.padding, sizeof(irqfd.padding))) {
                result = -EDGE_LINUX_EINVAL;
            } else {
                irqfd_registration.event_id =
                    kernel_anonymous_fd_descriptor_object_id(
                        (int32_t)irqfd.descriptor,
                        KERNEL_ANONYMOUS_FD_EVENT);
                irqfd_registration.gsi = irqfd.gsi;
                irqfd_registration.flags = irqfd.flags;
                irqfd_registration.resample_event_id = -1;
                if (irqfd_registration.event_id < 0) {
                    result = -EDGE_LINUX_EBADF;
                    goto vm_ioctl_done;
                }
                if ((irqfd.flags & EDGE_KVM_IRQFD_FLAG_RESAMPLE) != 0) {
                    irqfd_registration.resample_event_id =
                        kernel_anonymous_fd_descriptor_object_id(
                            (int32_t)irqfd.resample_descriptor,
                            KERNEL_ANONYMOUS_FD_EVENT);
                    if (irqfd_registration.resample_event_id < 0) {
                        result = -EDGE_LINUX_EBADF;
                        goto vm_ioctl_done;
                    }
                }
                if ((irqfd.flags & EDGE_KVM_IRQFD_FLAG_DEASSIGN) == 0) {
                    result = kernel_eventfd_retain(
                        irqfd_registration.event_id);
                    if (result < 0) goto vm_ioctl_done;
                    if (irqfd_registration.resample_event_id >= 0) {
                        result = kernel_eventfd_retain(
                            irqfd_registration.resample_event_id);
                        if (result < 0) {
                            kernel_eventfd_release(
                                irqfd_registration.event_id);
                            goto vm_ioctl_done;
                        }
                    }
                }
                result = edge_kvm_facade_vm_irqfd(
                    &g_edge_kvm_facade, file.handle,
                    &irqfd_registration);
                if (result < 0 &&
                    (irqfd.flags & EDGE_KVM_IRQFD_FLAG_DEASSIGN) == 0) {
                    kernel_eventfd_release(irqfd_registration.event_id);
                    if (irqfd_registration.resample_event_id >= 0)
                        kernel_eventfd_release(
                            irqfd_registration.resample_event_id);
                }
            }
        } else if (request->command == EDGE_KVM_IOCTL_SET_GSI_ROUTING) {
            result = edge_kvm_runtime_set_gsi_routing(
                request, file.handle);
        } else if (request->command == EDGE_KVM_IOCTL_IRQ_LINE ||
                   request->command == EDGE_KVM_IOCTL_IRQ_LINE_STATUS) {
            if (!request->argument || !request->copy_from_user ||
                request->copy_from_user(
                    request->copy_context, &irq_level,
                    request->argument, sizeof(irq_level)) < 0) {
                result = -EDGE_LINUX_EFAULT;
            } else {
                result = edge_kvm_facade_vm_set_irq_line(
                    &g_edge_kvm_facade, file.handle, &irq_level);
                if (result == 0 &&
                    request->command == EDGE_KVM_IOCTL_IRQ_LINE_STATUS &&
                    (!request->copy_to_user ||
                     request->copy_to_user(
                        request->copy_context, request->argument,
                        &irq_level, sizeof(irq_level)) < 0))
                    result = -EDGE_LINUX_EFAULT;
            }
        } else if (request->command == EDGE_KVM_IOCTL_SIGNAL_MSI) {
            if (!request->argument || !request->copy_from_user ||
                request->copy_from_user(
                    request->copy_context, &msi,
                    request->argument, sizeof(msi)) < 0) {
                result = -EDGE_LINUX_EFAULT;
            } else {
                result = edge_kvm_facade_vm_signal_msi(
                    &g_edge_kvm_facade, file.handle, &msi);
            }
        } else if (request->command == EDGE_KVM_IOCTL_SET_USER_MEMORY_REGION) {
            result = edge_kvm_copy_memory_region(request, &region);
            if (result == 0)
                result = edge_kvm_facade_vm_set_memory_region(
                    &g_edge_kvm_facade, file.handle, &region);
        } else if (request->command ==
                   EDGE_KVM_IOCTL_SET_USER_MEMORY_REGION2) {
            if (!request->argument || !request->copy_from_user ||
                request->copy_from_user(
                    request->copy_context, &region2, request->argument,
                    sizeof(region2)) < 0) {
                result = -EDGE_LINUX_EFAULT;
            } else if (region2.pad1 != 0 ||
                       !edge_kvm_runtime_padding_is_zero(
                           (const uint8_t *)region2.pad2,
                           sizeof(region2.pad2))) {
                result = -EDGE_LINUX_EINVAL;
            } else if ((region2.flags & EDGE_KVM_MEMORY_GUEST_MEMFD) != 0) {
                result = -EDGE_LINUX_EOPNOTSUPP;
            } else {
                region.slot = region2.slot;
                region.flags = region2.flags;
                region.guest_physical_address = region2.guest_phys_addr;
                region.memory_size = region2.memory_size;
                region.userspace_address = region2.userspace_addr;
                result = edge_kvm_facade_vm_set_memory_region(
                    &g_edge_kvm_facade, file.handle, &region);
            }
        } else if (request->command ==
                       EDGE_KVM_IOCTL_REGISTER_COALESCED_MMIO ||
                   request->command ==
                       EDGE_KVM_IOCTL_UNREGISTER_COALESCED_MMIO) {
            if (!request->argument || !request->copy_from_user ||
                request->copy_from_user(
                    request->copy_context, &coalesced_mmio_zone,
                    request->argument, sizeof(coalesced_mmio_zone)) < 0) {
                result = -EDGE_LINUX_EFAULT;
            } else {
                result = edge_kvm_facade_vm_coalesced_mmio(
                    &g_edge_kvm_facade, file.handle,
                    &coalesced_mmio_zone,
                    request->command ==
                        EDGE_KVM_IOCTL_UNREGISTER_COALESCED_MMIO);
            }
        } else if (request->command == EDGE_KVM_IOCTL_GET_DIRTY_LOG) {
            result = edge_kvm_runtime_get_dirty_log(request, file.handle);
        } else if (request->command == EDGE_KVM_IOCTL_CLEAR_DIRTY_LOG) {
            result = edge_kvm_runtime_clear_dirty_log(request, file.handle);
        } else if (request->command == EDGE_KVM_IOCTL_ENABLE_CAP) {
            if (!request->argument || !request->copy_from_user ||
                request->copy_from_user(
                    request->copy_context, &enable_cap,
                    request->argument, sizeof(enable_cap)) < 0) {
                result = -EDGE_LINUX_EFAULT;
            } else {
                result = edge_kvm_facade_vm_enable_cap(
                    &g_edge_kvm_facade, file.handle, &enable_cap);
            }
        } else if (request->command ==
                   EDGE_KVM_IOCTL_SET_IDENTITY_MAP_ADDR) {
            if (!request->argument || !request->copy_from_user ||
                request->copy_from_user(
                    request->copy_context, &identity_map_address,
                    request->argument, sizeof(identity_map_address)) < 0) {
                result = -EDGE_LINUX_EFAULT;
            } else {
                result = edge_kvm_facade_vm_ioctl(
                    &g_edge_kvm_facade, file.handle, request->command,
                    (uint64_t)(uintptr_t)&identity_map_address);
            }
        } else if (request->command == EDGE_KVM_IOCTL_CREATE_PIT2) {
            if (!request->argument || !request->copy_from_user ||
                request->copy_from_user(
                    request->copy_context, &pit_config,
                    request->argument, sizeof(pit_config)) < 0) {
                result = -EDGE_LINUX_EFAULT;
            } else {
                result = edge_kvm_facade_vm_ioctl(
                    &g_edge_kvm_facade, file.handle, request->command,
                    (uint64_t)(uintptr_t)&pit_config);
            }
        } else if (request->command == EDGE_KVM_IOCTL_GET_STATS_FD) {
            result = edge_kvm_runtime_install_stats(
                KERNEL_EDGE_KVM_FILE_VM, file.handle);
        } else if (edge_kvm_vm_command_known_unsupported(
                       request->command)) {
            result = -EDGE_LINUX_EOPNOTSUPP;
        } else {
            result = edge_kvm_facade_vm_ioctl(
                &g_edge_kvm_facade, file.handle, request->command,
                request->argument);
        }
vm_ioctl_done:
        ;
    } else if (file.kind == KERNEL_EDGE_KVM_FILE_VCPU) {
        if (request->command == EDGE_KVM_IOCTL_NMI) {
            result = edge_kvm_facade_vcpu_get_events(
                &g_edge_kvm_facade, file.handle, &vcpu_events);
            if (result == 0) {
                vcpu_events.nmi.pending = 1;
                vcpu_events.flags |= EDGE_KVM_VCPUEVENT_VALID_NMI_PENDING;
                result = edge_kvm_facade_vcpu_set_events(
                    &g_edge_kvm_facade, file.handle, &vcpu_events);
            }
        } else if (request->command == EDGE_KVM_IOCTL_INTERRUPT) {
            edge_kvm_interrupt_t interrupt;
            if (!request->argument || !request->copy_from_user ||
                request->copy_from_user(
                    request->copy_context, &interrupt, request->argument,
                    sizeof(interrupt)) < 0) {
                result = -EDGE_LINUX_EFAULT;
            } else if (interrupt.irq < 16u || interrupt.irq > UINT8_MAX) {
                result = -EDGE_LINUX_EINVAL;
            } else {
                result = edge_kvm_facade_vcpu_get_events(
                    &g_edge_kvm_facade, file.handle, &vcpu_events);
                if (result == 0) {
                    vcpu_events.interrupt.injected = 1;
                    vcpu_events.interrupt.number = (uint8_t)interrupt.irq;
                    result = edge_kvm_facade_vcpu_set_events(
                        &g_edge_kvm_facade, file.handle, &vcpu_events);
                }
            }
        } else if (request->command == EDGE_KVM_IOCTL_ARM_VCPU_INIT) {
            if (!request->argument || !request->copy_from_user ||
                request->copy_from_user(
                    request->copy_context, &vcpu_init,
                    request->argument, sizeof(vcpu_init)) < 0) {
                result = -EDGE_LINUX_EFAULT;
            } else {
                result = edge_kvm_facade_vcpu_init(
                    &g_edge_kvm_facade, file.handle, &vcpu_init);
            }
        } else if (request->command == EDGE_KVM_IOCTL_GET_ONE_REG) {
            result = edge_kvm_runtime_one_reg(request, file.handle, 0);
        } else if (request->command == EDGE_KVM_IOCTL_SET_ONE_REG) {
            result = edge_kvm_runtime_one_reg(request, file.handle, 1);
        } else if (request->command == EDGE_KVM_IOCTL_GET_REG_LIST) {
            result = edge_kvm_runtime_get_reg_list(request, file.handle);
        } else if (request->command == EDGE_KVM_IOCTL_SET_SIGNAL_MASK) {
            if (!request->argument || !request->copy_from_user ||
                request->copy_from_user(
                    request->copy_context, &signal_mask_header,
                    request->argument, sizeof(signal_mask_header)) < 0) {
                result = -EDGE_LINUX_EFAULT;
            } else if (signal_mask_header.length != sizeof(signal_mask)) {
                result = -EDGE_LINUX_EINVAL;
            } else if (request->copy_from_user(
                           request->copy_context, &signal_mask,
                           request->argument + sizeof(signal_mask_header),
                           sizeof(signal_mask)) < 0) {
                result = -EDGE_LINUX_EFAULT;
            } else {
                result = edge_kvm_facade_vcpu_set_signal_mask(
                    &g_edge_kvm_facade, file.handle, signal_mask);
            }
        } else if (request->command == EDGE_KVM_IOCTL_SET_MSRS) {
            result = edge_kvm_runtime_msrs(request, file.handle, 1);
        } else if (request->command == EDGE_KVM_IOCTL_GET_MSRS) {
            result = edge_kvm_runtime_msrs(request, file.handle, 0);
        } else if (request->command == EDGE_KVM_IOCTL_SET_MP_STATE) {
            if (!request->argument || !request->copy_from_user ||
                request->copy_from_user(
                    request->copy_context, &mp_state, request->argument,
                    sizeof(mp_state)) < 0) {
                result = -EDGE_LINUX_EFAULT;
            } else {
                result = edge_kvm_facade_vcpu_set_mp_state(
                    &g_edge_kvm_facade, file.handle, &mp_state);
            }
        } else if (request->command == EDGE_KVM_IOCTL_GET_MP_STATE) {
            result = edge_kvm_facade_vcpu_get_mp_state(
                &g_edge_kvm_facade, file.handle, &mp_state);
            if (result == 0 &&
                (!request->argument || !request->copy_to_user ||
                 request->copy_to_user(
                    request->copy_context, request->argument, &mp_state,
                    sizeof(mp_state)) < 0))
                result = -EDGE_LINUX_EFAULT;
        } else if (request->command == EDGE_KVM_IOCTL_SET_VCPU_EVENTS) {
            if (!request->argument || !request->copy_from_user ||
                request->copy_from_user(
                    request->copy_context, &vcpu_events,
                    request->argument, sizeof(vcpu_events)) < 0) {
                result = -EDGE_LINUX_EFAULT;
            } else {
                result = edge_kvm_facade_vcpu_set_events(
                    &g_edge_kvm_facade, file.handle, &vcpu_events);
            }
        } else if (request->command == EDGE_KVM_IOCTL_GET_VCPU_EVENTS) {
            result = edge_kvm_facade_vcpu_get_events(
                &g_edge_kvm_facade, file.handle, &vcpu_events);
            if (result == 0 &&
                (!request->argument || !request->copy_to_user ||
                 request->copy_to_user(
                    request->copy_context, request->argument, &vcpu_events,
                    sizeof(vcpu_events)) < 0))
                result = -EDGE_LINUX_EFAULT;
        } else if (request->command == EDGE_KVM_IOCTL_SET_VAPIC_ADDR) {
            if (!request->argument || !request->copy_from_user ||
                request->copy_from_user(
                    request->copy_context, &vapic_address,
                    request->argument, sizeof(vapic_address)) < 0) {
                result = -EDGE_LINUX_EFAULT;
            } else {
                result = edge_kvm_facade_vcpu_set_vapic_address(
                    &g_edge_kvm_facade, file.handle,
                    vapic_address.vapic_addr);
            }
        } else if (request->command == EDGE_KVM_IOCTL_GET_TSC_KHZ) {
            result = edge_kvm_facade_vcpu_get_tsc_khz(
                &g_edge_kvm_facade, file.handle);
        } else if (request->command == EDGE_KVM_IOCTL_SET_TSC_KHZ) {
            result = edge_kvm_facade_vcpu_set_tsc_khz(
                &g_edge_kvm_facade, file.handle,
                (uint32_t)request->argument);
        } else if (request->command == EDGE_KVM_IOCTL_X86_SETUP_MCE) {
            if (!request->argument || !request->copy_from_user ||
                request->copy_from_user(
                    request->copy_context, &mce_capability,
                    request->argument, sizeof(mce_capability)) < 0) {
                result = -EDGE_LINUX_EFAULT;
            } else {
                result = edge_kvm_facade_vcpu_setup_mce(
                    &g_edge_kvm_facade, file.handle, mce_capability);
            }
        } else if (request->command == EDGE_KVM_IOCTL_X86_SET_MCE) {
            if (!request->argument || !request->copy_from_user ||
                request->copy_from_user(
                    request->copy_context, &machine_check,
                    request->argument, sizeof(machine_check)) < 0) {
                result = -EDGE_LINUX_EFAULT;
            } else {
                result = edge_kvm_facade_vcpu_set_mce(
                    &g_edge_kvm_facade, file.handle, &machine_check);
            }
        } else if (request->command == EDGE_KVM_IOCTL_SET_REGS) {
            if (!request->argument || !request->copy_from_user ||
                request->copy_from_user(
                    request->copy_context, &registers, request->argument,
                    sizeof(registers)) < 0) {
                result = -EDGE_LINUX_EFAULT;
            } else {
                result = edge_kvm_facade_vcpu_set_regs(
                    &g_edge_kvm_facade, file.handle, &registers);
            }
        } else if (request->command == EDGE_KVM_IOCTL_GET_REGS) {
            result = edge_kvm_facade_vcpu_get_regs(
                &g_edge_kvm_facade, file.handle, &registers);
            if (result == 0 &&
                (!request->argument || !request->copy_to_user ||
                 request->copy_to_user(
                    request->copy_context, request->argument, &registers,
                    sizeof(registers)) < 0))
                result = -EDGE_LINUX_EFAULT;
        } else if (request->command == EDGE_KVM_IOCTL_SET_SREGS) {
            if (!request->argument || !request->copy_from_user ||
                request->copy_from_user(
                    request->copy_context, &special_registers,
                    request->argument, sizeof(special_registers)) < 0) {
                result = -EDGE_LINUX_EFAULT;
            } else {
                result = edge_kvm_facade_vcpu_set_sregs(
                    &g_edge_kvm_facade, file.handle, &special_registers);
            }
        } else if (request->command == EDGE_KVM_IOCTL_GET_SREGS) {
            result = edge_kvm_facade_vcpu_get_sregs(
                &g_edge_kvm_facade, file.handle, &special_registers);
            if (result == 0 &&
                (!request->argument || !request->copy_to_user ||
                 request->copy_to_user(
                    request->copy_context, request->argument,
                    &special_registers, sizeof(special_registers)) < 0))
                result = -EDGE_LINUX_EFAULT;
        } else if (request->command == EDGE_KVM_IOCTL_SET_SREGS2) {
            if (!request->argument || !request->copy_from_user ||
                request->copy_from_user(
                    request->copy_context, &special_registers2,
                    request->argument, sizeof(special_registers2)) < 0) {
                result = -EDGE_LINUX_EFAULT;
            } else {
                result = edge_kvm_facade_vcpu_set_sregs2(
                    &g_edge_kvm_facade, file.handle,
                    &special_registers2);
            }
        } else if (request->command == EDGE_KVM_IOCTL_GET_SREGS2) {
            result = edge_kvm_facade_vcpu_get_sregs2(
                &g_edge_kvm_facade, file.handle, &special_registers2);
            if (result == 0 &&
                (!request->argument || !request->copy_to_user ||
                 request->copy_to_user(
                    request->copy_context, request->argument,
                    &special_registers2,
                    sizeof(special_registers2)) < 0))
                result = -EDGE_LINUX_EFAULT;
        } else if (request->command == EDGE_KVM_IOCTL_SET_FPU) {
            if (!request->argument || !request->copy_from_user ||
                request->copy_from_user(
                    request->copy_context, &fpu_state,
                    request->argument, sizeof(fpu_state)) < 0) {
                result = -EDGE_LINUX_EFAULT;
            } else {
                result = edge_kvm_facade_vcpu_set_fpu(
                    &g_edge_kvm_facade, file.handle, &fpu_state);
            }
        } else if (request->command == EDGE_KVM_IOCTL_GET_FPU) {
            result = edge_kvm_facade_vcpu_get_fpu(
                &g_edge_kvm_facade, file.handle, &fpu_state);
            if (result == 0 &&
                (!request->argument || !request->copy_to_user ||
                 request->copy_to_user(
                    request->copy_context, request->argument,
                    &fpu_state, sizeof(fpu_state)) < 0))
                result = -EDGE_LINUX_EFAULT;
        } else if (request->command == EDGE_KVM_IOCTL_SET_LAPIC) {
            if (!request->argument || !request->copy_from_user ||
                request->copy_from_user(
                    request->copy_context, &g_runtime_lapic_state,
                    request->argument, sizeof(g_runtime_lapic_state)) < 0) {
                result = -EDGE_LINUX_EFAULT;
            } else {
                result = edge_kvm_facade_vcpu_set_lapic(
                    &g_edge_kvm_facade, file.handle,
                    &g_runtime_lapic_state);
            }
        } else if (request->command == EDGE_KVM_IOCTL_GET_LAPIC) {
            result = edge_kvm_facade_vcpu_get_lapic(
                &g_edge_kvm_facade, file.handle, &g_runtime_lapic_state);
            if (result == 0 &&
                (!request->argument || !request->copy_to_user ||
                 request->copy_to_user(
                    request->copy_context, request->argument,
                    &g_runtime_lapic_state,
                    sizeof(g_runtime_lapic_state)) < 0))
                result = -EDGE_LINUX_EFAULT;
        } else if (request->command == EDGE_KVM_IOCTL_SET_DEBUGREGS) {
            if (!request->argument || !request->copy_from_user ||
                request->copy_from_user(
                    request->copy_context, &debug_registers,
                    request->argument, sizeof(debug_registers)) < 0) {
                result = -EDGE_LINUX_EFAULT;
            } else {
                result = edge_kvm_facade_vcpu_set_debugregs(
                    &g_edge_kvm_facade, file.handle, &debug_registers);
            }
        } else if (request->command == EDGE_KVM_IOCTL_GET_DEBUGREGS) {
            result = edge_kvm_facade_vcpu_get_debugregs(
                &g_edge_kvm_facade, file.handle, &debug_registers);
            if (result == 0 &&
                (!request->argument || !request->copy_to_user ||
                 request->copy_to_user(
                    request->copy_context, request->argument,
                    &debug_registers, sizeof(debug_registers)) < 0))
                result = -EDGE_LINUX_EFAULT;
        } else if (request->command == EDGE_KVM_IOCTL_SET_GUEST_DEBUG_X86) {
            if (!request->argument || !request->copy_from_user ||
                request->copy_from_user(
                    request->copy_context, &guest_debug,
                    request->argument, sizeof(guest_debug)) < 0) {
                result = -EDGE_LINUX_EFAULT;
            } else {
                result = edge_kvm_facade_vcpu_set_guest_debug(
                    &g_edge_kvm_facade, file.handle, &guest_debug);
            }
        } else if (request->command == EDGE_KVM_IOCTL_SET_XCRS) {
            if (!request->argument || !request->copy_from_user ||
                request->copy_from_user(
                    request->copy_context, &xcrs,
                    request->argument, sizeof(xcrs)) < 0) {
                result = -EDGE_LINUX_EFAULT;
            } else {
                result = edge_kvm_facade_vcpu_set_xcrs(
                    &g_edge_kvm_facade, file.handle, &xcrs);
            }
        } else if (request->command == EDGE_KVM_IOCTL_GET_XCRS) {
            result = edge_kvm_facade_vcpu_get_xcrs(
                &g_edge_kvm_facade, file.handle, &xcrs);
            if (result == 0 &&
                (!request->argument || !request->copy_to_user ||
                 request->copy_to_user(
                    request->copy_context, request->argument,
                    &xcrs, sizeof(xcrs)) < 0))
                result = -EDGE_LINUX_EFAULT;
        } else if (request->command == EDGE_KVM_IOCTL_SET_XSAVE) {
            if (!request->argument || !request->copy_from_user ||
                request->copy_from_user(
                    request->copy_context, &g_runtime_xsave_state,
                    request->argument,
                    sizeof(g_runtime_xsave_state)) < 0) {
                result = -EDGE_LINUX_EFAULT;
            } else {
                result = edge_kvm_facade_vcpu_set_xsave(
                    &g_edge_kvm_facade, file.handle,
                    &g_runtime_xsave_state);
            }
        } else if (request->command == EDGE_KVM_IOCTL_GET_XSAVE ||
                   request->command == EDGE_KVM_IOCTL_GET_XSAVE2) {
            result = edge_kvm_facade_vcpu_get_xsave(
                &g_edge_kvm_facade, file.handle, &g_runtime_xsave_state);
            if (result == 0 &&
                (!request->argument || !request->copy_to_user ||
                 request->copy_to_user(
                    request->copy_context, request->argument,
                    &g_runtime_xsave_state,
                    sizeof(g_runtime_xsave_state)) < 0))
                result = -EDGE_LINUX_EFAULT;
        } else if (request->command == EDGE_KVM_IOCTL_SET_CPUID2) {
            result = edge_kvm_runtime_set_cpuid2(request, file.handle);
        } else if (request->command == EDGE_KVM_IOCTL_GET_CPUID2) {
            result = edge_kvm_runtime_get_cpuid2(request, file.handle);
        } else if (request->command == EDGE_KVM_IOCTL_SET_CPUID) {
            result = edge_kvm_runtime_set_cpuid(request, file.handle);
        } else if (request->command == EDGE_KVM_IOCTL_GET_STATS_FD) {
            result = edge_kvm_runtime_install_stats(
                KERNEL_EDGE_KVM_FILE_VCPU, file.handle);
        } else if (request->command == EDGE_KVM_IOCTL_PRE_FAULT_MEMORY) {
            if (!request->argument || !request->copy_from_user ||
                !request->copy_to_user || request->copy_from_user(
                    request->copy_context, &pre_fault_memory,
                    request->argument, sizeof(pre_fault_memory)) < 0) {
                result = -EDGE_LINUX_EFAULT;
            } else {
                result = edge_kvm_facade_vcpu_pre_fault_memory(
                    &g_edge_kvm_facade, file.handle, &pre_fault_memory);
                if (result == 0 && request->copy_to_user(
                        request->copy_context, request->argument,
                        &pre_fault_memory, sizeof(pre_fault_memory)) < 0)
                    result = -EDGE_LINUX_EFAULT;
            }
        } else if (request->command == EDGE_KVM_IOCTL_TRANSLATE) {
            edge_kvm_translation_t translation;

            if (!request->argument || !request->copy_from_user ||
                !request->copy_to_user || request->copy_from_user(
                    request->copy_context, &translation,
                    request->argument, sizeof(translation)) < 0) {
                result = -EDGE_LINUX_EFAULT;
            } else {
                result = edge_kvm_facade_vcpu_translate(
                    &g_edge_kvm_facade, file.handle, &translation);
                if (result == 0 && request->copy_to_user(
                        request->copy_context, request->argument,
                        &translation, sizeof(translation)) < 0)
                    result = -EDGE_LINUX_EFAULT;
            }
        } else if (edge_kvm_vcpu_command_known_unsupported(
                       request->command)) {
            result = -EDGE_LINUX_EOPNOTSUPP;
        } else {
            result = edge_kvm_facade_vcpu_ioctl(
                &g_edge_kvm_facade, file.handle, request->command,
                request->argument);
        }
    } else if (file.kind == KERNEL_EDGE_KVM_FILE_DEVICE) {
        if (request->command == EDGE_KVM_IOCTL_SET_DEVICE_ATTR)
            result = edge_kvm_runtime_device_attr(request, file.handle, 0);
        else if (request->command == EDGE_KVM_IOCTL_GET_DEVICE_ATTR)
            result = edge_kvm_runtime_device_attr(request, file.handle, 1);
        else if (request->command == EDGE_KVM_IOCTL_HAS_DEVICE_ATTR)
            result = edge_kvm_runtime_device_attr(request, file.handle, 2);
        else
            result = -EDGE_LINUX_ENOTTY;
    } else {
        result = -EDGE_LINUX_EBADF;
    }
    edge_kvm_runtime_unlock();
    if (rollback_descriptor >= 0)
        (void)g_descriptor_ops->close(
            g_descriptor_context, rollback_descriptor);
    return result;
}

int kernel_edge_kvm_vcpu_mmap_page(edge_kvm_handle_t handle,
                                   uint32_t page_index,
                                   uint64_t *physical_address) {
    int status;

    edge_kvm_runtime_lock();
    status = edge_kvm_facade_vcpu_mmap_page(
        &g_edge_kvm_facade, handle, page_index, physical_address);
    edge_kvm_runtime_unlock();
    return status;
}

static edge_kvm_descriptor_kind_t edge_kvm_facade_kind(
        kernel_edge_kvm_file_kind_t kind) {
    if (kind == KERNEL_EDGE_KVM_FILE_VM) return EDGE_KVM_DESCRIPTOR_VM;
    if (kind == KERNEL_EDGE_KVM_FILE_VCPU) return EDGE_KVM_DESCRIPTOR_VCPU;
    return EDGE_KVM_DESCRIPTOR_DEVICE;
}

int kernel_edge_kvm_descriptor_retain(kernel_edge_kvm_file_kind_t kind,
                                      edge_kvm_handle_t handle) {
    int status;
    if (kind != KERNEL_EDGE_KVM_FILE_VM &&
        kind != KERNEL_EDGE_KVM_FILE_VCPU &&
        kind != KERNEL_EDGE_KVM_FILE_DEVICE)
        return -EDGE_LINUX_EINVAL;
    edge_kvm_runtime_lock();
    status = edge_kvm_facade_descriptor_retain(
        &g_edge_kvm_facade, edge_kvm_facade_kind(kind), handle);
    edge_kvm_runtime_unlock();
    return status;
}

int kernel_edge_kvm_descriptor_release(kernel_edge_kvm_file_kind_t kind,
                                       edge_kvm_handle_t handle) {
    int status;
    if (kind != KERNEL_EDGE_KVM_FILE_VM &&
        kind != KERNEL_EDGE_KVM_FILE_VCPU &&
        kind != KERNEL_EDGE_KVM_FILE_DEVICE)
        return -EDGE_LINUX_EINVAL;
    edge_kvm_runtime_lock();
    status = edge_kvm_facade_descriptor_release(
        &g_edge_kvm_facade, edge_kvm_facade_kind(kind), handle);
    edge_kvm_runtime_unlock();
    return status;
}

int64_t kernel_edge_kvm_stats_read(kernel_edge_kvm_file_kind_t source_kind,
                                   edge_kvm_handle_t handle,
                                   uint64_t offset, void *buffer,
                                   uint32_t length) {
    uint8_t blob[EDGE_KVM_STATS_BLOB_SIZE] __attribute__((aligned(8)));
    uint32_t blob_size = 0;
    uint32_t copied;
    int status;

    if (!buffer && length != 0) return -EDGE_LINUX_EFAULT;
    edge_kvm_runtime_lock();
    status = edge_kvm_stats_build(
        source_kind, handle, blob, &blob_size);
    edge_kvm_runtime_unlock();
    if (status < 0) return status;
    if (offset >= blob_size || length == 0) return 0;
    copied = length;
    if ((uint64_t)copied > (uint64_t)blob_size - offset)
        copied = (uint32_t)((uint64_t)blob_size - offset);
    __builtin_memcpy(buffer, blob + offset, copied);
    return copied;
}
