/* SPDX-License-Identifier: MPL-2.0 */
/* x86-64 adapters for architecture-neutral kernel interfaces. */

#include <stdint.h>
#include "arch/x86_64/fpu.h"
#include "arch/x86_64/page_table.h"
#include "arch/x86_64/user_layout.h"
#include "dev/alsa.h"
#include "kernel/arch_cpu.h"
#include "kernel/proc_platform.h"
#include "kernel/smp.h"
#include "mm/arch_vm.h"
#include "string.h"
#include "sys/meminfo.h"
#include "sys/process.h"

#define X86_VM_PAGE_SIZE UINT64_C(4096)
#define X86_VM_PTE_PRESENT UINT64_C(0x001)
#define X86_VM_PTE_WRITE UINT64_C(0x002)
#define X86_VM_PTE_USER UINT64_C(0x004)
#define X86_VM_PTE_LARGE UINT64_C(0x080)
#define X86_VM_PTE_NO_EXECUTE (UINT64_C(1) << 63)
#define X86_VM_PTE_ADDRESS UINT64_C(0x000ffffffffff000)

static int x86_vm_walk_user(uint64_t address_space, uint64_t address,
                            uint64_t *physical_out, uint64_t *entry_out,
                            uint32_t *protection_out) {
    uint64_t *table;
    uint64_t entry;
    uint64_t permissions = X86_VM_PTE_WRITE;
    uint64_t no_execute = 0;

    if (!address_space) return -1;
    table = x86_page_table_alias(address_space);
    if (!table) return -1;
    entry = table[(address >> 39) & 0x1ffu];
    if ((entry & (X86_VM_PTE_PRESENT | X86_VM_PTE_USER)) !=
        (X86_VM_PTE_PRESENT | X86_VM_PTE_USER))
        return -1;
    permissions &= entry;
    no_execute |= entry & X86_VM_PTE_NO_EXECUTE;

    table = x86_page_table_alias(entry);
    if (!table) return -1;
    entry = table[(address >> 30) & 0x1ffu];
    if ((entry & (X86_VM_PTE_PRESENT | X86_VM_PTE_USER)) !=
        (X86_VM_PTE_PRESENT | X86_VM_PTE_USER))
        return -1;
    permissions &= entry;
    no_execute |= entry & X86_VM_PTE_NO_EXECUTE;
    if ((entry & X86_VM_PTE_LARGE) != 0) {
        if (physical_out)
            *physical_out = (entry & UINT64_C(0x000fffffc0000000)) |
                (address & UINT64_C(0x3fffffff));
        goto complete;
    }

    table = x86_page_table_alias(entry);
    if (!table) return -1;
    entry = table[(address >> 21) & 0x1ffu];
    if ((entry & (X86_VM_PTE_PRESENT | X86_VM_PTE_USER)) !=
        (X86_VM_PTE_PRESENT | X86_VM_PTE_USER))
        return -1;
    permissions &= entry;
    no_execute |= entry & X86_VM_PTE_NO_EXECUTE;
    if ((entry & X86_VM_PTE_LARGE) != 0) {
        if (physical_out)
            *physical_out = (entry & UINT64_C(0x000fffffffe00000)) |
                (address & UINT64_C(0x1fffff));
        goto complete;
    }

    table = x86_page_table_alias(entry);
    if (!table) return -1;
    entry = table[(address >> 12) & 0x1ffu];
    if ((entry & (X86_VM_PTE_PRESENT | X86_VM_PTE_USER)) !=
        (X86_VM_PTE_PRESENT | X86_VM_PTE_USER))
        return -1;
    permissions &= entry;
    no_execute |= entry & X86_VM_PTE_NO_EXECUTE;
    if (physical_out)
        *physical_out = (entry & X86_VM_PTE_ADDRESS) |
            (address & (X86_VM_PAGE_SIZE - 1u));

complete:
    if (entry_out) *entry_out = entry;
    if (protection_out) {
        uint32_t protection = ARCH_VM_PROT_READ;

        if ((permissions & X86_VM_PTE_WRITE) != 0)
            protection |= ARCH_VM_PROT_WRITE;
        if (no_execute == 0)
            protection |= ARCH_VM_PROT_EXEC;
        *protection_out = protection;
    }
    return 0;
}

int arch_vm_translate(uint64_t address_space, uint64_t virtual_address,
                      uint64_t *physical_address, uint64_t *entry_out) {
    if (!physical_address) return -1;
    return x86_vm_walk_user(address_space, virtual_address,
                            physical_address, entry_out, 0);
}

int arch_vm_user_page_protection(uint64_t address_space,
                                 uint64_t virtual_address,
                                 uint32_t *protection_out) {
    if (!protection_out) return -1;
    return x86_vm_walk_user(address_space, virtual_address, 0, 0,
                            protection_out);
}

uint64_t arch_vm_address_space_resident_pages(uint64_t address_space) {
    uint64_t *pml4;
    uint64_t pages = 0;

    if (!address_space) return 0;
    pml4 = x86_page_table_alias(address_space);
    if (!pml4) return 0;
    for (uint32_t pml4_index = 0; pml4_index < 256u; ++pml4_index) {
        uint64_t pml4e = pml4[pml4_index];
        uint64_t *pdpt;

        if ((pml4e & (X86_VM_PTE_PRESENT | X86_VM_PTE_USER)) !=
            (X86_VM_PTE_PRESENT | X86_VM_PTE_USER))
            continue;
        pdpt = x86_page_table_alias(pml4e);
        if (!pdpt) continue;
        for (uint32_t pdpt_index = 0; pdpt_index < 512u; ++pdpt_index) {
            uint64_t pdpte = pdpt[pdpt_index];
            uint64_t *pd;

            if ((pdpte & (X86_VM_PTE_PRESENT | X86_VM_PTE_USER)) !=
                (X86_VM_PTE_PRESENT | X86_VM_PTE_USER))
                continue;
            if (pdpte & X86_VM_PTE_LARGE) {
                pages += UINT64_C(262144);
                continue;
            }
            pd = x86_page_table_alias(pdpte);
            if (!pd) continue;
            for (uint32_t pd_index = 0; pd_index < 512u; ++pd_index) {
                uint64_t pde = pd[pd_index];
                uint64_t *pt;

                if ((pde & (X86_VM_PTE_PRESENT | X86_VM_PTE_USER)) !=
                    (X86_VM_PTE_PRESENT | X86_VM_PTE_USER))
                    continue;
                if (pde & X86_VM_PTE_LARGE) {
                    pages += UINT64_C(512);
                    continue;
                }
                pt = x86_page_table_alias(pde);
                if (!pt) continue;
                for (uint32_t pt_index = 0; pt_index < 512u; ++pt_index)
                    if ((pt[pt_index] &
                         (X86_VM_PTE_PRESENT | X86_VM_PTE_USER)) ==
                        (X86_VM_PTE_PRESENT | X86_VM_PTE_USER))
                        ++pages;
            }
        }
    }
    return pages;
}

int arch_vm_map_user_page(uint64_t address_space, uint64_t virtual_address,
                          uint64_t physical_address, uint32_t protection) {
    task_t *task = process_current_task();
    int backing_index;

    if (!task || (task->cr3 & X86_VM_PTE_ADDRESS) !=
                     (address_space & X86_VM_PTE_ADDRESS))
        return -1;
    backing_index = process_user_mmap_backing_page_index(
        (const void *)(uintptr_t)physical_address);
    if (backing_index < 0) return -1;
    return process_user_mmap_map_backing_page(
        task, virtual_address, backing_index,
        (protection & ARCH_VM_PROT_WRITE) != 0);
}

int arch_vm_unmap_user_range(uint64_t address_space, uint64_t virtual_address,
                             uint64_t length) {
    task_t *task = process_current_task();

    if (!task || (task->cr3 & X86_VM_PTE_ADDRESS) !=
                     (address_space & X86_VM_PTE_ADDRESS))
        return -1;
    process_user_mmap_unmap(task, virtual_address, length);
    return 0;
}

int arch_vm_unmap_user_page_if_physical(uint64_t address_space,
                                        uint64_t virtual_address,
                                        uint64_t physical_address) {
    task_t *task = process_current_task();
    int backing_index;

    if (!task || (task->cr3 & X86_VM_PTE_ADDRESS) !=
                     (address_space & X86_VM_PTE_ADDRESS))
        return -1;
    backing_index = process_user_mmap_backing_page_index(
        (const void *)(uintptr_t)physical_address);
    if (backing_index < 0)
        return -1;
    return process_user_mmap_unmap_page_if_backing(task, virtual_address,
                                                    backing_index);
}

int arch_mm_resolve_user_page(uint64_t address_space, uint64_t address,
                              uint32_t access) {
    task_t *task = process_current_task();
    task_t *memory = task ? process_vm_task(task) : 0;
    uint64_t physical;

    if (!memory ||
        (memory->cr3 & X86_VM_PTE_ADDRESS) !=
        (address_space & X86_VM_PTE_ADDRESS))
        return 0;
    if (arch_vm_translate(address_space, address, &physical, 0) == 0)
        return 1;
    if (!process_user_mmap_handle_fault(
            task, address, (access & ARCH_VM_PROT_WRITE) != 0))
        return 0;
    return arch_vm_translate(address_space, address, &physical, 0) == 0;
}

void *arch_vm_alloc_page(void) {
    int index = process_user_mmap_alloc_backing_page();
    return index < 0 ? 0 : process_user_mmap_backing_page_ptr(index);
}

void *arch_vm_alloc_pages(uint64_t page_count) {
    if (!page_count || page_count > UINT32_MAX) return 0;
    return process_user_mmap_alloc_contiguous_backing_pages(
        (uint32_t)page_count);
}

void *arch_vm_reserve_pages(uint64_t page_count) {
    void *memory = 0;
    uint64_t physical = 0;

    if (!page_count || page_count > UINT32_MAX) return 0;
    if (process_kernel_runtime_reserve_pages(
            (uint32_t)page_count, &memory, &physical) < 0)
        return 0;
    return memory;
}

int arch_vm_retain_page(void *page) {
    int index = process_user_mmap_backing_page_index(page);
    if (index < 0 || !process_user_mmap_backing_page_active(index)) return -1;
    process_user_mmap_retain_backing_page(index);
    return 0;
}

void arch_vm_free_page(void *page) {
    int index = process_user_mmap_backing_page_index(page);
    if (index >= 0) process_user_mmap_release_backing_page(index);
}

void arch_cpu_set_user_single_step(int enabled) {
    /* x86 single-step state is carried in the task's saved RFLAGS.TF bit. */
    (void)enabled;
}

__attribute__((naked, noreturn)) void arch_cpu_call_on_stack(
        uint64_t stack_pointer, arch_cpu_stack_entry_t entry,
        uint32_t argument) {
    __asm__ __volatile__(
        "cli\n\t"
        "movq %rdi, %rsp\n\t"
        "andq $-16, %rsp\n\t"
        "subq $8, %rsp\n\t"
        "movq $0, (%rsp)\n\t"
        "movl %edx, %edi\n\t"
        "jmp *%rsi");
}

static void x86_cpuid(uint32_t leaf, uint32_t subleaf, uint32_t *a,
                      uint32_t *b, uint32_t *c, uint32_t *d) {
    __asm__ __volatile__("cpuid"
                         : "=a"(*a), "=b"(*b), "=c"(*c), "=d"(*d)
                         : "a"(leaf), "c"(subleaf));
}

void arch_vm_sync_loaded_pages(void *const *pages, uint32_t page_count,
                               int executable) {
    uint32_t a, b, c, d;

    (void)pages;
    (void)page_count;
    __asm__ __volatile__("mfence" ::: "memory");
    if (executable)
        x86_cpuid(0u, 0u, &a, &b, &c, &d);
}

void arch_vm_sync_loaded_page(void *page, int executable) {
    void *pages[1] = {page};

    arch_vm_sync_loaded_pages(pages, 1u, executable);
}

int arch_vm_sync_user_exec_range(uint64_t address_space,
                                 uint64_t virtual_address,
                                 uint64_t length) {
    void *pages[1] = {(void *)(uintptr_t)virtual_address};

    (void)address_space;
    if (!length) return 0;
    arch_vm_sync_loaded_pages(pages, 1u, 1);
    return 0;
}

void arch_cpu_memory_barrier(void) {
    __asm__ __volatile__("mfence" ::: "memory");
}

void arch_cpu_relax(void) {
    __asm__ __volatile__("pause");
}

uint64_t arch_cpu_user_stack_top(void) {
    return X86_USER_STACK_BASE + X86_USER_FIXED_WINDOW_SIZE;
}

uint64_t arch_cpu_user_vdso_base(void) {
    return X86_USER_INTERP_BASE + X86_USER_FIXED_WINDOW_SIZE - 8192u;
}

int arch_proc_sound_available(void) {
    return alsa_available();
}

int arch_proc_filesystem_available(kernel_proc_filesystem_kind_t kind) {
    switch (kind) {
        case KERNEL_PROC_FS_EXT2:
#ifdef CONFIG_FS_EXT2
            return 1;
#else
            return 0;
#endif
        case KERNEL_PROC_FS_EXT4:
#ifdef CONFIG_FS_EXT4
            return 1;
#else
            return 0;
#endif
        case KERNEL_PROC_FS_FAT32:
#ifdef CONFIG_FS_FAT32
            return 1;
#else
            return 0;
#endif
        case KERNEL_PROC_FS_EXFAT:
#ifdef CONFIG_FS_EXFAT
            return 1;
#else
            return 0;
#endif
        case KERNEL_PROC_FS_NTFS:
#ifdef CONFIG_FS_NTFS
            return 1;
#else
            return 0;
#endif
        case KERNEL_PROC_FS_ISO9660:
#ifdef CONFIG_FS_ISO9660
            return 1;
#else
            return 0;
#endif
        case KERNEL_PROC_FS_UDF:
#ifdef CONFIG_FS_UDF
            return 1;
#else
            return 0;
#endif
        default:
            return 0;
    }
}

int arch_proc_sound_read(const char *name, char *buffer,
                         uint32_t capacity) {
    return alsa_proc_read(name, buffer, capacity);
}

void arch_cpu_sync_barrier(void) {
    __asm__ __volatile__("mfence" ::: "memory");
}

void arch_cpu_sync_instruction_stream(void) {
    uint32_t a, b, c, d;
    x86_cpuid(0u, 0u, &a, &b, &c, &d);
}

static int cpuinfo_append(char *buffer, uint32_t capacity, uint32_t *length,
                          const char *text) {
    if (!buffer || !length || !text) return -1;
    while (*text) {
        if (*length + 1u >= capacity) return -1;
        buffer[(*length)++] = *text++;
    }
    buffer[*length] = 0;
    return 0;
}

static int cpuinfo_append_u32(char *buffer, uint32_t capacity,
                              uint32_t *length, uint32_t value) {
    char reversed[12];
    uint32_t count = 0;
    if (!value) reversed[count++] = '0';
    while (value && count < sizeof(reversed)) {
        reversed[count++] = (char)('0' + value % 10u);
        value /= 10u;
    }
    while (count) {
        char byte[2] = { reversed[--count], 0 };
        if (cpuinfo_append(buffer, capacity, length, byte) < 0) return -1;
    }
    return 0;
}

static int cpuinfo_append_flag(char *buffer, uint32_t capacity,
                               uint32_t *length, uint32_t enabled,
                               const char *name) {
    if (!enabled) return 0;
    if (cpuinfo_append(buffer, capacity, length, " ") < 0) return -1;
    return cpuinfo_append(buffer, capacity, length, name);
}

int arch_cpu_proc_info(char *buffer, uint32_t capacity) {
    uint32_t a, b, c, d;
    uint32_t basic_ecx;
    uint32_t basic_edx;
    uint32_t maximum_basic;
    uint32_t maximum_extended;
    uint32_t family;
    uint32_t model;
    uint32_t stepping;
    uint32_t length = 0;
    char vendor[13];
    char brand[49];

    if (!buffer || capacity < 2u) return -1;
    x86_cpuid(0, 0, &maximum_basic, &b, &c, &d);
    ((uint32_t *)(void *)vendor)[0] = b;
    ((uint32_t *)(void *)vendor)[1] = d;
    ((uint32_t *)(void *)vendor)[2] = c;
    vendor[12] = 0;
    x86_cpuid(1, 0, &a, &b, &c, &d);
    basic_ecx = c;
    basic_edx = d;
    stepping = a & 0xfu;
    model = (a >> 4) & 0xfu;
    family = (a >> 8) & 0xfu;
    if (family == 6u || family == 15u) model |= ((a >> 16) & 0xfu) << 4;
    if (family == 15u) family += (a >> 20) & 0xffu;

    x86_cpuid(0x80000000u, 0, &maximum_extended, &b, &c, &d);
    brand[0] = 0;
    if (maximum_extended >= 0x80000004u) {
        uint32_t *words = (uint32_t *)(void *)brand;
        for (uint32_t leaf = 0; leaf < 3u; ++leaf) {
            x86_cpuid(0x80000002u + leaf, 0, &words[leaf * 4u + 0u],
                      &words[leaf * 4u + 1u], &words[leaf * 4u + 2u],
                      &words[leaf * 4u + 3u]);
        }
        brand[48] = 0;
    }
    if (!brand[0]) {
        const char fallback[] = "x86_64 Virtual CPU";
        uint32_t index;
        for (index = 0; fallback[index] && index + 1u < sizeof(brand); ++index)
            brand[index] = fallback[index];
        brand[index] = 0;
    }

    for (uint32_t cpu = 0; cpu < edge_smp_nr_cpu_ids(); ++cpu) {
        edge_cpu_topology_t topology;

        if (edge_smp_cpu_state(cpu) != EDGE_CPU_ONLINE) continue;
        if (edge_smp_get_cpu(cpu, &topology) != 0) return -1;
        if (cpuinfo_append(buffer, capacity, &length, "processor\t: ") < 0 ||
        cpuinfo_append_u32(buffer, capacity, &length, cpu) < 0 ||
        cpuinfo_append(buffer, capacity, &length, "\nvendor_id\t: ") < 0 ||
        cpuinfo_append(buffer, capacity, &length, vendor) < 0 ||
        cpuinfo_append(buffer, capacity, &length, "\ncpu family\t: ") < 0 ||
        cpuinfo_append_u32(buffer, capacity, &length, family) < 0 ||
        cpuinfo_append(buffer, capacity, &length, "\nmodel\t\t: ") < 0 ||
        cpuinfo_append_u32(buffer, capacity, &length, model) < 0 ||
        cpuinfo_append(buffer, capacity, &length, "\nmodel name\t: ") < 0 ||
        cpuinfo_append(buffer, capacity, &length, brand) < 0 ||
        cpuinfo_append(buffer, capacity, &length, "\nstepping\t: ") < 0 ||
        cpuinfo_append_u32(buffer, capacity, &length, stepping) < 0 ||
        cpuinfo_append(buffer, capacity, &length,
            "\nfpu\t\t: yes\nfpu_exception\t: yes\n"
            "flags\t\t: fpu tsc msr pae cx8 cmov pat clflush fxsr sse sse2") < 0 ||
        /* Report only state components enabled and preserved by the kernel. */
        cpuinfo_append_flag(buffer, capacity, &length,
                            basic_edx & (1u << 23), "mmx") < 0 ||
        cpuinfo_append_flag(buffer, capacity, &length,
                            basic_ecx & (1u << 0), "pni") < 0 ||
        cpuinfo_append_flag(buffer, capacity, &length,
                            basic_ecx & (1u << 1), "pclmulqdq") < 0 ||
        cpuinfo_append_flag(buffer, capacity, &length,
                            basic_ecx & (1u << 9), "ssse3") < 0 ||
        cpuinfo_append_flag(buffer, capacity, &length,
                            basic_ecx & (1u << 13), "cx16") < 0 ||
        cpuinfo_append_flag(buffer, capacity, &length,
                            basic_ecx & (1u << 19), "sse4_1") < 0 ||
        cpuinfo_append_flag(buffer, capacity, &length,
                            basic_ecx & (1u << 20), "sse4_2") < 0 ||
        cpuinfo_append_flag(buffer, capacity, &length,
                            basic_ecx & (1u << 22), "movbe") < 0 ||
        cpuinfo_append_flag(buffer, capacity, &length,
                            basic_ecx & (1u << 23), "popcnt") < 0 ||
        cpuinfo_append_flag(buffer, capacity, &length,
                            basic_ecx & (1u << 25), "aes") < 0 ||
        cpuinfo_append_flag(buffer, capacity, &length,
                            basic_ecx & (1u << 30), "rdrand") < 0 ||
        cpuinfo_append_flag(buffer, capacity, &length,
                            x86_fpu_xsave_enabled(), "xsave") < 0 ||
        cpuinfo_append_flag(buffer, capacity, &length,
                            x86_fpu_xsave_enabled(), "osxsave") < 0 ||
        cpuinfo_append_flag(buffer, capacity, &length,
                            x86_fpu_xsave_enabled() &&
                            (x86_fpu_enabled_features() & (1ull << 2)),
                            "avx") < 0 ||
        cpuinfo_append(buffer, capacity, &length,
            " syscall nx lm\nphysical id\t: ") < 0 ||
        cpuinfo_append_u32(buffer, capacity, &length,
                           topology.package_id) < 0 ||
        cpuinfo_append(buffer, capacity, &length, "\ncore id\t\t: ") < 0 ||
        cpuinfo_append_u32(buffer, capacity, &length, topology.core_id) < 0 ||
        cpuinfo_append(buffer, capacity, &length,
            "\nbugs\t\t:\naddress sizes\t: 46 bits physical, 48 bits virtual\n\n") < 0)
            return -1;
    }
    (void)maximum_basic;
    return (int)length;
}

int arch_cpu_proc_ioports(char *buffer, uint32_t capacity) {
    static const char resources[] =
        "0000-001f : dma1\n"
        "0020-0021 : pic1\n"
        "0040-0043 : timer0\n"
        "0060-0064 : i8042\n"
        "0070-0071 : rtc_cmos\n"
        "0080-008f : dma page reg\n"
        "00a0-00a1 : pic2\n"
        "00c0-00df : dma2\n"
        "00f0-00ff : fpu\n"
        "0170-0177 : ide1\n"
        "01f0-01f7 : ide0\n"
        "0376-0376 : ide1 control\n"
        "03c0-03df : vga\n"
        "03f6-03f6 : ide0 control\n"
        "03f8-03ff : serial\n"
        "0cf8-0cff : PCI conf1\n";
    uint32_t length = (uint32_t)sizeof(resources) - 1u;

    if (!buffer || capacity <= length) return -1;
    for (uint32_t index = 0; index <= length; ++index)
        buffer[index] = resources[index];
    return (int)length;
}

uint16_t arch_user_elf_machine(void) {
    return 62u; /* ELF EM_X86_64. */
}

uint64_t arch_vm_memory_total_bytes(void) {
    return meminfo_total_bytes();
}

uint64_t arch_vm_memory_free_bytes(void) {
    uint64_t free_bytes = process_user_mmap_backing_free_bytes();

    return process_user_mmap_backing_total_pages() ?
        free_bytes : meminfo_free_bytes();
}

int arch_vm_page_allocator_snapshot(
    edge_page_allocator_snapshot_t *snapshot) {
    uint64_t managed_pages;
    uint64_t free_pages;

    if (!snapshot) return -1;
    if (process_page_allocator_snapshot(snapshot) == 0) return 0;
    memset(snapshot, 0, sizeof(*snapshot));
    managed_pages = meminfo_total_bytes() / EDGE_PAGE_SIZE;
    free_pages = meminfo_free_bytes() / EDGE_PAGE_SIZE;
    if (managed_pages > UINT32_MAX) managed_pages = UINT32_MAX;
    if (free_pages > UINT32_MAX) free_pages = UINT32_MAX;
    snapshot->managed_pages[EDGE_PAGE_ZONE_NORMAL] =
        (uint32_t)managed_pages;
    snapshot->free_pages[EDGE_PAGE_ZONE_NORMAL] = (uint32_t)free_pages;
    snapshot->buddy_exact = 0u;
    return 0;
}

int arch_vm_write_notify_supported(void) {
    /*
     * x86 fbdev VMAs are installed read-only and
     * process_user_fbdev_handle_fault() records the first store to each page.
     * The deferred presenter write-protects those PTEs again after consuming
     * the damage list, so write faults are the authoritative damage source.
     * Advertising that capability avoids continuously polling PTE dirty bits
     * and shadow-comparing an idle framebuffer.
     */
    return 1;
}

int arch_vm_writeprotect_physical_aliases(uint64_t physical_address,
                                          uint64_t length) {
    /*
     * Legacy x86 DRM dumb-buffer mappings do not opt into the shared physical
     * write-notify path. fbdev uses its existing process page-table tracker.
     */
    (void)physical_address;
    (void)length;
    return 0;
}
