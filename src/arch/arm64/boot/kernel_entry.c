/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS ARM64 post-UEFI kernel entry.
 * Copyright (c) EdgeOS Contributors.
 *
 * This code runs only after successful ExitBootServices.  It is intentionally
 * independent of UEFI protocol pointers: firmware boot services are no longer
 * legal, while the UEFI-provided memory map, framebuffer and rootfs allocation
 * have become input to the ARM64 kernel's platform and VM initialization.
 */

#include <stdint.h>
#include "arch/arm64/bootinfo.h"
#include "arch/arm64/mmu.h"
#include "arch/arm64/interrupt.h"
#include "arch/arm64/platform.h"
#include "arch/arm64/smp.h"
#include "arch/arm64/task.h"
#include "arch/arm64/vm.h"
#include "arch/arm64/syscall.h"
#include "arch/arm64/user_layout.h"
#include "drivers/ramdisk.h"
#include "block/block.h"
#include "block/device_mapper.h"
#include "block/loop.h"
#include "vfs/vfs.h"
#include "arch/arm64/elf.h"
#include "elf/elf_image.h"
#include "kernel/user_stack.h"
#include "kernel/runtime.h"
#include "kernel/boot_command_line.h"
#ifdef CONFIG_NFSD
#include "fs/nfsd.h"
#endif
#include "kernel/boot_filesystems.h"
#include "kernel/boot_logfile.h"
#include "kernel/boot_root.h"
#include "fs/initramfs.h"
#include "console.h"
#include "fb_console.h"
#include "drivers/virtio_net_mmio.h"
#include "drivers/virtio_input_mmio.h"
#include "drivers/virtio_blk_mmio.h"
#ifdef CONFIG_VIRTIO_GPU
#include "drivers/virtio_gpu.h"
#endif
#include "drivers/e1000.h"
#include "net/lwip_stack.h"
#include "net/native_netdev.h"
#include "sys/bootlog.h"
#ifdef CONFIG_BSD_DRIVER_BRIDGE
#include "compat/freebsd/edgeos/arm64_handoff.h"
#include "compat/freebsd/edgeos/bootstrap.h"
#include "compat/freebsd/edgeos/firmware_metadata.h"
#include "compat/freebsd/edgeos/acpi_tables.h"
#ifdef CONFIG_DEVICE_TREE
#include "compat/freebsd/edgeos/ofw.h"
#endif
#endif

static void arm64_serial_putc(char ch) {
    edgeos_arm64_platform_serial_write(ch);
}

static void arm64_serial_puts(const char *s) {
    while (s && *s) arm64_serial_putc(*s++);
}

static uint64_t g_init_ttbr0;
static uint64_t g_init_entry;
static uint64_t g_init_stack;
static char g_init_path[VFS_PATH_MAX];

static int arm64_bootinfo_valid(const edgeos_arm64_bootinfo_t *bootinfo) {
    return bootinfo &&
           bootinfo->magic == EDGEOS_ARM64_BOOTINFO_MAGIC &&
           bootinfo->version == EDGEOS_ARM64_BOOTINFO_VERSION &&
           (bootinfo->flags & EDGEOS_ARM64_BOOTINFO_FLAG_EFI_MMAP) != 0 &&
           bootinfo->efi_mmap.map != 0 &&
           bootinfo->efi_mmap.size != 0 &&
           bootinfo->efi_mmap.descriptor_size != 0;
}

__attribute__((noreturn))
void edgeos_arm64_el1_main(edgeos_arm64_bootinfo_t *bootinfo) {
    int initramfs_root = 0;
    int boot_log_status;
    if (!arm64_bootinfo_valid(bootinfo)) {
        arm64_serial_puts("arm64: invalid UEFI handoff; halted\n");
        for (;;) __asm__ __volatile__("wfe");
    }

#if defined(CONFIG_BSD_DRIVER_BRIDGE) && defined(CONFIG_DEVICE_TREE)
    if ((bootinfo->flags & EDGEOS_ARM64_BOOTINFO_FLAG_FDT) != 0 &&
        bsd_ofw_fdt_install(
            (const void *)(uintptr_t)bootinfo->fdt_base,
            (size_t)bootinfo->fdt_size) != 0) {
        arm64_serial_puts(
            "arm64: firmware device tree validation failed\n");
    }
#endif
    (void)edgeos_arm64_platform_configure(bootinfo);
    if (edgeos_arm64_mmu_init(bootinfo) < 0) {
        arm64_serial_puts("arm64: failed to install EdgeOS EL1 page tables; halted\n");
        for (;;) __asm__ __volatile__("wfe");
    }
    arm64_serial_puts("arm64: entered EdgeOS EL1 after ExitBootServices\n");
    arm64_serial_puts("arm64: EdgeOS EL1 page tables active\n");
#ifdef CONFIG_BSD_DRIVER_BRIDGE
    if ((bootinfo->flags & EDGEOS_ARM64_BOOTINFO_FLAG_ACPI) != 0)
        bsd_acpi_tables_install_rsdp(bootinfo->acpi_rsdp);
    if (bsd_firmware_metadata_configure_efi(
        bootinfo->efi_system_table,
        (const void *)(uintptr_t)bootinfo->efi_mmap.map,
        (size_t)bootinfo->efi_mmap.size,
        (size_t)bootinfo->efi_mmap.descriptor_size,
        bootinfo->efi_mmap.descriptor_version) != 0) {
        arm64_serial_puts("arm64: EFI runtime metadata rejected\n");
    }
#endif
    boot_log_status = kernel_boot_log_configure();
    bootlog_init();
    if (boot_log_status < 0)
        bootlog_stage("bootlog: invalid loglevel or logfile option");
    if (edgeos_arm64_platform_kind() ==
        EDGEOS_ARM64_PLATFORM_RASPBERRY_PI_5)
        bootlog_stage("ARM64: Raspberry Pi 5 BCM2712 platform detected");
    else if (edgeos_arm64_platform_kind() ==
        EDGEOS_ARM64_PLATFORM_RASPBERRY_PI_4)
        bootlog_stage("ARM64: Raspberry Pi 4 BCM2711 platform detected");
    bootlog_stage("ARM64: EdgeOS EL1 page tables active");
#if defined(CONFIG_BSD_DRIVER_BRIDGE) && defined(CONFIG_DEVICE_TREE)
    if (bsd_ofw_fdt_available())
        bootlog_stage("ARM64: Firmware device tree ready");
#endif
    if (edgeos_arm64_vm_init(bootinfo) < 0) {
        arm64_serial_puts("arm64: early VM allocator initialization failed; halted\n");
        for (;;) __asm__ __volatile__("wfe");
    }
#ifdef CONFIG_VIRTIO_GPU
    if (virtio_gpu_mmio_init(bootinfo) < 0) {
        arm64_serial_puts(
            "arm64: no usable virtio GPU transport discovered\n");
    } else {
        /*
         * UEFI initially attaches fbcon to the firmware framebuffer.  The
         * virtio GPU replaces that scanout after ExitBootServices, so rebind
         * the console before userspace starts using the Linux VT interface.
         */
        console_set_backend(&FB_CONSOLE);
        console_init(COLOR_WHITE, COLOR_BLACK);
    }
#endif
    if (edgeos_arm64_smp_discover(bootinfo) < 0)
        arm64_serial_puts("arm64: CPU topology discovery unavailable; continuing on boot CPU\n");
    bootlog_stage("ARM64: Initializing memory management");
    block_init();
#ifdef CONFIG_DEVICE_MAPPER
    edge_dm_initialize();
#endif
#ifdef CONFIG_LOOP_DEVICE
    edge_loop_initialize();
#endif
    (void)edgeos_arm64_virtio_blk_init(bootinfo);
    if ((bootinfo->flags & EDGEOS_ARM64_BOOTINFO_FLAG_ROOTFS) &&
        ramdisk_register("ram0", (void *)(uintptr_t)bootinfo->rootfs.base,
                         bootinfo->rootfs.size, 1) < 0)
        arm64_serial_puts("arm64: UEFI rootfs fallback registration failed\n");
    vfs_bootstrap_init();
#ifdef CONFIG_INITRAMFS
    if ((bootinfo->flags & EDGEOS_ARM64_BOOTINFO_FLAG_INITRAMFS) &&
        bootinfo->initramfs.base && bootinfo->initramfs.size) {
        if (initramfs_mount_root() < 0 ||
            initramfs_unpack_memory(
                (const void *)(uintptr_t)bootinfo->initramfs.base,
                bootinfo->initramfs.size) < 0) {
            arm64_serial_puts(
                "arm64: initramfs mount or unpack failed; halted\n");
            for (;;) __asm__ __volatile__("wfe");
        }
        initramfs_root = 1;
        bootlog_stage("ARM64: Initramfs root mounted");
    }
#endif
    if (!initramfs_root) {
        kernel_boot_root_result_t root_result;

        if (kernel_boot_root_mount(&root_result) < 0) {
            arm64_serial_puts(
                "arm64: root filesystem selection or mount failed; halted\n");
            for (;;) __asm__ __volatile__("wfe");
        }
        bootlog_stage("ARM64: Root filesystem mounted");
    }
    (void)kernel_boot_log_start();
    if (kernel_boot_mount_sysfs() < 0) {
        arm64_serial_puts("arm64: failed to mount sysfs device model; halted\n");
        for (;;) __asm__ __volatile__("wfe");
    }
    {
        vfs_inode_t init_inode;
        elf_image_info_t init_elf;
        elf_image_info_t interp_elf;
        uint64_t init_ttbr0;
        uint64_t init_entry;
        uint64_t interp_entry = 0;
        uint64_t init_bias = 0;
        uint64_t interp_bias = 0;
        uint64_t init_sp;
        if (kernel_boot_init_path(
                initramfs_root, g_init_path, sizeof(g_init_path)) < 0) {
            arm64_serial_puts(
                "arm64: invalid init path in command line; halted\n");
            for (;;) __asm__ __volatile__("wfe");
        }
        if (vfs_resolve(g_init_path, &init_inode, 0, 0, 0) < 0 ||
            (init_inode.mode & 0xf000u) != VFS_INODE_FILE ||
            elf_image_probe(
                g_init_path, EDGEOS_ELF_MACHINE_ARM64, &init_elf) < 0) {
            arm64_serial_puts(
                "arm64: mounted root lacks configured init; halted\n");
            for (;;) __asm__ __volatile__("wfe");
        }
        if (init_elf.type == 3u)
            init_bias = EDGEOS_ARM64_USER_PROGRAM_BASE;
        if (edgeos_arm64_address_space_create(&init_ttbr0) < 0 ||
            elf_image_load(init_ttbr0, g_init_path, EDGEOS_ELF_MACHINE_ARM64, init_bias,
                                  &init_elf, &init_entry) < 0 || !init_entry) {
            arm64_serial_puts(
                "arm64: failed to map configured init into user VM; halted\n");
            for (;;) __asm__ __volatile__("wfe");
        }
        if (init_elf.interpreter[0])
            interp_bias = EDGEOS_ARM64_USER_INTERPRETER_BASE;
        if (init_elf.interpreter[0] &&
            (elf_image_probe(init_elf.interpreter, EDGEOS_ELF_MACHINE_ARM64, &interp_elf) < 0 ||
             elf_image_load(init_ttbr0, init_elf.interpreter, EDGEOS_ELF_MACHINE_ARM64,
                                   interp_elf.type == 3u ? interp_bias : 0,
                                   &interp_elf, &interp_entry) < 0 || !interp_entry)) {
            arm64_serial_puts("arm64: failed to map init dynamic interpreter; halted\n");
            for (;;) __asm__ __volatile__("wfe");
        }
        if (linux_user_stack_build(init_ttbr0, g_init_path,
                                          init_bias + init_elf.phdr_vaddr,
                                          init_elf.phnum, init_entry, interp_bias, &init_sp) < 0 || !init_sp) {
            arm64_serial_puts("arm64: failed to construct Linux initial stack; halted\n");
            for (;;) __asm__ __volatile__("wfe");
        }
        g_init_ttbr0 = init_ttbr0;
        g_init_entry = interp_entry ? interp_entry : init_entry;
        g_init_stack = init_sp;
    }
    edgeos_arm64_exceptions_init();
    bootlog_stage("ARM64: Initializing exceptions and interrupt controller");
    if (edgeos_arm64_irq_init(bootinfo) < 0) {
        arm64_serial_puts("arm64: GICv3 discovery or timer initialization failed; halted\n");
        for (;;) __asm__ __volatile__("wfe");
    }
#ifdef CONFIG_VIRTIO_GPU
    if (virtio_gpu_enable_interrupts() < 0)
        arm64_serial_puts(
            "arm64: virtio GPU interrupts unavailable; retaining polling mode\n");
#endif
    if (edgeos_arm64_smp_start_secondary_cpus() < 0)
        arm64_serial_puts("arm64: one or more secondary CPUs did not start\n");
    if (edgeos_arm64_virtio_blk_enable_interrupts() < 0)
        arm64_serial_puts("arm64: virtio block interrupts unavailable; retaining polling mode\n");
    __asm__ __volatile__("msr daifclr, #2");
    while (edgeos_arm64_timer_ticks() < 5u) {
        __asm__ __volatile__("wfe");
    }
    if (edgeos_arm64_context_selftest() < 0) {
        arm64_serial_puts("arm64: context switch self-test failed; halted\n");
        for (;;) __asm__ __volatile__("wfe");
    }
    if (edgeos_arm64_syscall_selftest() < 0) {
        arm64_serial_puts("arm64: SVC ABI self-test failed; halted\n");
        for (;;) __asm__ __volatile__("wfe");
    }
    if (edgeos_arm64_virtio_net_init(bootinfo) == 0) {
        if (edgeos_arm64_virtio_net_enable_interrupts() < 0)
            arm64_serial_puts("arm64: virtio network interrupts unavailable; retaining polling mode\n");
        e1000_init();
        if (edge_native_netdev_register() != 0)
            arm64_serial_puts(
                "arm64: native network registration failed\n");
        lwip_stack_init();
#ifdef CONFIG_NFSD
        if (edge_nfsd_boot_start() < 0)
            arm64_serial_puts("arm64: NFS server startup failed\n");
#endif
    } else {
        arm64_serial_puts("arm64: no virtio-mmio network device discovered\n");
    }
    if (edgeos_arm64_virtio_input_init(bootinfo) < 0) {
        arm64_serial_puts("arm64: no virtio keyboard discovered\n");
    } else if (edgeos_arm64_virtio_input_enable_interrupts() < 0) {
        arm64_serial_puts(
            "arm64: virtio input interrupts unavailable; retaining polling mode\n");
    }
    bootlog_stage("ARM64: Timer, scheduler, and syscall entry verified");
    bootlog_stage("ARM64: Network stack initialized");
    bootlog_stage("INIT: Starting configured init");
    if (kernel_process_runtime_init(
            g_init_path, g_init_ttbr0, g_init_entry, g_init_stack) < 0) {
        arm64_serial_puts("arm64: process table allocation failed; halted\n");
        for (;;) __asm__ __volatile__("wfe");
    }
#ifdef CONFIG_BSD_DRIVER_BRIDGE
    if (bsd_bridge_bootstrap(0) != 0) {
        arm64_serial_puts("arm64: BSD driver bridge startup failed\n");
    } else {
        bsd_bridge_handoff_status_t handoff_status;

        if (bsd_bridge_arm64_handoff_start(
            kernel_boot_command_line_get(), bootinfo,
            &handoff_status) != 0) {
            arm64_serial_puts(
                "arm64: BSD driver bridge device handoff failed\n");
        } else if (handoff_status.enabled) {
            arm64_serial_puts(
                "arm64: BSD driver bridge runtime ready with selected devices\n");
        } else {
            arm64_serial_puts(
                "arm64: BSD driver bridge runtime ready\n");
        }
    }
#endif
    kernel_process_runtime_enter();
    for (;;) __asm__ __volatile__("wfe");
}
