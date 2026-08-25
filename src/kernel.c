#include "fb.h"
#include "fb_console.h"
#include "vga_console.h"
#include "console.h"
#include "console_backend.h"
#include "serial_console.h"
#include "arch/x86_64/gdt.h"
#include "arch/x86_64/smp.h"
#include "arch/x86_64/idt.h"
#include "keyboard.h"
#include "arch/x86_64/isr.h"
#include "dev/dev.h"
#include "vfs/vfs.h"
#ifdef CONFIG_FS_EXT2
#include "ext2/ext2.h"
#endif
#ifdef CONFIG_FS_EXT4
#include "ext4/ext4.h"
#endif
#include "block/block.h"
#include "sys/meminfo.h"
#include "sys/boottime.h"
#include "sys/bootlog.h"
#include "sys/process.h"
#include "sys/scheduler.h"
#include "sys/syscall.h"
#include "kernel/boot_filesystems.h"
#include "kernel/deferred_work.h"
#include "kernel/drm_runtime.h"
#include "kernel/file_metadata.h"
#include "kernel/timer_policy.h"
#include "elf/elf_loader.h"
#include "drivers/e1000.h"
#ifdef CONFIG_WIFI_INTEL_IWLWIFI
#include "drivers/iwlwifi.h"
#endif
#ifdef CONFIG_VMWARE_VMXNET3
#include "drivers/vmxnet3.h"
#endif
#ifdef CONFIG_HYPERV_NETVSC
#include "drivers/hyperv.h"
#endif
#include "drivers/usb.h"
#ifdef CONFIG_ACPI
#include "drivers/acpi.h"
#endif
#ifdef CONFIG_PCI_DRIVER_PROBE
#include "drivers/pci_probe.h"
#endif
#ifdef CONFIG_PCI
#include "drivers/pci.h"
#endif
#ifdef CONFIG_VIRTIO_GPU
#include "drivers/virtio_gpu.h"
#endif
#ifdef CONFIG_VIRTIO_RNG
#include "drivers/virtio_rng.h"
#endif
#ifdef CONFIG_VIRTIO_BALLOON
#include "drivers/virtio_balloon.h"
#endif
#ifdef CONFIG_BSD_DRIVER_BRIDGE
#ifdef CONFIG_BSD_DRIVER_ACPICA
#include "compat/freebsd/edgeos/acpica.h"
#endif
#include "compat/freebsd/edgeos/callout.h"
#include "compat/freebsd/edgeos/x86_64_handoff.h"
#endif
#ifdef CONFIG_VIRTIO_CONSOLE
#include "drivers/virtio_console.h"
#endif
#ifdef CONFIG_VIRTIO_INPUT
#include "drivers/virtio_input.h"
#endif
#ifdef CONFIG_RTC
#include "drivers/rtc.h"
#endif
#ifdef CONFIG_HPET
#include "drivers/hpet.h"
#endif
#ifdef CONFIG_APIC
#include "drivers/apic.h"
#endif
#ifdef CONFIG_SMBUS
#include "drivers/smbus.h"
#endif
#ifdef CONFIG_I2C
#include "drivers/i2c.h"
#endif
#ifdef CONFIG_TPM2
#include "drivers/tpm2.h"
#endif
#ifdef CONFIG_WATCHDOG
#include "drivers/watchdog.h"
#endif
#ifdef CONFIG_CPUFREQ_INTEL_PSTATE
#include "drivers/intel_pstate.h"
#endif
#ifdef CONFIG_AUDIO_AC97
#include "drivers/audio.h"
#endif
#ifdef CONFIG_GRAPHICS_BGA
#include "drivers/bga.h"
#endif
#ifdef CONFIG_VMWARE_SVGA
#include "drivers/vmware_svga.h"
#endif
#ifdef CONFIG_GRAPHICS_INTEL
#include "drivers/intel_graphics.h"
#endif
#include "net/lwip_stack.h"
#include "net/native_netdev.h"
#include "stdio.h"
#include "string.h"
#include "arch/x86_64/io_ports.h"
#include "arch/x86_64/boot/multiboot.h"
#include "kernel/boot_command_line.h"
#ifdef CONFIG_NFSD
#include "fs/nfsd.h"
#endif
#include "kernel/boot_logfile.h"
#include "kernel/boot_root.h"
#ifdef CONFIG_BSD_DRIVER_BRIDGE
#include "compat/freebsd/edgeos/bootstrap.h"
#include "compat/freebsd/edgeos/firmware_metadata.h"
#include "compat/freebsd/edgeos/handoff.h"
#include "compat/freebsd/edgeos/isa.h"
#endif
#ifdef CONFIG_INITRAMFS
#include "fs/initramfs.h"
#endif

#include <stdint.h>

#ifndef EDGEOS_KERNEL_RELEASE
#error "EDGEOS_KERNEL_RELEASE must be provided by the build configuration"
#endif

volatile uint32_t g_timer_ticks;
static const char *g_edge_version = EDGEOS_KERNEL_RELEASE;
static int g_has_fb_console;
static char g_boot_init_path[VFS_PATH_MAX];

#ifndef MULTIBOOT2_BOOTLOADER_MAGIC
#define MULTIBOOT2_BOOTLOADER_MAGIC 0x36d76289u
#endif

struct mb2_tag_header {
    uint32_t type;
    uint32_t size;
};

static const char *kernel_cmdline(uint32_t magic, void *mb_info) {
    if (!mb_info) return 0;
    if (magic == MULTIBOOT2_BOOTLOADER_MAGIC) {
        uint8_t *base = (uint8_t *)mb_info;
        struct mb2_tag_header *tag = (struct mb2_tag_header *)(base + 8);
        while (tag->type != 0) {
            if (tag->type == 1 && tag->size > sizeof(*tag)) {
                return (const char *)(tag + 1);
            }
            tag = (struct mb2_tag_header *)((uint8_t *)tag + ((tag->size + 7u) & ~7u));
        }
        return 0;
    }
    if (magic == MULTIBOOT_BOOTLOADER_MAGIC) {
        multiboot_info_t *mb = (multiboot_info_t *)mb_info;
        if ((mb->flags & MULTIBOOT_INFO_CMDLINE) && mb->cmdline) {
            return (const char *)(uintptr_t)mb->cmdline;
        }
    }
    return 0;
}

static void save_kernel_cmdline(uint32_t magic, void *mb_info) {
    const char *cmdline = kernel_cmdline(magic, mb_info);
    kernel_boot_command_line_set(cmdline ? cmdline : "");
}

static void apply_boot_console_preference(void) {
    char console[64];
    int preferred = -1;

    /*
     * Linux permits multiple console= arguments.  Output is sent to all
     * registered consoles, but /dev/console is bound to the last console=
     * device.  Alpine getty and automation depend on that distinction: a VM
     * may show boot logs on both fbcon and ttyS0 while the login terminal is
     * selected only by the final console= token.
     */
    if (kernel_boot_option_get("console", console, sizeof(console)) <= 0)
        return;
    if (strncmp(console, "ttyS0", 5) == 0 &&
        (console[5] == 0 || console[5] == ','))
        preferred = 0;
    else if ((strncmp(console, "tty0", 4) == 0 &&
              (console[4] == 0 || console[4] == ',')) ||
             (strncmp(console, "tty1", 4) == 0 &&
              (console[4] == 0 || console[4] == ',')))
        preferred = 1;
    if (preferred >= 0) {
        syscall_console_set_preferred_line(preferred);
    }
}

static const char *boot_init_name(const char *path) {
    const char *name = path;

    if (!path) return "init";
    while (*path) {
        if (*path == '/' && path[1]) name = path + 1;
        path++;
    }
    return name;
}

#define PIT_CMD_PORT 0x43
#define PIT_CH0_PORT 0x40
#define PIT_INPUT_HZ 1193182u
static void pit_set_rate(uint32_t hz) {
    uint32_t divisor;
    if (hz == 0) hz = EDGE_KERNEL_TIMER_HZ;
    divisor = PIT_INPUT_HZ / hz;
    if (divisor == 0) divisor = 1;
    if (divisor > 0xFFFFu) divisor = 0xFFFFu;
    outportb(PIT_CMD_PORT, 0x36); /* ch0, lobyte/hibyte, mode 3 */
    outportb(PIT_CH0_PORT, (uint8_t)(divisor & 0xFFu));
    outportb(PIT_CH0_PORT, (uint8_t)((divisor >> 8) & 0xFFu));
}

static void timer_handler(REGISTERS *r) {
    uint32_t cpu = x86_smp_current_cpu_id();

#ifdef CONFIG_APIC
    if (r && r->int_no == APIC_TIMER_VECTOR &&
        apic_timer_consume_oneshot()) {
        task_t *task = process_current_task();

        if (task && !task->is_idle) task->need_resched = 1;
        return;
    }
#else
    (void)r;
#endif
    if (edge_kernel_timer_runs_global_work(cpu)) {
        boottime_timer_tick(EDGE_KERNEL_TIMER_HZ);
#ifdef CONFIG_BSD_DRIVER_BRIDGE
        bsd_callout_process_timer_tick();
#endif
        g_timer_ticks++;
#ifdef CONFIG_USB
        usb_poll_irq();
#endif
        syscall_tty_irq_poll();
        if (edge_drm_scanout_refresh_required() ||
            virtio_gpu_presents_pending())
            kernel_display_work_request();
    }
    scheduler_tick();
#ifdef CONFIG_FB_CONSOLE
    if (edge_kernel_timer_runs_global_work(cpu) && g_has_fb_console) {
        if (fb_user_mmap_active()) {
            /*
             * Linux fbdev mmap writes are visible to scanout hardware without
             * a userspace syscall.  EdgeOS' virtio-gpu resource backing buffer
             * needs an explicit transfer/flush.  IRQ context records cadence;
             * syscall, scheduler-idle, and mmap-fault paths consume the work in
             * process context.  Dirty-page walks, shadow comparisons, and
             * synchronous virtio commands must never run on the PIT interrupt
             * stack.  ARM64 follows the same deferred-work contract.
             */
            fb_user_mmap_request_tick_from_irq(g_timer_ticks);
        } else {
            fb_console_request_tick_from_irq(g_timer_ticks);
        }
    }
#endif
}

static void ensure_default_system_files(void) {
    static char tmp[256];
    if (vfs_read_file("/etc/os-release", tmp, sizeof(tmp)) < 0) {
        char content[160];
        int n = 0;
        const char *a = "NAME=EdgeOS\n";
        const char *b = "VERSION=";
        const char *c = "\n";
        while (a[n]) { content[n] = a[n]; n++; }
        for (int i = 0; b[i]; ++i) content[n++] = b[i];
        for (int i = 0; g_edge_version[i]; ++i) content[n++] = g_edge_version[i];
        for (int i = 0; c[i]; ++i) content[n++] = c[i];
        content[n] = 0;
        vfs_write_file("/etc/os-release", content, (uint32_t)n);
    }
    if (vfs_read_file("/etc/passwd", tmp, sizeof(tmp)) < 0) {
        const char *pw =
            "root:x:0:0:root:/root:/bin/sh\n"
            "user:x:1000:1000:user:/home/user:/bin/sh\n";
        vfs_write_file("/etc/passwd", pw, (uint32_t)strlen(pw));
    }
    if (vfs_read_file("/etc/group", tmp, sizeof(tmp)) < 0) {
        const char *gr =
            "root:x:0:\n"
            "user:x:1000:user\n";
        vfs_write_file("/etc/group", gr, (uint32_t)strlen(gr));
    }
    if (vfs_read_file("/etc/shadow", tmp, sizeof(tmp)) < 0) {
        const char *sh =
            "root:$6$edgeos$fBGq3tzKqj1d/Mx7YFi1bR0TF0bggz7XwW6PBmucCNFAQA97VvO95xxyFBL4ENOhKcdxohhDO99GCByHvdluA.:0:0:99999:7:::\n"
            "user:$6$edgeos$Bo9eqxKWhKDkW8Uee.aPu4XIwP8kJ0/xeJ5.D325Br2wlNQockexTBvW1/bKqmbY7PVHYvloDdO1SyY8VJbA10:0:0:99999:7:::\n";
        vfs_write_file("/etc/shadow", sh, (uint32_t)strlen(sh));
    }
    (void)vfs_mkdir("/home");
    (void)vfs_mkdir("/home/user");
}

static void ensure_default_dev_entries(void) {
    static const char *chr_nodes[] = {
        "/dev/console", "/dev/tty", "/dev/tty0", "/dev/ttyS0",
#ifdef CONFIG_VIRTIO_CONSOLE
        "/dev/hvc0",
#endif
#ifdef CONFIG_RTC
        "/dev/rtc", "/dev/rtc0",
#endif
        "/dev/fb0", "/dev/ptmx"
    };
    static const struct {
        const char *path;
        uint32_t minor;
    } memory_nodes[] = {
        { "/dev/null", 3u },
        { "/dev/zero", 5u },
        { "/dev/full", 7u },
        { "/dev/random", 8u },
        { "/dev/urandom", 9u },
    };
    for (int i = 0; i < (int)(sizeof(chr_nodes) / sizeof(chr_nodes[0])); ++i) {
        (void)vfs_touch(chr_nodes[i]);
    }
    for (uint32_t i = 0u;
         i < (uint32_t)(sizeof(memory_nodes) / sizeof(memory_nodes[0]));
         ++i) {
        (void)vfs_mknod(
            memory_nodes[i].path, (uint16_t)(VFS_INODE_CHR | 0666u),
            kernel_file_device_encode(1u, memory_nodes[i].minor));
    }
    for (uint32_t vt = 1u; vt <= EDGE_FB_VT_COUNT; ++vt) {
        char path[12] = "/dev/tty";
        uint32_t offset = 8u;

        if (vt >= 10u) path[offset++] = (char)('0' + vt / 10u);
        path[offset++] = (char)('0' + vt % 10u);
        path[offset] = 0;
        (void)vfs_touch(path);
    }
    for (int i = 0; i < block_count(); ++i) {
        block_device_t *b = block_get(i);
        char path[32];
        int p = 0;
        if (!b || !b->present) continue;
        path[p++] = '/'; path[p++] = 'd'; path[p++] = 'e'; path[p++] = 'v'; path[p++] = '/';
        for (int j = 0; b->name[j] && p < (int)sizeof(path) - 1; ++j) path[p++] = b->name[j];
        path[p] = 0;
        (void)vfs_touch(path);
    }
}

void kmain(uint32_t magic, void *mb_info) {
    int initramfs_root = 0;
    int boot_log_status;

    serial_console_init();
    save_kernel_cmdline(magic, mb_info);
#ifdef CONFIG_BSD_DRIVER_BRIDGE
    bsd_firmware_metadata_reset_smap();
    if (magic == MULTIBOOT_BOOTLOADER_MAGIC && mb_info) {
        const multiboot_info_t *information = mb_info;

        if ((information->flags & MULTIBOOT_INFO_MEM_MAP) != 0) {
            uintptr_t cursor = information->mmap_addr;
            uintptr_t end = cursor + information->mmap_length;

            while (cursor < end) {
                const multiboot_memory_map_t *entry =
                    (const multiboot_memory_map_t *)cursor;
                uintptr_t next = cursor + sizeof(entry->size) +
                    entry->size;

                if (entry->size < sizeof(*entry) - sizeof(entry->size) ||
                    next <= cursor || next > end)
                    break;
                (void)bsd_firmware_metadata_add_smap(entry->addr,
                    entry->len, entry->type);
                cursor = next;
            }
        }
    }
#endif
    boot_log_status = kernel_boot_log_configure();
    boottime_init();
    console_set_kernel_log_timestamps(1);
    printf("[time] clocksource=%s frequency=%llu Hz\n",
           boottime_clocksource_name(),
           (unsigned long long)boottime_clocksource_hz());
    printf("[boot] magic=0x%x mb_info=0x%x\n", magic, (uint32_t)(uintptr_t)mb_info);
#ifdef CONFIG_PCI
    pci_inventory_init();
    printf("[pci] shared inventory functions=%u\n", pci_function_count());
#endif
#ifdef CONFIG_BSD_DRIVER_BRIDGE
    {
        int reserve_error =
            bsd_bridge_x86_64_reserve_native_devices(
                kernel_boot_command_line_get());

        if (reserve_error != 0)
            printf("[bsd-bridge] native device reservation failed: %d\n",
                reserve_error);
    }
#endif
    int has_fb = 0;
#ifdef CONFIG_FB_CONSOLE
    has_fb = fb_init_from_bootinfo(magic, mb_info) ? 1 : 0;
#ifdef CONFIG_GRAPHICS_BGA
    if (bga_init(has_fb) == 0 && !has_fb) {
        has_fb = 1;
    }
#endif
#ifdef CONFIG_VMWARE_SVGA
    if (vmware_svga_init(has_fb) == 0 && !has_fb) {
        has_fb = 1;
    }
#endif
#ifdef CONFIG_GRAPHICS_INTEL
    (void)intel_graphics_probe_init(has_fb);
#endif
#ifdef CONFIG_VIRTIO_GPU
    if (virtio_gpu_init() == 0) {
        has_fb = 1;
    }
#endif
#endif
    g_has_fb_console = has_fb;
#ifdef CONFIG_FB_CONSOLE
    if (has_fb) console_set_backend(&FB_CONSOLE);
    else
#endif
    console_set_backend(&VGA_CONSOLE);
    console_init(COLOR_WHITE, COLOR_BLACK);

    bootlog_init();
    if (boot_log_status < 0)
        bootlog_stage("bootlog: invalid loglevel or logfile option");
    bootlog_stage("Initializing GDT");

    gdt_init();
    bootlog_stage("Initializing IDT");
    idt_init();
    bootlog_stage("Initializing keyboard");
    keyboard_init();
    isr_register_interrupt_handler(IRQ_BASE + 0, timer_handler);
    pit_set_rate(EDGE_KERNEL_TIMER_HZ);
    bootlog_stage("Initializing syscalls");
    syscall_init();
    apply_boot_console_preference();
    printf("[boot] cmdline=\"%s\" default_console_line=%d\n",
           kernel_boot_command_line_get(), syscall_console_default_line());
    __asm__ __volatile__("sti");
    bootlog_stage("Initializing memory");
    meminfo_init(magic, mb_info);
    process_mmap_backing_init(magic, mb_info);
    if (syscall_runtime_init() < 0) {
        printf("[syscall-runtime] ERROR runtime kernel backing unavailable; Linux socket ABI degraded\n");
    }
#ifdef CONFIG_ACPI
    bootlog_stage("Initializing ACPI");
    acpi_init(magic, mb_info);
#ifdef CONFIG_APIC
    bootlog_stage("Initializing APIC");
    apic_init();
    x86_smp_discover();
#endif
#endif
#ifdef CONFIG_VIRTIO_RNG
    bootlog_stage("Initializing VirtIO RNG");
    virtio_rng_init();
#endif
#ifdef CONFIG_VIRTIO_BALLOON
    bootlog_stage("Initializing VirtIO balloon");
    virtio_balloon_init();
#endif
#ifdef CONFIG_VIRTIO_CONSOLE
    bootlog_stage("Initializing VirtIO console");
    virtio_console_init();
#endif
#ifdef CONFIG_VIRTIO_INPUT
    bootlog_stage("Initializing VirtIO input");
    virtio_input_init();
#endif
#ifdef CONFIG_RTC
    bootlog_stage("Initializing RTC");
    rtc_init();
#endif
#ifdef CONFIG_HPET
    bootlog_stage("Initializing HPET");
    hpet_init();
#endif
#ifdef CONFIG_SMBUS
    bootlog_stage("Initializing SMBus");
    smbus_init();
#endif
#ifdef CONFIG_I2C
    bootlog_stage("Initializing I2C");
    i2c_init();
#endif
#ifdef CONFIG_TPM2
    bootlog_stage("Initializing TPM2");
    tpm2_init();
#endif
#ifdef CONFIG_WATCHDOG
    bootlog_stage("Initializing watchdog");
    watchdog_init();
#endif
#ifdef CONFIG_CPUFREQ_INTEL_PSTATE
    bootlog_stage("Initializing Intel P-State");
    intel_pstate_init();
#endif
#if defined(CONFIG_AUDIO_AC97) || defined(CONFIG_AUDIO_HDA) || defined(CONFIG_USB_AUDIO)
    bootlog_stage("Initializing audio");
    audio_init();
#endif
#if defined(CONFIG_PCI) && defined(CONFIG_PCI_DRIVER_PROBE)
    bootlog_stage("Probing PCI driver coverage");
    pci_driver_probe_init();
#endif
    bootlog_stage("Detecting block devices");
    dev_init(magic, mb_info);
    bootlog_stage("Initializing network");
#ifdef CONFIG_NET
#ifdef CONFIG_WIFI_INTEL_IWLWIFI
    iwlwifi_init();
#endif
#ifdef CONFIG_VMWARE_VMXNET3
    vmxnet3_probe_init();
#endif
#ifdef CONFIG_HYPERV_NETVSC
    hyperv_probe_init();
#endif
#if defined(CONFIG_E1000) || defined(CONFIG_VIRTIO_NET)
    e1000_init();
    if (edge_native_netdev_register() != 0)
        printf("[net] native network registration failed\n");
#else
    printf("[boot] networking enabled with no compiled NIC driver\n");
#endif
    lwip_stack_init();
#else
    printf("[boot] networking disabled by CONFIG_NET\n");
#endif
    bootlog_stage("Initializing USB");
#ifdef CONFIG_USB
    usb_init();
#else
    printf("[boot] USB disabled by CONFIG_USB\n");
#endif
    bootlog_stage("Initializing VFS");
    vfs_init();

    bootlog_stage("Mounting root filesystem");
    {
        int mounted = 0;

#ifdef CONFIG_INITRAMFS
        if (initramfs_multiboot_has_archive(magic, mb_info)) {
            printf("[fs] initramfs cpio archive detected, mounting tmpfs root\n");
            if (initramfs_mount_root() == 0 &&
                initramfs_unpack_multiboot(magic, mb_info) >= 0) {
                mounted = 1;
                initramfs_root = 1;
            } else {
                printf("[fs] initramfs mount/unpack failed, trying block root\n");
            }
        }
#endif

        if (!mounted) {
            kernel_boot_root_result_t root_result;

            if (kernel_boot_root_mount(&root_result) == 0) {
                printf("[fs] root mounted from /dev/%s as %s (%s)\n",
                       root_result.device->name,
                       root_result.filesystem_type,
                       (root_result.mount_flags & VFS_MOUNT_READONLY) ?
                           "read-only" : "read-write");
                mounted = 1;
            }
        }

        if (!mounted) {
            printf("[fs] root filesystem mount failed, falling back to mem fs\n");
#ifdef CONFIG_FS_FAT32
            vfs_mount("mem", "/", "fat32");
#else
            vfs_mount("mem", "/", "tmpfs");
#endif
        }
    }
    (void)kernel_boot_log_start();
    vfs_mkdir("/etc");
    vfs_mkdir("/etc/systemd");
    vfs_mkdir("/etc/systemd/system");
    vfs_mkdir("/root");
    vfs_mkdir("/boot");
    vfs_mkdir("/dev");
    vfs_mkdir("/dev/pts");
    vfs_mkdir("/mnt");
    vfs_mkdir("/lib");
    vfs_mkdir("/lib/systemd");
    vfs_mkdir("/lib/systemd/system");
    vfs_mkdir("/usr");
    vfs_mkdir("/usr/lib");
    vfs_mkdir("/usr/lib/systemd");
    vfs_mkdir("/usr/lib/systemd/system");
    vfs_mkdir("/var");
    vfs_mkdir("/var/run");
    vfs_mkdir("/run");
    ensure_default_dev_entries();
    if (kernel_boot_mount_api_filesystems() < 0)
        printf("[fs] failed to mount API filesystems\n");
    if (vfs_read_file("/etc/hostname", (char[8]){0}, 1) < 0) {
        (void)vfs_write_file("/etc/hostname", "edgeos\n", 7);
    }
#ifdef CONFIG_NET
    (void)lwip_stack_reload_system_config();
#endif
#ifdef CONFIG_NFSD
    if (edge_nfsd_boot_start() < 0)
        printf("[nfsd] boot startup failed\n");
#endif
    /* Do not mutate rootfs before launching init. On LiveCD/ramdisk this can
     * destabilize startup if userspace image is not expecting writes yet. */

    process_init();

#ifdef CONFIG_BSD_DRIVER_BRIDGE
    bootlog_stage("Initializing BSD driver bridge");
    {
        int bridge_error = bsd_bridge_bootstrap(0);

        if (bridge_error != 0) {
            bsd_bridge_bootstrap_status_t bridge_status;

            bsd_bridge_bootstrap_get_status(&bridge_status);
            printf("[bsd-bridge] startup failed: %d stage=%d\n",
                bridge_error, (int)bridge_status.stage);
            (void)bsd_bridge_x86_64_release_reserved_native_devices();
        }
        else {
            bsd_bridge_handoff_status_t handoff_status;
            bsd_bridge_bootstrap_status_t bridge_status;

#ifdef CONFIG_BSD_DRIVER_ACPICA
            bridge_error = bsd_acpica_runtime_initialize();
            if (bridge_error != 0) {
                printf("[bsd-bridge] ACPICA runtime failed: %d\n",
                    bridge_error);
            }
#endif
            if (kernel_boot_option_enabled("bsd_bridge.i8042", 0)) {
                bsd_bridge_bootstrap_get_status(&bridge_status);
                bridge_error = bsd_isa_i8042_attach(
                    bridge_status.root);
                if (bridge_error != 0)
                    printf("[bsd-bridge] i8042 attach failed: %d\n",
                        bridge_error);
                else
                    printf("[bsd-bridge] i8042 input attached\n");
            }
            bridge_error = bsd_bridge_x86_64_handoff_start(
                kernel_boot_command_line_get(), &handoff_status);
            if (bridge_error != 0) {
                printf("[bsd-bridge] device handoff failed: %d\n",
                    bridge_error);
            } else if (handoff_status.enabled) {
                printf("[bsd-bridge] runtime ready; pci selected=%u "
                    "attached=%u\n",
                    (uint32_t)handoff_status.pci.selected,
                    (uint32_t)handoff_status.pci.attached);
            } else {
                printf("[bsd-bridge] runtime ready; device handoff disabled\n");
            }
        }
    }
#endif

#if defined(CONFIG_SMP) && defined(CONFIG_APIC)
    isr_register_interrupt_handler(APIC_TIMER_VECTOR, timer_handler);
    bootlog_stage("Starting secondary CPUs");
    (void)x86_smp_start_secondaries();
#endif

    bootlog_stage("INIT: Starting configured init");
    {
        char *init_argv[] = { 0, 0 };
        char *init_envp[] = {
            "HOME=/",
            "PATH=/usr/libexec/rc/bin:/bin:/sbin:/usr/bin:/usr/sbin",
            "TERM=linux",
            "EINFO_COLOR=YES",
            0
        };
        int init_pid;

        if (kernel_boot_init_path(
                initramfs_root, g_boot_init_path,
                sizeof(g_boot_init_path)) < 0) {
            printf("[init] invalid init path in command line\n");
            for (;;) __asm__ __volatile__("hlt");
        }
        init_argv[0] = (char *)boot_init_name(g_boot_init_path);
        init_pid = process_spawn_exec_env(
            g_boot_init_path, 1, init_argv, 4, init_envp);
        if (init_pid < 0 &&
            !kernel_boot_option_present("init") &&
            !(initramfs_root && kernel_boot_option_present("rdinit"))) {
            printf("[init] default init missing, trying /bin/edgebox\n");
            char *edgebox_argv[] = { "edgebox", 0 };
            init_pid = process_spawn_exec_env("/bin/edgebox", 1, edgebox_argv, 4, init_envp);
        }

        if (init_pid < 0) {
            printf("[init] failed to spawn init process\n");
            for (;;) __asm__ __volatile__("hlt");
        }

        kernel_boot_log_flush_now();
        (void)init_pid;
        /*
         * The bootstrap task executes on the architecture boot stack, not on
         * its task-owned kernel stack.  It has no continuation after handing
         * control to userspace and must never become runnable again through a
         * stale waiter notification.  Retire it as terminal before switching
         * to PID 1; the per-CPU idle tasks provide the persistent kernel idle
         * context.
         */
        scheduler_task_set_zombie(process_current_task());
        scheduler_yield();
        for (;;) __asm__ __volatile__("sti; hlt");
    }
}
