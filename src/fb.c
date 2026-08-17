#include "fb.h"
#include "arch/x86_64/boot/multiboot.h"
#include "string.h"
#include <stddef.h>
#include "console.h"
#include "fb_console.h"
#include "dev/fbdev.h"
#include "stdio.h" 
#include "font8x8_basic.h"
#include "sys/boottime.h"
#include "kernel/arch_cpu.h"
#include "mm/arch_vm.h"
#include "sys/mmio.h"
#include "display.h"
#include "kernel/drm_runtime.h"
#include "kernel/deferred_work.h"
#include "kernel/smp.h"

#ifndef MULTIBOOT2_BOOTLOADER_MAGIC
#define MULTIBOOT2_BOOTLOADER_MAGIC 0x36d76289u
#endif

fb_t fb = {0};

static uint8_t *fb_backbuffer = NULL;
/*
 * Keep the early console off slow firmware framebuffer apertures.  Raspberry
 * Pi 5 exposes its 1920x1080 RGB565 scanout through GOP; the historical
 * 1024x768 buffer was too small, so glyph rendering fell back to thousands of
 * individual aperture stores per line.  Sixteen MiB covers common 1080p and
 * 1440p boot modes while retaining deterministic allocation before the kernel
 * heap is available.
 */
#define FB_BACKBUFFER_MAX (16u * 1024u * 1024u)
static uint8_t fb_backbuffer_storage[FB_BACKBUFFER_MAX];
#define FB_REMAP_VIRT_BASE 0x00000000FC000000ULL
#define FB_REMAP_MAX_PAGES 32
#define FB_USER_MMAP_MAX_DIRTY_ROWS 4096u
#define FB_USER_MMAP_DIRTY_WORDS ((FB_USER_MMAP_MAX_DIRTY_ROWS + 31u) / 32u)
#define FB_USER_MMAP_SHADOW_MAX (16u * 1024u * 1024u)
#define FB_USER_MMAP_FRAME_US 16667ull
#define FB_USER_MMAP_PTE_SCAN_US 10000ull
#define FB_USER_MMAP_SHADOW_SCAN_US FB_USER_MMAP_FRAME_US
#define FB_USER_MMAP_SHADOW_ROWS_PER_SCAN 128u
#define FB_USER_MMAP_PRESENT_INTERVAL_US 10000ull
#define FB_USER_MMAP_DIRTY_IDLE_US 2000ull
#define FB_USER_MMAP_DIRTY_MAX_LATENCY_US FB_USER_MMAP_FRAME_US
#define PAGE_PRESENT 0x001ULL
#define PAGE_WRITE   0x002ULL
#define PAGE_PS      0x080ULL

#define ALIGN_UP(v, a) (((v) + (a) - 1) & ~((a) - 1))
#ifndef FB_DEBUG
#define FB_DEBUG 0
#endif
#ifndef EDGE_GUI_DEEP_TRACE
#define EDGE_GUI_DEEP_TRACE 0
#endif
static inline int fb_bpp_bytes(void) { return (fb.bpp + 7) / 8; }
static uint64_t g_fb_remap_phys_base;
static uint32_t g_fb_remap_pages;
static int g_fb_remap_active;
static uint64_t g_fb_remap_pt[FB_REMAP_MAX_PAGES][512] __attribute__((aligned(4096)));
static uint64_t g_fb_phys_base;
static uint32_t g_fb_phys_pages;
static uint64_t g_fb_phys_offset;
static int g_fb_user_mmap_active;
static int g_fb_user_mmap_log_budget = EDGE_GUI_DEEP_TRACE ? 16 : 2;
static int g_fb_user_mmap_checksum_log_budget = EDGE_GUI_DEEP_TRACE ? 24 : 2;
static int g_fb_user_mmap_periodic_log_budget = EDGE_GUI_DEEP_TRACE ? 24 : 0;
static int g_fb_user_mmap_tick_log_budget = EDGE_GUI_DEEP_TRACE ? 16 : 0;
static uint32_t g_fb_user_mmap_dirty_flushes;
static uint32_t g_fb_user_mmap_full_flushes;
static uint64_t g_fb_user_mmap_next_flush_us;
static uint64_t g_fb_user_mmap_next_forced_flush_us;
static uint32_t g_fb_user_mmap_skip_flushes;
static int g_fb_user_mmap_dirty_valid;
static uint32_t g_fb_user_mmap_dirty_y0;
static uint32_t g_fb_user_mmap_dirty_y1;
static uint32_t g_fb_user_mmap_dirty_rows[FB_USER_MMAP_DIRTY_WORDS];
static uint64_t g_fb_user_mmap_dirty_first_us;
static uint64_t g_fb_user_mmap_dirty_last_us;
static uint8_t g_fb_user_mmap_shadow[FB_USER_MMAP_SHADOW_MAX];
static uint32_t g_fb_user_mmap_shadow_bytes;
static int g_fb_user_mmap_shadow_valid;
static uint32_t g_fb_user_mmap_shadow_next_y;
static uint64_t g_fb_user_mmap_next_shadow_scan_us;
static uint64_t g_fb_user_mmap_next_pte_scan_us;
static volatile int g_fb_user_mmap_deferred_pending;
static volatile uint32_t g_fb_user_mmap_deferred_ticks;
extern uint64_t pd_table3[512];
void process_user_fbdev_writeprotect_all(void);
void process_user_fbdev_collect_dirty_all(void);
static uint32_t fb_sample_pixel(uint32_t x, uint32_t y);
static uint32_t fb_sample_nonzero_bytes(uint32_t y0, uint32_t y1);
static int g_direct_display_owner;

static void fb_register_direct_display(void) {
    display_backend_t backend = {
        .name = "direct-framebuffer",
        .owner = &g_direct_display_owner,
    };

    (void)display_backend_register(&backend);
}

static int fb_user_mmap_requires_present(void) {
    if (display_backend_requires_present()) return 1;
#if defined(__aarch64__)
    /*
     * ARM64 firmware scanout is a cacheable physical aperture.  Userspace
     * writes need the same deferred dirty-row cleaning as a transferred
     * backend even though no device command is required after the clean.
     */
    return 1;
#endif
    /*
     * Coherent direct framebuffers do not need a transfer or cache-clean
     * boundary after userspace stores.
     */
    return 0;
}

int fb_user_mmap_write_tracking_required(void) {
    return fb_user_mmap_requires_present() && arch_vm_write_notify_supported();
}

static void fb_user_mmap_dirty_rows_clear(void) {
    memset(g_fb_user_mmap_dirty_rows, 0, sizeof(g_fb_user_mmap_dirty_rows));
    g_fb_user_mmap_dirty_first_us = 0;
    g_fb_user_mmap_dirty_last_us = 0;
}

static void fb_user_mmap_dirty_row_set(uint32_t y) {
    if (y >= FB_USER_MMAP_MAX_DIRTY_ROWS) return;
    g_fb_user_mmap_dirty_rows[y >> 5] |= (1u << (y & 31u));
}

static int fb_user_mmap_dirty_row_test(uint32_t y) {
    if (y >= FB_USER_MMAP_MAX_DIRTY_ROWS) return 0;
    return (g_fb_user_mmap_dirty_rows[y >> 5] & (1u << (y & 31u))) != 0;
}

static void fb_user_mmap_mark_dirty_rows(uint32_t y0, uint32_t y1) {
    uint64_t now_us;
    if (!fb.height) return;
    if (y0 >= fb.height) y0 = fb.height - 1u;
    if (y1 >= fb.height) y1 = fb.height - 1u;
    if (y1 < y0) return;
    now_us = boottime_monotonic_us();
    if (!g_fb_user_mmap_dirty_valid) {
        g_fb_user_mmap_dirty_y0 = y0;
        g_fb_user_mmap_dirty_y1 = y1;
        g_fb_user_mmap_dirty_valid = 1;
        g_fb_user_mmap_dirty_first_us = now_us;
    } else {
        if (y0 < g_fb_user_mmap_dirty_y0) g_fb_user_mmap_dirty_y0 = y0;
        if (y1 > g_fb_user_mmap_dirty_y1) g_fb_user_mmap_dirty_y1 = y1;
    }
    g_fb_user_mmap_dirty_last_us = now_us;
    if (fb.height <= FB_USER_MMAP_MAX_DIRTY_ROWS) {
        for (uint32_t y = y0; y <= y1; ++y) fb_user_mmap_dirty_row_set(y);
    }
}

static void fb_user_mmap_shadow_reset(void) {
    g_fb_user_mmap_shadow_valid = 0;
    g_fb_user_mmap_shadow_bytes = 0;
    g_fb_user_mmap_shadow_next_y = 0;
    g_fb_user_mmap_next_shadow_scan_us = 0;
    g_fb_user_mmap_next_pte_scan_us = 0;
}

static void fb_user_mmap_shadow_scan(uint64_t now_us) {
    uint64_t bytes64;
    uint32_t bytes;
    uint32_t first = 0;
    uint32_t last = 0;
    uint32_t scan_y0;
    uint32_t scan_y1;
    int any = 0;
    static int shadow_log_budget = EDGE_GUI_DEEP_TRACE ? 24 : 0;

    if (!fb.addr || !fb.pitch || !fb.height) return;
    bytes64 = (uint64_t)fb.pitch * (uint64_t)fb.height;
    if (bytes64 == 0 || bytes64 > FB_USER_MMAP_SHADOW_MAX) return;
    if (g_fb_user_mmap_next_shadow_scan_us &&
        now_us < g_fb_user_mmap_next_shadow_scan_us) {
        return;
    }
    /*
     * This is EdgeOS' deferred-I/O safety net for fbdev mmap.  Linux fbdev
     * scanout hardware observes stores directly; virtio-gpu needs an explicit
     * transfer.  Hardware dirty bits are cheap when they are reliable, but X11
     * can keep writable framebuffer translations hot for long periods.  A
     * bounded shadow diff of the real aperture catches those stores.  Keep it
     * as a fallback: the normal path is the Linux-style fbdev write-fault dirty
     * list, and this scan covers stale TLBs or old mappings that were writable
     * before the presenter re-armed deferred I/O.  Never compare the full
     * aperture from a timer/syscall pump after the seed pass.  At 1600x1000x32,
     * a whole-screen memcmp/memcpy loop is large enough to starve DBus/GTK and
     * makes a working desktop look hung.  Walk a bounded band each frame so a
     * full fallback pass completes quickly without monopolizing the VM.
     */
    g_fb_user_mmap_next_shadow_scan_us = now_us + FB_USER_MMAP_SHADOW_SCAN_US;
    bytes = (uint32_t)bytes64;
    if (!g_fb_user_mmap_shadow_valid ||
        g_fb_user_mmap_shadow_bytes != bytes) {
        /*
         * The first shadow sample is also a Linux fbdev visibility boundary.
         * On real fbdev scanout, pixels written before the kernel notices the
         * mmap are already visible.  On virtio-gpu, if hardware dirty bits were
         * missed before this shadow was armed, simply seeding the shadow would
         * remember the new pixels without ever transferring them to the host,
         * leaving Xorg/XFCE black until a later expose changes the buffer.
         * Mark nonzero rows dirty while seeding so the same tick presents the
         * initial mmap contents without relying on userspace repaint hacks.
         */
        for (uint32_t y = 0; y < fb.height; ++y) {
            const uint8_t *row = fb.addr + (uint64_t)y * fb.pitch;
            for (uint32_t x = 0; x < fb.pitch; ++x) {
                if (row[x] == 0) continue;
                if (!any) first = y;
                last = y;
                any = 1;
                fb_user_mmap_dirty_row_set(y);
                break;
            }
        }
        memcpy(g_fb_user_mmap_shadow, fb.addr, bytes);
        g_fb_user_mmap_shadow_bytes = bytes;
        g_fb_user_mmap_shadow_valid = 1;
        g_fb_user_mmap_shadow_next_y = 0;
        if (any) fb_user_mmap_mark_dirty_rows(first, last);
        if (shadow_log_budget > 0) {
            printf("[fb-shadow] seed bytes=%u dirty=%d y=%u..%u size=%ux%u pitch=%u p00=0x%x mid=0x%x budget=%d\n",
                   bytes, any, first, last,
                   fb.width, fb.height, fb.pitch,
                   fb_sample_pixel(0, 0),
                   fb_sample_pixel(fb.width / 2, fb.height / 2),
                   shadow_log_budget - 1);
            shadow_log_budget--;
        }
        return;
    }

    scan_y0 = g_fb_user_mmap_shadow_next_y;
    if (scan_y0 >= fb.height) scan_y0 = 0;
    scan_y1 = scan_y0 + FB_USER_MMAP_SHADOW_ROWS_PER_SCAN;
    if (scan_y1 > fb.height) scan_y1 = fb.height;
    g_fb_user_mmap_shadow_next_y = scan_y1;
    if (g_fb_user_mmap_shadow_next_y >= fb.height) g_fb_user_mmap_shadow_next_y = 0;

    for (uint32_t y = scan_y0; y < scan_y1; ++y) {
        uint32_t off = y * fb.pitch;
        if (memcmp(g_fb_user_mmap_shadow + off, fb.addr + off, fb.pitch) != 0) {
            memcpy(g_fb_user_mmap_shadow + off, fb.addr + off, fb.pitch);
            if (!any) first = y;
            last = y;
            any = 1;
            fb_user_mmap_dirty_row_set(y);
        }
    }
    if (any) {
        fb_user_mmap_mark_dirty_rows(first, last);
        if (shadow_log_budget > 0) {
            printf("[fb-shadow] changed y=%u..%u p00=0x%x mid=0x%x panel=0x%x budget=%d\n",
                   first, last,
                   fb_sample_pixel(0, 0),
                   fb_sample_pixel(fb.width / 2, fb.height / 2),
                   fb_sample_pixel(fb.width > 32 ? 32 : 0, fb.height > 16 ? 16 : 0),
                   shadow_log_budget - 1);
            shadow_log_budget--;
        }
    }
}

static uint32_t fb_sample_pixel(uint32_t x, uint32_t y) {
    const uint8_t *row;

    if (!fb.addr || x >= fb.width || y >= fb.height || fb.bpp != 32) return 0;
    row = fb.addr + (uint64_t)y * fb.pitch;
    return ((const uint32_t *)row)[x];
}

static uint32_t fb_sample_nonzero_bytes(uint32_t y0, uint32_t y1) {
    uint32_t count = 0;
    uint32_t budget = 4096;

    if (!fb.addr || !fb.pitch || !fb.height) return 0;
    if (y0 >= fb.height) y0 = fb.height - 1u;
    if (y1 >= fb.height) y1 = fb.height - 1u;
    if (y1 < y0) return 0;

    for (uint32_t y = y0; y <= y1 && budget; ++y) {
        const uint8_t *row = fb.addr + (uint64_t)y * fb.pitch;
        uint32_t step = fb.pitch / 64u;
        if (step == 0) step = 1;
        for (uint32_t x = 0; x < fb.pitch && budget; x += step, --budget) {
            if (row[x] != 0) count++;
        }
    }
    return count;
}

#if defined(__x86_64__)
static inline uint64_t read_cr3(void) {
    uint64_t v;
    __asm__ __volatile__("mov %%cr3, %0" : "=r"(v));
    return v;
}

static inline void write_cr3(uint64_t v) {
    __asm__ __volatile__("mov %0, %%cr3" :: "r"(v) : "memory");
}
#endif

static void fb_clear_remap_window(void) {
#if defined(__x86_64__)
    for (uint32_t i = 0; i < FB_REMAP_MAX_PAGES; ++i) {
        uint64_t p = FB_REMAP_VIRT_BASE + ((uint64_t)i << 21);
        pd_table3[480 + i] = (p & 0x000FFFFFFFFFF000ULL) |
                             PAGE_PRESENT | PAGE_WRITE | PAGE_PS;
    }
#endif
    g_fb_remap_active = 0;
    g_fb_remap_phys_base = 0;
    g_fb_remap_pages = 0;
}

static int fb_install_kernel_remap(uint64_t phys_base, uint64_t offset,
                                   uint32_t pages) {
#if defined(__x86_64__)
    (void)offset;
    if (pages == 0 || pages > FB_REMAP_MAX_PAGES) return 0;

    /*
     * Linux drivers access framebuffer/device memory through kernel mappings
     * that remain valid regardless of the current userspace page table.  EdgeOS
     * enters fbdev presentation from timer/syscall paths while a Linux process
     * CR3 is loaded, so fb.addr must not be a low identity address that can be
     * hidden or aliased by userspace VM layout.  Keep the user-visible fbdev
     * mmap aperture separate; this remap is supervisor-only kernel access.
     */
    for (uint32_t i = 0; i < pages; ++i) {
        for (uint32_t j = 0; j < 512; ++j) {
            uint64_t p = phys_base + ((uint64_t)i << 21) + ((uint64_t)j << 12);
            g_fb_remap_pt[i][j] = (p & 0x000FFFFFFFFFF000ULL) |
                                  PAGE_PRESENT | PAGE_WRITE;
        }
        pd_table3[480 + i] = ((uint64_t)(uintptr_t)&g_fb_remap_pt[i][0]) |
                             PAGE_PRESENT | PAGE_WRITE;
    }
    for (uint32_t i = pages; i < FB_REMAP_MAX_PAGES; ++i) {
        uint64_t p = FB_REMAP_VIRT_BASE + ((uint64_t)i << 21);
        pd_table3[480 + i] = (p & 0x000FFFFFFFFFF000ULL) |
                             PAGE_PRESENT | PAGE_WRITE | PAGE_PS;
    }
    write_cr3(read_cr3());
    g_fb_remap_active = 1;
    g_fb_remap_phys_base = phys_base;
    g_fb_remap_pages = pages;
    return 1;
#elif defined(__aarch64__)
    (void)phys_base;
    (void)offset;
    (void)pages;
    return 0;
#else
#error "fb_install_kernel_remap needs an architecture implementation"
#endif
}

static uint8_t *fb_kernel_address_for_physical(uint64_t physical_addr) {
#if defined(__x86_64__)
    /*
     * Low PCI apertures overlap the Linux userspace mmap arena in a process
     * CR3.  Keep kernel drawing on the supervisor-only linear alias while
     * fbdev PTEs continue to contain the real bus/physical address.
     */
    return (uint8_t *)edge_mmio_low_alias(physical_addr);
#elif defined(__aarch64__)
    /* Generic UEFI installs the GOP aperture in the EL1 physical map. */
    return (uint8_t *)(uintptr_t)physical_addr;
#else
#error "fb_kernel_address_for_physical needs an architecture implementation"
#endif
}

static int fb_install_boot_framebuffer(uint64_t addr, uint32_t pitch,
                                       uint32_t width, uint32_t height,
                                       uint32_t bpp, uint32_t r_pos,
                                       uint32_t r_size, uint32_t g_pos,
                                       uint32_t g_size, uint32_t b_pos,
                                       uint32_t b_size) {
    uint64_t phys_base;
    uint64_t offset;
    uint64_t size;
    uint64_t total;
    uint32_t pages;

    if (!addr || !pitch || !width || !height) return 0;
    if (bpp != 16u && bpp != 24u && bpp != 32u) return 0;
    if (!r_size || !g_size || !b_size || r_size > 8u || g_size > 8u || b_size > 8u) return 0;
    if (r_pos + r_size > bpp || g_pos + g_size > bpp || b_pos + b_size > bpp) return 0;

    display_backend_reset();
    fb.addr = fb_kernel_address_for_physical(addr);
    fb.pitch = pitch;
    fb.width = width;
    fb.height = height;
    fb.bpp = bpp;
    fb.r_pos = r_pos;
    fb.g_pos = g_pos;
    fb.b_pos = b_pos;
    fb.r_mask = ((1u << r_size) - 1u) << fb.r_pos;
    fb.g_mask = ((1u << g_size) - 1u) << fb.g_pos;
    fb.b_mask = ((1u << b_size) - 1u) << fb.b_pos;
    fb_backbuffer = NULL;
    fb_clear_remap_window();

    phys_base = addr & ~0x1FFFFFULL;
    offset = addr - phys_base;
    size = (uint64_t)pitch * (uint64_t)height;
    total = offset + size;
    pages = (uint32_t)((total + 0x1FFFFFULL) >> 21);
    if (pages == 0) return 0;
    g_fb_phys_base = phys_base;
    g_fb_phys_offset = offset;
    g_fb_phys_pages = pages;

    if (!fb_install_kernel_remap(phys_base, offset, pages) &&
        addr > 0xFFFFFFFFULL)
        return 0;
    fb_register_direct_display();

    return 1;
}

struct multiboot_tag {
    uint32_t type;
    uint32_t size;
};

struct multiboot_tag_framebuffer {
    struct multiboot_tag tag;
    uint64_t framebuffer_addr;
    uint32_t framebuffer_pitch;
    uint32_t framebuffer_width;
    uint32_t framebuffer_height;
    uint8_t framebuffer_bpp;
    uint8_t framebuffer_type;
    uint16_t reserved;
    union {
        struct {
            uint32_t framebuffer_palette_addr;
            uint16_t framebuffer_palette_num_colors;
        };
        struct {
            uint8_t framebuffer_red_field_position;
            uint8_t framebuffer_red_mask_size;
            uint8_t framebuffer_green_field_position;
            uint8_t framebuffer_green_mask_size;
            uint8_t framebuffer_blue_field_position;
            uint8_t framebuffer_blue_mask_size;
        };
    };
};

static uint32_t fb_argb_to_pixel(uint32_t argb) {
    uint32_t r = (argb >> 16) & 0xFF;
    uint32_t g = (argb >> 8) & 0xFF;
    uint32_t b = argb & 0xFF;
    uint32_t r_max = fb.r_pos < 32u ? fb.r_mask >> fb.r_pos : 0;
    uint32_t g_max = fb.g_pos < 32u ? fb.g_mask >> fb.g_pos : 0;
    uint32_t b_max = fb.b_pos < 32u ? fb.b_mask >> fb.b_pos : 0;
    uint32_t pixel = (((r * r_max + 127u) / 255u) << fb.r_pos) & fb.r_mask;
    pixel |= (((g * g_max + 127u) / 255u) << fb.g_pos) & fb.g_mask;
    pixel |= (((b * b_max + 127u) / 255u) << fb.b_pos) & fb.b_mask;
    return pixel;
}

bool fb_init_from_multiboot2(void *mb_info) {
    if (!mb_info)
        return false;
    uint8_t *ptr = (uint8_t *)mb_info;
    struct multiboot_tag *tag = (struct multiboot_tag *)(ptr + 8);
    while (tag->type != 0) {
        if (tag->type == 8) {
            struct multiboot_tag_framebuffer *fbtag = (struct multiboot_tag_framebuffer *)tag;
            if (fbtag->framebuffer_type != 1)
                return false;
            if (!fb_install_boot_framebuffer(fbtag->framebuffer_addr,
                                             fbtag->framebuffer_pitch,
                                             fbtag->framebuffer_width,
                                             fbtag->framebuffer_height,
                                             fbtag->framebuffer_bpp,
                                             fbtag->framebuffer_red_field_position,
                                             fbtag->framebuffer_red_mask_size,
                                             fbtag->framebuffer_green_field_position,
                                             fbtag->framebuffer_green_mask_size,
                                             fbtag->framebuffer_blue_field_position,
                                             fbtag->framebuffer_blue_mask_size)) {
                return false;
            }
            printf("[fb] multiboot2 framebuffer %ux%u pitch=%u bpp=%u addr=0x%llx\n",
                   fb.width, fb.height, fb.pitch, fb.bpp,
                   (unsigned long long)fbtag->framebuffer_addr);
            return true;
        }
        tag = (struct multiboot_tag *)((uint8_t *)tag + ALIGN_UP(tag->size, 8));
    }
    return false;
}

static bool fb_init_from_multiboot1(multiboot_info_t *mbi) {
    if (!mbi) return false;
    if (!(mbi->flags & MULTIBOOT_INFO_FRAMEBUFFER_INFO)) return false;
    if (mbi->framebuffer_type != MULTIBOOT_FRAMEBUFFER_TYPE_RGB) return false;
    if (!fb_install_boot_framebuffer(mbi->framebuffer_addr,
                                     mbi->framebuffer_pitch,
                                     mbi->framebuffer_width,
                                     mbi->framebuffer_height,
                                     mbi->framebuffer_bpp,
                                     mbi->framebuffer_red_field_position,
                                     mbi->framebuffer_red_mask_size,
                                     mbi->framebuffer_green_field_position,
                                     mbi->framebuffer_green_mask_size,
                                     mbi->framebuffer_blue_field_position,
                                     mbi->framebuffer_blue_mask_size)) {
        return false;
    }
#ifdef CONFIG_GRAPHICS_VBE
    if (mbi->flags & MULTIBOOT_INFO_VBE_INFO) {
        printf("[fb] VBE framebuffer mode=0x%x %ux%u pitch=%u bpp=%u addr=0x%llx\n",
               mbi->vbe_mode, fb.width, fb.height, fb.pitch, fb.bpp,
               (unsigned long long)mbi->framebuffer_addr);
    } else
#endif
    {
        printf("[fb] multiboot1 framebuffer %ux%u pitch=%u bpp=%u addr=0x%llx\n",
               fb.width, fb.height, fb.pitch, fb.bpp,
               (unsigned long long)mbi->framebuffer_addr);
    }
    return true;
}

bool fb_init_from_bootinfo(uint32_t magic, void *mb_info) {
    if (magic == MULTIBOOT2_BOOTLOADER_MAGIC) {
        return fb_init_from_multiboot2(mb_info);
    }
    if (magic == MULTIBOOT_BOOTLOADER_MAGIC) {
        return fb_init_from_multiboot1((multiboot_info_t *)mb_info);
    }
    return false;
}

void fb_install_physical(uint64_t physical_addr, uint8_t *kernel_addr,
                         uint32_t width, uint32_t height, uint32_t pitch,
                         uint32_t bpp, uint32_t r_pos, uint32_t g_pos,
                         uint32_t b_pos, uint32_t r_mask, uint32_t g_mask,
                         uint32_t b_mask) {
    uint64_t size = (uint64_t)pitch * (uint64_t)height;

    display_backend_reset();
    if (!kernel_addr) kernel_addr = fb_kernel_address_for_physical(physical_addr);
    fb.addr = kernel_addr;
    fb.width = width;
    fb.height = height;
    fb.pitch = pitch;
    fb.bpp = bpp;
    fb.r_pos = r_pos;
    fb.g_pos = g_pos;
    fb.b_pos = b_pos;
    fb.r_mask = r_mask;
    fb.g_mask = g_mask;
    fb.b_mask = b_mask;
    fb_backbuffer = NULL;
    fb_clear_remap_window();
    g_fb_phys_base = physical_addr & ~0x1FFFFFULL;
    g_fb_phys_offset = physical_addr - g_fb_phys_base;
    g_fb_phys_pages = (uint32_t)(((g_fb_phys_offset + size + 0x1FFFFFULL) >> 21));
    (void)fb_install_kernel_remap(g_fb_phys_base, g_fb_phys_offset, g_fb_phys_pages);
    fb.addr = kernel_addr;
    fb_register_direct_display();
    printf("[fb] kernel mapping kva=0x%llx phys=0x%llx off=0x%llx pages=%u active=%d size=%ux%u pitch=%u\n",
           (unsigned long long)(uintptr_t)fb.addr,
           (unsigned long long)g_fb_phys_base,
           (unsigned long long)g_fb_phys_offset,
           g_fb_phys_pages,
           g_fb_remap_active,
           fb.width, fb.height, fb.pitch);
}

void fb_uninstall(uint8_t *expected_kernel_addr) {
    if (!fb.addr || (expected_kernel_addr && fb.addr != expected_kernel_addr))
        return;
    display_backend_reset();
    fb_release_user_mmap();
    fb_backbuffer = NULL;
    fb_clear_remap_window();
    g_fb_phys_base = 0;
    g_fb_phys_offset = 0;
    g_fb_phys_pages = 0;
    fb = (fb_t){0};
}

void fb_install(uint8_t *addr, uint32_t width, uint32_t height, uint32_t pitch,
                uint32_t bpp, uint32_t r_pos, uint32_t g_pos, uint32_t b_pos,
                uint32_t r_mask, uint32_t g_mask, uint32_t b_mask) {
    /*
     * Identity/static-memory backends retain the historical entry point.
     * PCI and DMA-backed drivers must use fb_install_physical() so a kernel
     * virtual alias can never leak into Linux userspace page tables.
     */
    fb_install_physical((uint64_t)(uintptr_t)addr, addr, width, height, pitch,
                        bpp, r_pos, g_pos, b_pos, r_mask, g_mask, b_mask);
}

int fb_get_2m_remap(uint64_t *phys_base, uint32_t *page_count, uint64_t *virt_base) {
    if (!g_fb_remap_active) return 0;
    if (phys_base) *phys_base = g_fb_remap_phys_base;
    if (page_count) *page_count = g_fb_remap_pages;
    if (virt_base) *virt_base = FB_REMAP_VIRT_BASE;
    return 1;
}

int fb_get_2m_phys_window(uint64_t *phys_base, uint32_t *page_count, uint64_t *offset_in_first_page) {
    if (!fb.addr || fb.pitch == 0 || fb.height == 0 || g_fb_phys_pages == 0) return 0;
    if (phys_base) *phys_base = g_fb_phys_base;
    if (page_count) *page_count = g_fb_phys_pages;
    if (offset_in_first_page) *offset_in_first_page = g_fb_phys_offset;
    return 1;
}

void fb_debug_dump(void) {
#if FB_DEBUG
    printf("FB addr=%p size=%ux%u pitch=%u bpp=%u\n",
                   fb.addr, fb.width, fb.height, fb.pitch, fb.bpp);
    printf("R: mask=%08x pos=%u\n", fb.r_mask, fb.r_pos);
    printf("G: mask=%08x pos=%u\n", fb.g_mask, fb.g_pos);
    printf("B: mask=%08x pos=%u\n", fb.b_mask, fb.b_pos);
#endif
}



void fb_putpixel(int x, int y, uint32_t argb) {
    if (!fb.addr) return;
    if ((unsigned)x >= fb.width || (unsigned)y >= fb.height) return;
    uint8_t *base = fb_backbuffer ? fb_backbuffer : fb.addr;
    uint32_t pixel = fb_argb_to_pixel(argb);
    uint8_t *p = base + y * fb.pitch + x * fb_bpp_bytes();

    switch (fb.bpp) {
    case 32: *(uint32_t*)p = pixel; break;
    case 24: p[0] = (pixel) & 0xFF; p[1] = (pixel>>8) & 0xFF; p[2] = (pixel>>16) & 0xFF; break;
    case 16: *(uint16_t*)p = (uint16_t)pixel; break;
    default: p[0] = pixel & 0xFF; break;
    }
}

void fb_clear(uint32_t argb) {
    if (!fb.addr) return;
    uint8_t *base = fb_backbuffer ? fb_backbuffer : fb.addr;
    uint32_t pix = fb_argb_to_pixel(argb);

    if (fb.bpp == 32) {
        for (uint32_t y=0; y<fb.height; y++) {
            uint32_t *row = (uint32_t *)(base + y * fb.pitch);
            for (uint32_t x=0; x<fb.width; x++) row[x] = pix;
        }
    } else if (fb.bpp == 24) {
        uint8_t r = (pix>>16)&0xFF, g=(pix>>8)&0xFF, b=pix&0xFF;
        for (uint32_t y=0; y<fb.height; y++) {
            uint8_t *row = base + y * fb.pitch;
            for (uint32_t x=0; x<fb.width; x++) { row[0]=b; row[1]=g; row[2]=r; row += 3; }
        }
    } else if (fb.bpp == 16) {
        uint16_t v = (uint16_t)pix;
        for (uint32_t y=0; y<fb.height; y++) {
            uint16_t *row = (uint16_t *)(base + y * fb.pitch);
            for (uint32_t x=0; x<fb.width; x++) row[x] = v;
        }
    } else {
        for (uint32_t y=0; y<fb.height; y++)
            for (uint32_t x=0; x<fb.width; x++)
                fb_putpixel(x,y,argb);
    }
}

bool fb_enable_backbuffer(void) {
    size_t size = fb.pitch * fb.height;
    if (size > FB_BACKBUFFER_MAX)
        return false;
    fb_backbuffer = fb_backbuffer_storage;
    return true;
}

void fb_present(void) {
    if (!fb.addr || !fb_backbuffer)
        goto flush_only;
    memcpy(fb.addr, fb_backbuffer, fb.pitch * fb.height);
flush_only:
    display_backend_present_rect(0, 0, fb.width, fb.height);
}

void fb_present_rect(int x, int y, int w, int h) {
    uint32_t bpp;
    if (!fb.addr || w <= 0 || h <= 0)
        return;
    if (x < 0) {
        w += x;
        x = 0;
    }
    if (y < 0) {
        h += y;
        y = 0;
    }
    if (x >= (int)fb.width || y >= (int)fb.height || w <= 0 || h <= 0)
        return;
    if (x + w > (int)fb.width)
        w = (int)fb.width - x;
    if (y + h > (int)fb.height)
        h = (int)fb.height - y;
    if (fb_backbuffer) {
        bpp = fb_bpp_bytes();
        for (int row = 0; row < h; ++row) {
            uint8_t *dst = fb.addr + (uint32_t)(y + row) * fb.pitch + (uint32_t)x * bpp;
            uint8_t *src = fb_backbuffer + (uint32_t)(y + row) * fb.pitch + (uint32_t)x * bpp;
            memcpy(dst, src, (uint32_t)w * bpp);
        }
    }
    display_backend_present_rect((uint32_t)x, (uint32_t)y,
                                 (uint32_t)w, (uint32_t)h);
}

void fb_flush_rect(int x, int y, int w, int h) {
    if (!fb.addr || w <= 0 || h <= 0)
        return;
    if (x < 0) {
        w += x;
        x = 0;
    }
    if (y < 0) {
        h += y;
        y = 0;
    }
    if (x >= (int)fb.width || y >= (int)fb.height || w <= 0 || h <= 0)
        return;
    if (x + w > (int)fb.width)
        w = (int)fb.width - x;
    if (y + h > (int)fb.height)
        h = (int)fb.height - y;
    {
        uint32_t bytes_per_pixel = (fb.bpp + 7u) / 8u;
        uint32_t row_bytes = (uint32_t)w * bytes_per_pixel;
        for (int row = 0; row < h; ++row)
            arch_cpu_clean_data_range(
                fb.addr + (uint32_t)(y + row) * fb.pitch +
                (uint32_t)x * bytes_per_pixel,
                row_bytes);
    }
    display_backend_present_rect((uint32_t)x, (uint32_t)y,
                                 (uint32_t)w, (uint32_t)h);
}

void fb_flush_rects(const display_rect_t *rects, uint32_t count) {
    display_rect_t clipped[8];
    uint32_t clipped_count = 0;
    uint32_t bytes_per_pixel;

    if (!fb.addr || !rects || !count)
        return;
    bytes_per_pixel = (fb.bpp + 7u) / 8u;
    for (uint32_t index = 0; index < count; ++index) {
        display_rect_t rect = rects[index];
        uint32_t row_bytes;

        if (!rect.width || !rect.height || rect.x >= fb.width ||
            rect.y >= fb.height)
            continue;
        if (rect.width > fb.width - rect.x)
            rect.width = fb.width - rect.x;
        if (rect.height > fb.height - rect.y)
            rect.height = fb.height - rect.y;
        row_bytes = rect.width * bytes_per_pixel;
        for (uint32_t row = 0; row < rect.height; ++row)
            arch_cpu_clean_data_range(
                fb.addr + (rect.y + row) * fb.pitch +
                    rect.x * bytes_per_pixel,
                row_bytes);
        clipped[clipped_count++] = rect;
        if (clipped_count == sizeof(clipped) / sizeof(clipped[0])) {
            display_backend_present_rects(clipped, clipped_count);
            clipped_count = 0;
        }
    }
    if (clipped_count)
        display_backend_present_rects(clipped, clipped_count);
}

void fb_note_user_mmap(void) {
    /*
     * Linux fbdev usually maps memory that scanout hardware observes directly.
     * EdgeOS' virtio-gpu backend is different: userspace mmap writes land in
     * the resource backing buffer and must be explicitly transferred/flushed to
     * the host.  Mark ownership here so the timer stops repainting the kernel
     * fbconsole backbuffer over userspace.  Direct GOP/ramfb apertures observe
     * stores without a kernel present; resource-backed devices retain the
     * deferred transfer path.
     */
    if (!g_fb_user_mmap_active && g_fb_user_mmap_log_budget > 0) {
        uint64_t phys_base = 0;
        uint64_t phys_off = 0;
        uint32_t phys_pages = 0;
        (void)fb_get_2m_phys_window(&phys_base, &phys_pages, &phys_off);
        printf("[fb] userspace mmap owns fbdev addr=0x%x user=0x%x phys=0x%x off=0x%x pages=%u size=%ux%u pitch=%u bpp=%u\n",
               (uint32_t)(uintptr_t)fb.addr,
               (uint32_t)(EDGE_FBDEV_USER_BASE + phys_off),
               (uint32_t)phys_base,
               (uint32_t)phys_off,
               phys_pages,
               fb.width, fb.height, fb.pitch, fb.bpp);
        g_fb_user_mmap_log_budget--;
    }
    if (!g_fb_user_mmap_active) {
        fb_console_set_fbdev_owned(1);
        g_fb_user_mmap_active = 1;
        g_fb_user_mmap_next_flush_us = 0;
        g_fb_user_mmap_next_forced_flush_us = 0;
        g_fb_user_mmap_deferred_pending = fb_user_mmap_requires_present();
        g_fb_user_mmap_deferred_ticks = 0;
        g_fb_user_mmap_skip_flushes = 0;
        g_fb_user_mmap_dirty_valid = 0;
        fb_user_mmap_dirty_rows_clear();
        fb_user_mmap_shadow_reset();
    }
}

int fb_user_mmap_active(void) {
    return g_fb_user_mmap_active;
}

void fb_release_user_mmap(void) {
    if (!g_fb_user_mmap_active) return;
    /*
     * All /dev/fb0 descriptors have closed.  Stop the mmap presentation pump
     * and force the next fbdev mmap owner to seed a fresh shadow.  Red flag:
     * keeping this state active after Xorg exits makes later X servers compare
     * against stale pixels and keeps QEMU busy scanning an idle framebuffer.
     */
    g_fb_user_mmap_active = 0;
    fb_console_set_fbdev_owned(0);
    g_fb_user_mmap_next_flush_us = 0;
    g_fb_user_mmap_next_forced_flush_us = 0;
    g_fb_user_mmap_deferred_pending = 0;
    g_fb_user_mmap_deferred_ticks = 0;
    g_fb_user_mmap_dirty_valid = 0;
    fb_user_mmap_dirty_rows_clear();
    fb_user_mmap_shadow_reset();
    if (g_fb_user_mmap_log_budget > 0) {
        printf("[fb] userspace mmap released fbdev dirty=%u full=%u skip=%u\n",
               g_fb_user_mmap_dirty_flushes,
               g_fb_user_mmap_full_flushes,
               g_fb_user_mmap_skip_flushes);
        g_fb_user_mmap_log_budget--;
    }
}

void fb_note_user_mmap_dirty(uint64_t window_offset, uint64_t len) {
    uint64_t start;
    uint64_t end;
    uint64_t fb_bytes;
    uint32_t y0;
    uint32_t y1;

    if (!fb_user_mmap_requires_present() || !fb.addr || fb.pitch == 0 ||
        fb.height == 0 || len == 0)
        return;
    fb_bytes = (uint64_t)fb.pitch * (uint64_t)fb.height;
    if (fb_bytes == 0) return;
    /*
     * window_offset is the byte offset inside the Linux-visible /dev/fb0 mmap
     * aperture, not the absolute physical address and not smem_start with its
     * low bits folded in.  Linux fbdev drivers report smem_start separately;
     * mmap damage is relative to the VMA offset supplied by userspace.  Mixing
     * the 2 MiB physical-window offset into dirty accounting makes non-aligned
     * framebuffers skip the first visible rows or mark rows past the real
     * screen, which in turn leaves Xorg/XFCE scanout stale.
     */
    if (window_offset >= fb_bytes) return;
    if (window_offset + len < window_offset) end = fb_bytes;
    else end = window_offset + len;
    start = window_offset;
    if (end > fb_bytes) end = fb_bytes;
    if (end <= start) return;

    y0 = (uint32_t)(start / fb.pitch);
    y1 = (uint32_t)((end - 1u) / fb.pitch);
    if (y0 >= fb.height) y0 = fb.height - 1u;
    if (y1 >= fb.height) y1 = fb.height - 1u;
    /*
     * Track the exact rows touched by write faults.  A min/max row span is
     * correct but expensive for desktop workloads: one panel write near the
     * top plus one cursor/window write lower on the screen becomes a full
     * 1280x800 transfer.  Linux fbdev scanout sees these stores directly; the
     * EdgeOS virtio-gpu bridge must submit transfers, so preserving row
     * granularity is part of making mmap fbdev behave fast enough for X11.
     *
     * Red flag: keep this keyed only on fbdev mmap damage.  Do not add Xorg,
     * XFCE, Alpine, DISPLAY, or rootfs special cases.
     */
    fb_user_mmap_mark_dirty_rows(y0, y1);
    /*
     * Dirty mmap stores may happen in long user-mode repaint bursts where the
     * task does not enter a normal syscall path for a while.  Request a
     * process-context pump from the same generic damage path so fbdev mmap
     * clients cannot starve their own scanout updates.
    */
    g_fb_user_mmap_deferred_pending = 1;
    kernel_display_work_request();
}

void fb_user_mmap_request_tick_from_irq(uint32_t ticks) {
    if (!g_fb_user_mmap_active || !fb_user_mmap_requires_present()) return;
    /*
     * Timer IRQs provide refresh cadence only for backends that require an
     * explicit present.  Direct scanout mappings return above; repeatedly
     * cleaning a non-cacheable GOP aperture is unnecessary and expensive.
     * Synchronous transfer work remains deferred to process context.
     */
    g_fb_user_mmap_deferred_ticks = ticks;
    g_fb_user_mmap_deferred_pending = 1;
    kernel_display_work_request();
}

void fb_user_mmap_pump_deferred(void) {
    uint32_t ticks;

    /*
     * Runtime presentation is serialized by the architecture-wide execution
     * owner before this function is called, and the VirtIO-GPU command queue
     * has its own lock. Allow the CPU that consumed the display-work latch to
     * finish the bounded pump. Requiring CPU0 here lets another CPU consume
     * and republish the latch indefinitely while a multithreaded application
     * keeps CPU0 busy, which turns ordinary pointer damage into visible stalls.
     */
    if (!g_fb_user_mmap_active || !fb_user_mmap_requires_present() ||
        !g_fb_user_mmap_deferred_pending)
        return;
    if (!fb_user_mmap_deferred_due()) return;
    ticks = g_fb_user_mmap_deferred_ticks;
    g_fb_user_mmap_deferred_pending = 0;
    fb_user_mmap_tick(ticks);
}

int fb_user_mmap_deferred_due(void) {
    uint64_t now_us;

    if (!g_fb_user_mmap_active || !fb_user_mmap_requires_present() ||
        !g_fb_user_mmap_deferred_pending || !fb.addr)
        return 0;
    /*
     * ARM64 write-notify faults already coalesce every store to a page until
     * userspace next enters the kernel.  Flush at that syscall boundary: if a
     * client enters an indefinite poll before the timer deadline, no later
     * process-context callback exists to publish the completed frame.
     */
    if (arch_vm_write_notify_supported())
        return g_fb_user_mmap_dirty_valid != 0;
    now_us = boottime_monotonic_us();
    if (g_fb_user_mmap_next_flush_us && now_us < g_fb_user_mmap_next_flush_us) return 0;
    if (!g_fb_user_mmap_dirty_valid) return 1;
    if (!g_fb_user_mmap_dirty_first_us || !g_fb_user_mmap_dirty_last_us) return 1;
    if (g_fb_user_mmap_dirty_first_us > now_us || g_fb_user_mmap_dirty_last_us > now_us) return 0;
    if (now_us - g_fb_user_mmap_dirty_first_us >= FB_USER_MMAP_DIRTY_MAX_LATENCY_US) return 1;
    if (now_us - g_fb_user_mmap_dirty_last_us >= FB_USER_MMAP_DIRTY_IDLE_US) return 1;
    return 0;
}

void fb_user_mmap_tick(uint32_t ticks) {
    uint64_t now_us;
    uint32_t y0;
    uint32_t y1;
    uint32_t rows;
    int full_flush = 0;
    int did_flush = 0;

    (void)ticks;
    if (!g_fb_user_mmap_active || !fb_user_mmap_requires_present() || !fb.addr)
        return;
    /*
     * Direct fbdev mmap writes bypass kernel copy helpers, so EdgeOS tracks
     * damage through the same Linux-visible mechanism used by fbdev deferred
     * I/O: userspace writes fault a write-protected framebuffer page, the fault
     * marks the row dirty and makes the PTE writable, and this presenter later
     * transfers those dirty rows before re-arming write protection.  The mmap
     * remains a writable MAP_SHARED device mapping from userspace's point of
     * view; the write-protect cycle is kernel bookkeeping for virtio-gpu.
     *
     * Red flag: keep this generic for all fbdev mmap clients.  Do not special
     * case Xorg, XFCE, rootfs paths, or app names here.
     */
    /*
     * Do not call fb_present_rect() here: that helper is for kernel console
     * rendering and copies fb_backbuffer over fb.addr before flushing.  When
     * Xorg or another Linux fbdev mmap client owns /dev/fb0, fb.addr already
     * contains userspace's pixels.  Copying the console backbuffer here would
     * exactly repaint the text VT over the X desktop.
     */
    now_us = boottime_monotonic_us();
    if (g_fb_user_mmap_next_flush_us && now_us < g_fb_user_mmap_next_flush_us) return;
    g_fb_user_mmap_next_flush_us = now_us + FB_USER_MMAP_PRESENT_INTERVAL_US;
    if (g_fb_user_mmap_tick_log_budget > 0) {
        printf("[fb] mmap-tick active=%d shadow=%d dirty=%d frames=%u skips=%u p00=0x%x mid=0x%x nz=%u budget=%d\n",
               g_fb_user_mmap_active,
               g_fb_user_mmap_shadow_valid,
               g_fb_user_mmap_dirty_valid,
               g_fb_user_mmap_dirty_flushes,
               g_fb_user_mmap_skip_flushes,
               fb_sample_pixel(0, 0),
               fb_sample_pixel(fb.width / 2, fb.height / 2),
               fb_sample_nonzero_bytes(0, fb.height ? fb.height - 1u : 0),
               g_fb_user_mmap_tick_log_budget - 1);
        g_fb_user_mmap_tick_log_budget--;
    }
    /*
     * Linux fbdev scanout hardware observes mmap stores directly.  EdgeOS'
     * virtio-gpu resource is backed by normal RAM and the host only sees new
     * pixels after TRANSFER_TO_HOST_2D/RESOURCE_FLUSH, so the kernel must track
     * damage independently of userspace.  Use x86 accessed/dirty state on the
     * fbdev PTEs as the generic dirty signal: this keeps the mmap aperture
     * writable like Linux while avoiding a full framebuffer memcmp in the timer
     * path.  Red flag: keep this generic to /dev/fb0 mappings; do not key it on
     * Xorg, XFCE, rootfs paths, DISPLAY, or application names.
     */
    if (!arch_vm_write_notify_supported() &&
        (!g_fb_user_mmap_next_pte_scan_us ||
         now_us >= g_fb_user_mmap_next_pte_scan_us)) {
        g_fb_user_mmap_next_pte_scan_us = now_us + FB_USER_MMAP_PTE_SCAN_US;
        process_user_fbdev_collect_dirty_all();
    }
    /*
     * Write faults are the durable dirty signal.  The PTE dirty-bit walk keeps
     * old mappings and stale translations from being missed, and the bounded
     * shadow diff below covers the remaining case where a vCPU writes through a
     * stale writable TLB entry before EdgeOS grows Linux-grade remote shootdown.
     */
    if (!arch_vm_write_notify_supported())
        fb_user_mmap_shadow_scan(now_us);

    /*
     * Linux fbdev mmap exposes scanout memory: once userspace stores pixels,
     * the display engine observes them without an ioctl or msync.  EdgeOS'
     * virtio-gpu backend is not a direct scanout aperture, so it must submit
     * transfers for rows dirtied through the mmap aperture.  Dirty PTEs and the
     * shadow diff above are the damage sources; do not synthesize idle
     * full-screen transfers when no bytes changed.  Repeated 1600x1000
     * transfers while the buffer is still black starve Xorg/DBus/GTK and make
     * startxfce4 look frozen.
     */
    /*
     * Compute the present range only after both damage sources have run.  A
     * large Xorg ShadowFB repaint can be discovered by fb_user_mmap_shadow_scan()
     * even when a few hardware-dirty rows were already pending.  Choosing y0/y1
     * before the shadow diff and then clearing dirty state after a tiny flush
     * drops the larger repaint, leaving the host scanout black while Linux
     * userspace believes it has drawn a full desktop.
     */
    if (!g_fb_user_mmap_dirty_valid) {
        /*
         * Linux fbdev scanout observes mmap stores directly and does not perform
         * periodic full-screen refreshes when userspace is idle.  EdgeOS' virtio
         * backend needs explicit transfers, but the dirty PTE walk and shadow diff
         * above are the Linux-compatible damage sources.  After the initial sync
         * frame, no dirty rows means no present work; otherwise an idle XFCE
         * desktop turns into repeated synchronous multi-megabyte transfers and
         * input/window creation looks like a kernel stall.  If a repaint is missed,
         * fix dirty tracking instead of hiding it with full-screen polling.
         */
        g_fb_user_mmap_skip_flushes++;
        return;
    }
    /*
     * Linux fb_deferred_io batches mmap write faults and runs the framebuffer
     * driver's deferred callback after a short delay.  Presenting immediately
     * after every 4 KiB fbdev write fault is observably non-Linux for Xorg
     * ShadowFB: one full desktop repaint becomes hundreds of tiny synchronous
     * virtio-gpu transfers, and re-protecting between those transfers makes
     * userspace fault again on the same repaint.  Wait briefly for the current
     * burst to go idle, with a display-frame maximum latency so pointer and
     * window updates still appear promptly.
     */
    if (g_fb_user_mmap_dirty_first_us && g_fb_user_mmap_dirty_last_us &&
        (g_fb_user_mmap_dirty_first_us > now_us ||
         g_fb_user_mmap_dirty_last_us > now_us ||
         (now_us - g_fb_user_mmap_dirty_first_us < FB_USER_MMAP_DIRTY_MAX_LATENCY_US &&
          now_us - g_fb_user_mmap_dirty_last_us < FB_USER_MMAP_DIRTY_IDLE_US))) {
        /*
         * Keep the delayed work armed while coalescing a write burst.  The
         * pump clears g_fb_user_mmap_deferred_pending before calling here, so
         * returning without re-arming can strand a full Xorg repaint in the
         * virtio-gpu backing buffer until unrelated kernel activity happens.
         * Linux fbdev deferred I/O similarly keeps delayed work pending until
         * the driver's callback consumes the dirty list.
         */
        g_fb_user_mmap_deferred_pending = 1;
        return;
    }
    y0 = g_fb_user_mmap_dirty_y0;
    y1 = g_fb_user_mmap_dirty_y1;
    if (y0 >= fb.height) y0 = fb.height - 1u;
    if (y1 >= fb.height) y1 = fb.height - 1u;
    rows = y1 >= y0 ? (y1 - y0 + 1u) : 0;
    if (rows == 0) return;
    if (rows >= (fb.height / 2u)) full_flush = 1;
    g_fb_user_mmap_dirty_flushes++;
    if (full_flush || (y0 == 0 && rows >= fb.height)) g_fb_user_mmap_full_flushes++;
    if (g_fb_user_mmap_checksum_log_budget > 0 ||
        (g_fb_user_mmap_periodic_log_budget > 0 &&
         (g_fb_user_mmap_dirty_flushes == 60u ||
          g_fb_user_mmap_dirty_flushes == 120u ||
          (g_fb_user_mmap_dirty_flushes % 300u) == 0u))) {
        uint32_t top = fb_sample_pixel(fb.width > 8 ? 8 : 0, fb.height > 8 ? 8 : 0);
        uint32_t mid = fb_sample_pixel(fb.width / 2, fb.height / 2);
        uint32_t panel = fb_sample_pixel(fb.width > 32 ? 32 : 0, fb.height > 16 ? 16 : 0);
        uint32_t clock = fb_sample_pixel(fb.width > 460 ? 460 : fb.width / 2,
                                         fb.height > 160 ? 160 : fb.height / 2);
        /*
         * These samples prove whether Linux fbdev mmap clients are changing the
         * visible aperture before EdgeOS submits the virtio-gpu transfer.  Keep
         * the budget tiny: serial logging from the display pump can itself make
         * X11 look slow.
         */
        printf("[fb] user-mmap scanout flush y=%u..%u p00=0x%x top=0x%x mid=0x%x panel=0x%x app=0x%x size=%ux%u pitch=%u frames=%u full=%u\n",
               y0, y1,
               fb_sample_pixel(0, 0), top, mid, panel, clock, fb.width, fb.height, fb.pitch,
               g_fb_user_mmap_dirty_flushes, g_fb_user_mmap_full_flushes);
        printf("[fb] user-mmap sample nonzero=%u range=%u..%u addr=0x%x\n",
               fb_sample_nonzero_bytes(y0, y1), y0, y1,
               (uint32_t)(uintptr_t)fb.addr);
        if (g_fb_user_mmap_checksum_log_budget > 0) g_fb_user_mmap_checksum_log_budget--;
        else g_fb_user_mmap_periodic_log_budget--;
    }
    if (!full_flush && fb.height <= FB_USER_MMAP_MAX_DIRTY_ROWS) {
        uint32_t run_start = 0;
        uint32_t run_len = 0;
        for (uint32_t y = y0; y <= y1; ++y) {
            if (fb_user_mmap_dirty_row_test(y)) {
                if (run_len == 0) run_start = y;
                run_len++;
            } else if (run_len != 0) {
                fb_flush_rect(0, (int)run_start, (int)fb.width, (int)run_len);
                did_flush = 1;
                run_len = 0;
            }
        }
        if (run_len != 0) {
            fb_flush_rect(0, (int)run_start, (int)fb.width, (int)run_len);
            did_flush = 1;
        }
    } else {
        fb_flush_rect(0, (int)y0, (int)fb.width, (int)rows);
        did_flush = 1;
    }
    g_fb_user_mmap_dirty_valid = 0;
    fb_user_mmap_dirty_rows_clear();
    /*
     * Re-arm mmap write faults after the batched present, matching Linux
     * fb_deferred_io's visible contract: writes are ordinary MAP_SHARED stores
     * to userspace, but the kernel gets a page_mkwrite-style transition to
     * discover damage for backends that are not true scanout memory.  The
     * batching above is the important guard against the old failure mode where
     * Xorg ShadowFB repaints were split into hundreds of tiny synchronous
     * transfers.  Leaving the aperture writable permanently misses later
     * xfdesktop/panel/xclock stores on EdgeOS because stale writable TLB entries
     * do not reliably update the software PTE dirty bit.
     *
     * Red flag: keep this generic fbdev deferred-I/O behavior.  Do not replace
     * it with Xorg/XFCE-specific repaints or idle full-screen polling.
     */
    process_user_fbdev_writeprotect_all();
    (void)did_flush;
}


uint8_t *fb_get_draw_buffer(void) {
    return fb_backbuffer ? fb_backbuffer : fb.addr;
}
void fb_draw_char(int x, int y, char ch, uint32_t fg, uint32_t bg, bool opaque) {
    const uint8_t *glyph = font8x8_basic[(unsigned char)ch];
    for (int row = 0; row < 8; row++) {
        uint8_t bits = glyph[row];
        for (int col = 0; col < 8; col++) {
            if (bits & (1 << col)) {
                fb_putpixel(x + col, y + row, fg);
            } else if (opaque) {
                fb_putpixel(x + col, y + row, bg);
            }
        }
    }
}

void fb_draw_string(int x, int y, const char *s, uint32_t fg, uint32_t bg, bool opaque) {
    if (!s) return;
    int cx = x;
    while (*s) {
        if (*s == '\n') {
            y += 8;
            cx = x;
            s++;
            continue;
        }
        fb_draw_char(cx, y, *s++, fg, bg, opaque);
        cx += 8;
    }
}
