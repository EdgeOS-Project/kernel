#include <stddef.h>
#include <stdint.h>
#include "arch/arm64/bootinfo.h"
#include "arch/arm64/mmu.h"
#include "arch/arm64/platform.h"
#include "console.h"
#include "fb.h"
#include "fb_console.h"
#include "fs/initramfs.h"
#include "kernel/boot_command_line.h"
#if defined(CONFIG_BSD_DRIVER_BRIDGE) && defined(CONFIG_DEVICE_TREE)
#include "compat/freebsd/edgeos/ofw.h"
#endif

typedef uint64_t efi_status_t;
typedef void *efi_handle_t;
typedef uint16_t efi_char16_t;

#define EFI_SUCCESS 0
#define EFI_ERROR_BIT 0x8000000000000000ULL
#define EFI_BUFFER_TOO_SMALL (EFI_ERROR_BIT | 5)
#define EFI_LOAD_ERROR (EFI_ERROR_BIT | 1)
#define EFI_INVALID_PARAMETER (EFI_ERROR_BIT | 2)
#define EFI_OPEN_PROTOCOL_BY_HANDLE_PROTOCOL 0x00000001U
#define EFI_FILE_MODE_READ 0x0000000000000001ULL
#define EFI_ALLOCATE_ANY_PAGES 0
#define EFI_RESERVED_MEMORY_TYPE 0
#define EFI_LOADER_DATA 2

#define QEMU_VIRT_FW_CFG_BASE 0x09020000ULL
#define FW_CFG_FILE_DIR 0x0019u
#define FW_CFG_DMA_CTL_ERROR 0x01u
#define FW_CFG_DMA_CTL_SELECT 0x08u
#define FW_CFG_DMA_CTL_WRITE 0x10u
#define RAMFB_FORMAT_XRGB8888 0x34325258u
#define EDGEOS_VIDEO_MIN_WIDTH 320u
#define EDGEOS_VIDEO_MIN_HEIGHT 200u
#define EDGEOS_VIDEO_MAX_WIDTH 7680u
#define EDGEOS_VIDEO_MAX_HEIGHT 4320u
#define EDGEOS_VIDEO_MAX_BYTES (128u * 1024u * 1024u)

#define EFIAPI

typedef struct {
    uint64_t signature;
    uint32_t revision;
    uint32_t header_size;
    uint32_t crc32;
    uint32_t reserved;
} efi_table_header_t;

typedef struct {
    uint32_t data1;
    uint16_t data2;
    uint16_t data3;
    uint8_t data4[8];
} efi_guid_t;

typedef struct efi_simple_text_output_protocol efi_simple_text_output_protocol_t;
typedef struct efi_boot_services efi_boot_services_t;
typedef struct efi_system_table efi_system_table_t;
typedef struct efi_loaded_image_protocol efi_loaded_image_protocol_t;
typedef struct efi_simple_file_system_protocol efi_simple_file_system_protocol_t;
typedef struct efi_file_protocol efi_file_protocol_t;
typedef struct efi_graphics_output_protocol efi_graphics_output_protocol_t;
typedef struct efi_simple_text_input_protocol efi_simple_text_input_protocol_t;
typedef struct efi_configuration_table efi_configuration_table_t;
typedef struct efi_load_file_protocol efi_load_file_protocol_t;

struct efi_simple_text_output_protocol {
    void *reset;
    efi_status_t (EFIAPI *output_string)(efi_simple_text_output_protocol_t *self,
                                         const efi_char16_t *string);
};

typedef struct {
    uint16_t scan_code;
    efi_char16_t unicode_char;
} efi_input_key_t;

struct efi_simple_text_input_protocol {
    void *reset;
    efi_status_t (EFIAPI *read_key_stroke)(efi_simple_text_input_protocol_t *self,
                                           efi_input_key_t *key);
    void *wait_for_key;
};

struct efi_loaded_image_protocol {
    uint32_t revision;
    efi_handle_t parent_handle;
    efi_system_table_t *system_table;
    efi_handle_t device_handle;
    void *file_path;
    void *reserved;
    uint32_t load_options_size;
    void *load_options;
    void *image_base;
    uint64_t image_size;
    uint32_t image_code_type;
    uint32_t image_data_type;
    efi_status_t (EFIAPI *unload)(efi_handle_t image_handle);
};

struct efi_file_protocol {
    uint64_t revision;
    efi_status_t (EFIAPI *open)(efi_file_protocol_t *self, efi_file_protocol_t **new_handle,
                                const efi_char16_t *file_name, uint64_t open_mode,
                                uint64_t attributes);
    efi_status_t (EFIAPI *close)(efi_file_protocol_t *self);
    efi_status_t (EFIAPI *delete_file)(efi_file_protocol_t *self);
    efi_status_t (EFIAPI *read)(efi_file_protocol_t *self, uint64_t *buffer_size,
                                void *buffer);
    void *write;
    efi_status_t (EFIAPI *get_position)(efi_file_protocol_t *self, uint64_t *position);
    efi_status_t (EFIAPI *set_position)(efi_file_protocol_t *self, uint64_t position);
    efi_status_t (EFIAPI *get_info)(efi_file_protocol_t *self, const efi_guid_t *info_type,
                                    uint64_t *buffer_size, void *buffer);
};

struct efi_simple_file_system_protocol {
    uint64_t revision;
    efi_status_t (EFIAPI *open_volume)(efi_simple_file_system_protocol_t *self,
                                       efi_file_protocol_t **root);
};

struct efi_load_file_protocol {
    efi_status_t (EFIAPI *load_file)(efi_load_file_protocol_t *self,
                                     void *file_path,
                                     uint8_t boot_policy,
                                     uint64_t *buffer_size,
                                     void *buffer);
};

struct efi_boot_services {
    efi_table_header_t hdr;
    void *raise_tpl;
    void *restore_tpl;
    efi_status_t (EFIAPI *allocate_pages)(uint32_t type, uint32_t memory_type,
                                          uint64_t pages, uint64_t *memory);
    efi_status_t (EFIAPI *free_pages)(uint64_t memory, uint64_t pages);
    efi_status_t (EFIAPI *get_memory_map)(uint64_t *memory_map_size,
                                          void *memory_map,
                                          uint64_t *map_key,
                                          uint64_t *descriptor_size,
                                          uint32_t *descriptor_version);
    efi_status_t (EFIAPI *allocate_pool)(uint32_t pool_type, uint64_t size,
                                         void **buffer);
    efi_status_t (EFIAPI *free_pool)(void *buffer);
    void *create_event;
    void *set_timer;
    void *wait_for_event;
    void *signal_event;
    void *close_event;
    void *check_event;
    void *install_protocol_interface;
    void *reinstall_protocol_interface;
    void *uninstall_protocol_interface;
    efi_status_t (EFIAPI *handle_protocol)(efi_handle_t handle, const efi_guid_t *protocol,
                                           void **interface);
    void *reserved;
    void *register_protocol_notify;
    void *locate_handle;
    void *locate_device_path;
    void *install_configuration_table;
    void *load_image;
    void *start_image;
    void *exit;
    void *unload_image;
    efi_status_t (EFIAPI *exit_boot_services)(efi_handle_t image_handle,
                                              uint64_t map_key);
    void *get_next_monotonic_count;
    void *stall;
    void *set_watchdog_timer;
    void *connect_controller;
    void *disconnect_controller;
    efi_status_t (EFIAPI *open_protocol)(efi_handle_t handle, const efi_guid_t *protocol,
                                         void **interface, efi_handle_t agent_handle,
                                         efi_handle_t controller_handle, uint32_t attributes);
    void *close_protocol;
    void *open_protocol_information;
    void *protocols_per_handle;
    void *locate_handle_buffer;
    efi_status_t (EFIAPI *locate_protocol)(const efi_guid_t *protocol,
                                           void *registration, void **interface);
};

typedef struct efi_system_table {
    efi_table_header_t hdr;
    efi_char16_t *firmware_vendor;
    uint32_t firmware_revision;
    efi_handle_t console_in_handle;
    efi_simple_text_input_protocol_t *con_in;
    efi_handle_t console_out_handle;
    efi_simple_text_output_protocol_t *con_out;
    efi_handle_t standard_error_handle;
    efi_simple_text_output_protocol_t *std_err;
    void *runtime_services;
    efi_boot_services_t *boot_services;
    uint64_t number_of_table_entries;
    efi_configuration_table_t *configuration_table;
} efi_system_table_t;

struct efi_configuration_table {
    efi_guid_t vendor_guid;
    void *vendor_table;
};

typedef struct {
    uint32_t red_mask;
    uint32_t green_mask;
    uint32_t blue_mask;
    uint32_t reserved_mask;
} efi_pixel_bitmask_t;

typedef struct {
    uint32_t version;
    uint32_t horizontal_resolution;
    uint32_t vertical_resolution;
    uint32_t pixel_format;
    efi_pixel_bitmask_t pixel_information;
    uint32_t pixels_per_scanline;
} efi_graphics_output_mode_information_t;

typedef struct {
    uint32_t max_mode;
    uint32_t mode;
    efi_graphics_output_mode_information_t *info;
    uint64_t size_of_info;
    uint64_t frame_buffer_base;
    uint64_t frame_buffer_size;
} efi_graphics_output_protocol_mode_t;

typedef efi_status_t (EFIAPI *efi_gop_query_mode_fn)(
    efi_graphics_output_protocol_t *self, uint32_t mode_number,
    uint64_t *size_of_info, efi_graphics_output_mode_information_t **info);
typedef efi_status_t (EFIAPI *efi_gop_set_mode_fn)(
    efi_graphics_output_protocol_t *self, uint32_t mode_number);

struct efi_graphics_output_protocol {
    efi_gop_query_mode_fn query_mode;
    efi_gop_set_mode_fn set_mode;
    void *blt;
    efi_graphics_output_protocol_mode_t *mode;
};

static const efi_guid_t loaded_image_protocol_guid = {
    0x5B1B31A1, 0x9562, 0x11D2, {0x8E, 0x3F, 0x00, 0xA0, 0xC9, 0x69, 0x72, 0x3B}
};

static const efi_guid_t simple_file_system_protocol_guid = {
    0x964E5B22, 0x6459, 0x11D2, {0x8E, 0x39, 0x00, 0xA0, 0xC9, 0x69, 0x72, 0x3B}
};

static const efi_guid_t graphics_output_protocol_guid = {
    0x9042A9DE, 0x23DC, 0x4A38, {0x96, 0xFB, 0x7A, 0xDE, 0xD0, 0x80, 0x51, 0x6A}
};

static const efi_guid_t file_info_guid = {
    0x09576E92, 0x6D3F, 0x11D2, {0x8E, 0x39, 0x00, 0xA0, 0xC9, 0x69, 0x72, 0x3B}
};

/* EFI_LOAD_FILE2_PROTOCOL_GUID, used by U-Boot to expose an initrd in memory. */
static const efi_guid_t load_file2_protocol_guid = {
    0x4006C0C1, 0xFCB3, 0x403E, {0x99, 0x6D, 0x4A, 0x6C, 0x87, 0x24, 0xE0, 0x6D}
};

/* EFI_DTB_TABLE_GUID, supplied by Generic UEFI implementations that boot FDT. */
static const efi_guid_t fdt_table_guid = {
    0xB1B621D5, 0xF19C, 0x41A5, {0x83, 0x0B, 0xD9, 0x15, 0x2C, 0x69, 0xAA, 0xE0}
};

/* ACPI_20_TABLE_GUID.  Generic UEFI may expose ACPI instead of an FDT. */
static const efi_guid_t acpi20_table_guid = {
    0x8868E871, 0xE4F1, 0x11D3, {0xBC, 0x22, 0x00, 0x80, 0xC7, 0x3C, 0x88, 0x81}
};

typedef struct {
    uint64_t size;
    uint64_t file_size;
    uint64_t physical_size;
    uint8_t create_time[16];
    uint8_t last_access_time[16];
    uint8_t modification_time[16];
    uint64_t attribute;
    efi_char16_t file_name[1];
} efi_file_info_t;

typedef struct {
    uint32_t control;
    uint32_t length;
    uint64_t address;
} __attribute__((packed, aligned(8))) fw_cfg_dma_access_t;

typedef struct {
    uint64_t address;
    uint32_t fourcc;
    uint32_t flags;
    uint32_t width;
    uint32_t height;
    uint32_t stride;
} __attribute__((packed)) ramfb_config_t;

static efi_simple_text_output_protocol_t *g_con;
static efi_graphics_output_protocol_t *g_gop;
static uint8_t *g_fb;
static uint32_t g_fb_width;
static uint32_t g_fb_height;
static uint32_t g_fb_stride;
static uint32_t g_fb_pitch;
static uint32_t g_fb_bpp;
static uint32_t g_fb_format;
static uint32_t g_fb_r_mask;
static uint32_t g_fb_g_mask;
static uint32_t g_fb_b_mask;
static uint32_t g_fb_r_pos;
static uint32_t g_fb_g_pos;
static uint32_t g_fb_b_pos;
static uint64_t g_fb_base;
static uint64_t g_fb_size;
static int g_rootfs_ok;
static uint64_t g_rootfs_size;
static uint64_t g_initramfs_size;
static uint64_t g_kernel_image_base;
static uint64_t g_kernel_image_size;
static void *g_rootfs_base;
static void *g_initramfs_base;
static efi_status_t g_rootfs_status;
static int g_pl011_rx_pending = -1;
static edgeos_arm64_bootinfo_t g_bootinfo;
static uint8_t g_efi_mmap_storage[128 * 1024] __attribute__((aligned(8)));

__attribute__((noreturn))
void edgeos_arm64_kernel_entry(edgeos_arm64_bootinfo_t *bootinfo);

#define EDGEOS_ARM64_FONT_SCALE 2
#define EDGEOS_ARM64_CELL_W (8u * EDGEOS_ARM64_FONT_SCALE)
#define EDGEOS_ARM64_CELL_H (10u * EDGEOS_ARM64_FONT_SCALE)
#define EDGEOS_ARM64_BG_R 10
#define EDGEOS_ARM64_BG_G 14
#define EDGEOS_ARM64_BG_B 18

static void puts16(const efi_char16_t *s) {
    if (g_con && s) {
        g_con->output_string(g_con, s);
    }
}

static void pl011_init(void) {}

static void serial_putc(char ch) {
    edgeos_arm64_platform_serial_write(ch);
}

static int serial_getc_nonblock(void);

static void serial_puts(const char *s) {
    while (s && *s) serial_putc(*s++);
}

void serial_console_init(void) { pl011_init(); }
int serial_console_is_ready(void) {
    return edgeos_arm64_platform_serial_base() != 0;
}
void serial_console_write_raw(char ch) { serial_putc(ch); }
void serial_console_write_emergency(char ch) { serial_putc(ch); }
void serial_console_clear(void) {}
int serial_console_pollchar(void) { return serial_getc_nonblock(); }
int serial_console_haschar(void) {
    if (g_pl011_rx_pending >= 0) return 1;
    if (!edgeos_arm64_platform_serial_has_input()) return 0;
    g_pl011_rx_pending = edgeos_arm64_platform_serial_read();
    return 1;
}
int serial_console_probechar(void) { return serial_console_haschar(); }
int serial_console_buffered(void) { return 0; }
void serial_console_inject_input(const char *s) { (void)s; }
int serial_console_proc_snapshot(char *buf, unsigned int max) {
    if (!buf || max == 0) return -1;
    buf[0] = 0;
    return 0;
}

static int serial_getc_nonblock(void) {
    int ch;
    if (g_pl011_rx_pending >= 0) {
        ch = g_pl011_rx_pending;
        g_pl011_rx_pending = -1;
        return ch;
    }
    return edgeos_arm64_platform_serial_read();
}

static void put_hex64(uint64_t value) {
    efi_char16_t buf[19];
    static const efi_char16_t digits[] = u"0123456789abcdef";
    buf[0] = u'0';
    buf[1] = u'x';
    for (int i = 0; i < 16; ++i) {
        buf[2 + i] = digits[(value >> ((15 - i) * 4)) & 0xf];
    }
    buf[18] = 0;
    puts16(buf);
}

static void serial_hex64(uint64_t value) {
    static const char digits[] = "0123456789abcdef";
    serial_puts("0x");
    for (int i = 0; i < 16; ++i) {
        serial_putc(digits[(value >> ((15 - i) * 4)) & 0xf]);
    }
}

static int is_error(efi_status_t status) {
    return (status & EFI_ERROR_BIT) != 0;
}

static uint32_t current_exception_level(void) {
    uint64_t current_el;

    __asm__ __volatile__("mrs %0, CurrentEL" : "=r"(current_el));
    return (uint32_t)(current_el >> 2);
}

static int guid_equal(const efi_guid_t *a, const efi_guid_t *b) {
    const uint8_t *pa = (const uint8_t *)a;
    const uint8_t *pb = (const uint8_t *)b;
    uint32_t i;
    for (i = 0; i < sizeof(*a); ++i) {
        if (pa[i] != pb[i]) return 0;
    }
    return 1;
}

static uint32_t be32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | p[3];
}

static uint16_t be16(const uint8_t *p) {
    return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}

static uint16_t cpu_to_be16(uint16_t value) {
    return (uint16_t)((value << 8) | (value >> 8));
}

static uint32_t cpu_to_be32(uint32_t value) {
    return ((value & 0x000000ffu) << 24) |
           ((value & 0x0000ff00u) << 8) |
           ((value & 0x00ff0000u) >> 8) |
           ((value & 0xff000000u) >> 24);
}

static uint64_t cpu_to_be64(uint64_t value) {
    return ((uint64_t)cpu_to_be32((uint32_t)value) << 32) |
           cpu_to_be32((uint32_t)(value >> 32));
}

static void fw_cfg_select(uint16_t selector) {
    volatile uint16_t *control =
        (volatile uint16_t *)(uintptr_t)(QEMU_VIRT_FW_CFG_BASE + 8u);
    *control = cpu_to_be16(selector);
}

static uint8_t fw_cfg_read_byte(void) {
    volatile uint8_t *data =
        (volatile uint8_t *)(uintptr_t)QEMU_VIRT_FW_CFG_BASE;
    return *data;
}

static int fw_cfg_find_file(const char *name, uint16_t *selector_out,
                            uint32_t *size_out) {
    uint8_t count_bytes[4];
    uint8_t entry[64];
    uint32_t count;
    uint32_t index;
    uint32_t offset;

    if (!name || !selector_out || !size_out) return -1;
    fw_cfg_select(0);
    if (fw_cfg_read_byte() != 'Q' || fw_cfg_read_byte() != 'E' ||
        fw_cfg_read_byte() != 'M' || fw_cfg_read_byte() != 'U') return -1;
    fw_cfg_select(FW_CFG_FILE_DIR);
    for (offset = 0; offset < sizeof(count_bytes); ++offset) {
        count_bytes[offset] = fw_cfg_read_byte();
    }
    count = be32(count_bytes);
    if (count > 4096u) return -1;
    for (index = 0; index < count; ++index) {
        int matches = 1;
        for (offset = 0; offset < sizeof(entry); ++offset) {
            entry[offset] = fw_cfg_read_byte();
        }
        for (offset = 0; offset < 56u; ++offset) {
            char expected = name[offset];
            char actual = (char)entry[8u + offset];
            if (expected != actual) {
                matches = 0;
                break;
            }
            if (!expected) break;
        }
        if (!matches) continue;
        *size_out = be32(entry);
        *selector_out = be16(entry + 4u);
        return 0;
    }
    return -1;
}

static int fw_cfg_dma_write(uint16_t selector, const void *buffer,
                            uint32_t length) {
    volatile uint64_t *dma_register =
        (volatile uint64_t *)(uintptr_t)(QEMU_VIRT_FW_CFG_BASE + 16u);
    volatile fw_cfg_dma_access_t access;
    uint32_t spins = 0;

    access.control = cpu_to_be32(((uint32_t)selector << 16) |
                                 FW_CFG_DMA_CTL_SELECT |
                                 FW_CFG_DMA_CTL_WRITE);
    access.length = cpu_to_be32(length);
    access.address = cpu_to_be64((uint64_t)(uintptr_t)buffer);
    __asm__ __volatile__("dmb sy" ::: "memory");
    *dma_register = cpu_to_be64((uint64_t)(uintptr_t)&access);
    __asm__ __volatile__("dmb sy" ::: "memory");
    while (access.control != 0 && spins++ < 1000000u) {
        __asm__ __volatile__("yield");
    }
    __asm__ __volatile__("dmb sy" ::: "memory");
    if (spins >= 1000000u) return -1;
    return (cpu_to_be32(access.control) & FW_CFG_DMA_CTL_ERROR) ? -1 : 0;
}

static int configure_custom_ramfb(efi_system_table_t *st, uint32_t width,
                                  uint32_t height, uint64_t *base_out,
                                  uint64_t *size_out) {
    uint16_t selector;
    uint32_t item_size;
    uint64_t framebuffer_size;
    uint64_t framebuffer_base = 0;
    uint64_t pages;
    ramfb_config_t config;
    uint64_t index;

    if (!st || !st->boot_services || !st->boot_services->allocate_pages ||
        !base_out || !size_out || width < EDGEOS_VIDEO_MIN_WIDTH ||
        height < EDGEOS_VIDEO_MIN_HEIGHT || width > EDGEOS_VIDEO_MAX_WIDTH ||
        height > EDGEOS_VIDEO_MAX_HEIGHT) return -1;
    framebuffer_size = (uint64_t)width * height * 4u;
    if (!framebuffer_size || framebuffer_size > EDGEOS_VIDEO_MAX_BYTES) return -1;
    if (fw_cfg_find_file("etc/ramfb", &selector, &item_size) < 0 ||
        item_size != sizeof(config)) return -1;
    pages = (framebuffer_size + 4095u) >> 12;
    if (is_error(st->boot_services->allocate_pages(
            EFI_ALLOCATE_ANY_PAGES, EFI_RESERVED_MEMORY_TYPE, pages,
            &framebuffer_base)) || !framebuffer_base) return -1;
    for (index = 0; index < pages * 4096u; ++index) {
        ((uint8_t *)(uintptr_t)framebuffer_base)[index] = 0;
    }
    config.address = cpu_to_be64(framebuffer_base);
    config.fourcc = cpu_to_be32(RAMFB_FORMAT_XRGB8888);
    config.flags = 0;
    config.width = cpu_to_be32(width);
    config.height = cpu_to_be32(height);
    config.stride = cpu_to_be32(width * 4u);
    if (fw_cfg_dma_write(selector, &config, sizeof(config)) < 0) return -1;
    *base_out = framebuffer_base;
    *size_out = pages * 4096u;
    return 0;
}

static efi_status_t capture_fdt(efi_system_table_t *st) {
    uint64_t i;

    if ((g_bootinfo.flags & EDGEOS_ARM64_BOOTINFO_FLAG_FDT) != 0 &&
        g_bootinfo.fdt_base && g_bootinfo.fdt_size)
        return EFI_SUCCESS;
    if (!st || !st->configuration_table) return EFI_SUCCESS;
    for (i = 0; i < st->number_of_table_entries; ++i) {
        efi_configuration_table_t *table = &st->configuration_table[i];
        const uint8_t *fdt;
        uint8_t *copy;
        uint32_t size;
        uint64_t pages;
        uint64_t physical = 0;
        efi_status_t status;

        if (!guid_equal(&table->vendor_guid, &fdt_table_guid) || !table->vendor_table) continue;
        fdt = (const uint8_t *)table->vendor_table;
        if (be32(fdt) != 0xd00dfeedu) return EFI_LOAD_ERROR;
        size = be32(fdt + 4);
        if (size < 40u || size > UINT32_MAX - 4095u ||
            !st->boot_services || !st->boot_services->allocate_pages)
            return EFI_LOAD_ERROR;
        pages = ((uint64_t)size + 4095u) >> 12;
        status = st->boot_services->allocate_pages(
            EFI_ALLOCATE_ANY_PAGES, EFI_LOADER_DATA, pages, &physical);
        if (is_error(status) || !physical)
            return is_error(status) ? status : EFI_LOAD_ERROR;
        copy = (uint8_t *)(uintptr_t)physical;
        for (uint32_t offset = 0; offset < size; ++offset)
            copy[offset] = fdt[offset];
        for (uint64_t offset = size; offset < pages * 4096u; ++offset)
            copy[offset] = 0;
        g_bootinfo.fdt_base = physical;
        g_bootinfo.fdt_size = size;
        g_bootinfo.flags |= EDGEOS_ARM64_BOOTINFO_FLAG_FDT;
        return EFI_SUCCESS;
    }
    return EFI_SUCCESS;
}

static void capture_acpi(efi_system_table_t *st) {
    uint64_t i;
    const uint8_t signature[] = { 'R', 'S', 'D', ' ', 'P', 'T', 'R', ' ' };

    if (!st || !st->configuration_table) return;
    for (i = 0; i < st->number_of_table_entries; ++i) {
        efi_configuration_table_t *table = &st->configuration_table[i];
        const uint8_t *rsdp;
        uint32_t j;

        if (!guid_equal(&table->vendor_guid, &acpi20_table_guid) || !table->vendor_table) continue;
        rsdp = (const uint8_t *)table->vendor_table;
        for (j = 0; j < sizeof(signature); ++j) {
            if (rsdp[j] != signature[j]) return;
        }
        g_bootinfo.acpi_rsdp = (uint64_t)(uintptr_t)rsdp;
        g_bootinfo.flags |= EDGEOS_ARM64_BOOTINFO_FLAG_ACPI;
        return;
    }
}

static uint32_t mask_pos(uint32_t mask) {
    uint32_t pos = 0;
    while (pos < 32 && ((mask >> pos) & 1u) == 0) pos++;
    return pos;
}

static uint32_t mask_bits(uint32_t mask) {
    uint32_t bits = 0;

    while (mask) {
        ++bits;
        mask >>= 1;
    }
    return bits;
}

static uint32_t pixel_component(uint8_t component, uint32_t mask,
                                uint32_t position) {
    uint32_t maximum;
    uint32_t scaled;

    if (!mask || position >= 32u) return 0;
    maximum = mask >> position;
    scaled = ((uint32_t)component * maximum + 127u) / 255u;
    return (scaled << position) & mask;
}

static uint32_t pixel(uint8_t r, uint8_t g, uint8_t b) {
    return pixel_component(r, g_fb_r_mask, g_fb_r_pos) |
           pixel_component(g, g_fb_g_mask, g_fb_g_pos) |
           pixel_component(b, g_fb_b_mask, g_fb_b_pos);
}

static void edgeos_putchar_color(char ch, uint32_t fg) {
    (void)fg;
    console_putchar(ch);
}

static void edgeos_puts_color(const char *s, uint32_t fg) {
    const char *p = s;
    while (p && *p) {
        edgeos_putchar_color(*p++, fg);
    }
}

static void fb_log(const char *s, uint32_t color) {
    console_output_batch_begin();
    edgeos_puts_color("[edgeos] ", pixel(80, 220, 150));
    edgeos_puts_color(s, color);
    edgeos_putchar_color('\n', color);
    /* Present and clean only the dirty text rectangle once per complete line. */
    console_output_batch_end();
}

static int select_gop_mode(efi_system_table_t *st,
                           efi_graphics_output_protocol_t *gop,
                           uint32_t requested_width,
                           uint32_t requested_height) {
    uint32_t mode_number;

    if (!requested_width || !requested_height || !gop || !gop->mode ||
        !gop->query_mode || !gop->set_mode || !st || !st->boot_services) {
        return 0;
    }
    for (mode_number = 0; mode_number < gop->mode->max_mode; ++mode_number) {
        efi_graphics_output_mode_information_t *info = NULL;
        uint64_t info_size = 0;
        efi_status_t status = gop->query_mode(gop, mode_number, &info_size, &info);
        int matches = !is_error(status) && info &&
                      info->horizontal_resolution == requested_width &&
                      info->vertical_resolution == requested_height;
        if (info && st->boot_services->free_pool) {
            st->boot_services->free_pool(info);
        }
        if (!matches) continue;
        status = gop->set_mode(gop, mode_number);
        serial_puts("uefi: GOP SetMode ");
        serial_hex64(requested_width);
        serial_putc('x');
        serial_hex64(requested_height);
        serial_puts(is_error(status) ? " failed status=" : " selected\n");
        if (is_error(status)) {
            serial_hex64(status);
            serial_putc('\n');
        }
        return is_error(status) ? 0 : 1;
    }
    return 0;
}

static void fb_init(efi_system_table_t *st, uint32_t requested_width,
                    uint32_t requested_height) {
    efi_graphics_output_protocol_t *gop = NULL;
    efi_graphics_output_mode_information_t *info;
    uint32_t r_pos;
    uint32_t g_pos;
    uint32_t b_pos;
    uint32_t bytes_per_pixel;
    uint32_t used_bits;
    uint64_t required_size;
    int custom_mode = 0;
    if (!st || !st->boot_services || !st->boot_services->locate_protocol) return;
    if (is_error(st->boot_services->locate_protocol(&graphics_output_protocol_guid, NULL, (void **)&gop))) return;
    if (requested_width && requested_height &&
        !select_gop_mode(st, gop, requested_width, requested_height)) {
        if (configure_custom_ramfb(st, requested_width, requested_height,
                                   &g_fb_base, &g_fb_size) == 0) {
            custom_mode = 1;
            serial_puts("uefi: custom ramfb mode selected\n");
        } else {
            serial_puts("uefi: custom ramfb mode failed; using GOP default\n");
        }
    }
    if (!gop || !gop->mode || !gop->mode->info || !gop->mode->frame_buffer_base) return;
    info = gop->mode->info;
    g_gop = gop;
    if (custom_mode) {
        g_fb = (uint8_t *)(uintptr_t)g_fb_base;
        g_fb_width = requested_width;
        g_fb_height = requested_height;
        g_fb_stride = requested_width;
        g_fb_format = 1;
        g_fb_bpp = 32u;
    } else {
        g_fb_base = gop->mode->frame_buffer_base;
        g_fb_size = gop->mode->frame_buffer_size;
        g_fb = (uint8_t *)(uintptr_t)g_fb_base;
        g_fb_width = info->horizontal_resolution;
        g_fb_height = info->vertical_resolution;
        g_fb_stride = info->pixels_per_scanline;
        g_fb_format = info->pixel_format;
        g_fb_bpp = 32u;
    }
    if (g_fb_format == 0) {
        g_fb_r_mask = 0x000000ffu;
        g_fb_g_mask = 0x0000ff00u;
        g_fb_b_mask = 0x00ff0000u;
    } else if (g_fb_format == 1) {
        g_fb_b_mask = 0x000000ffu;
        g_fb_g_mask = 0x0000ff00u;
        g_fb_r_mask = 0x00ff0000u;
    } else if (g_fb_format == 2) {
        g_fb_r_mask = info->pixel_information.red_mask;
        g_fb_g_mask = info->pixel_information.green_mask;
        g_fb_b_mask = info->pixel_information.blue_mask;
        if (!g_fb_r_mask || !g_fb_g_mask || !g_fb_b_mask) return;
        used_bits = mask_bits(g_fb_r_mask | g_fb_g_mask | g_fb_b_mask |
                              info->pixel_information.reserved_mask);
        g_fb_bpp = (used_bits + 7u) & ~7u;
        if (g_fb_bpp != 16u && g_fb_bpp != 24u && g_fb_bpp != 32u)
            return;
    } else {
        return;
    }
    bytes_per_pixel = g_fb_bpp / 8u;
    if (g_fb_stride < g_fb_width ||
        g_fb_stride > UINT32_MAX / bytes_per_pixel)
        return;
    g_fb_pitch = g_fb_stride * bytes_per_pixel;
    required_size = (uint64_t)g_fb_pitch * g_fb_height;
    if (!required_size || required_size > g_fb_size) return;
    g_fb_r_pos = mask_pos(g_fb_r_mask);
    g_fb_g_pos = mask_pos(g_fb_g_mask);
    g_fb_b_pos = mask_pos(g_fb_b_mask);
    r_pos = g_fb_r_pos;
    g_pos = g_fb_g_pos;
    b_pos = g_fb_b_pos;
    fb_install_physical(g_fb_base,
                        (uint8_t *)(uintptr_t)g_fb_base,
                        g_fb_width, g_fb_height, g_fb_pitch, g_fb_bpp,
                        r_pos, g_pos, b_pos,
                        g_fb_r_mask, g_fb_g_mask, g_fb_b_mask);
    serial_puts("uefi: GOP framebuffer format=");
    serial_hex64(g_fb_format);
    serial_puts(" bpp=");
    serial_hex64(g_fb_bpp);
    serial_puts(" pitch=");
    serial_hex64(g_fb_pitch);
    serial_putc('\n');
    console_set_backend(&FB_CONSOLE);
    console_init(COLOR_WHITE, COLOR_BLACK);
    fb_console_present();
    fb_flush_rect(0, 0, (int)g_fb_width, (int)g_fb_height);
    (void)g_gop;
}

static efi_status_t open_volume_file(efi_handle_t image_handle,
                                     efi_system_table_t *st,
                                     const efi_char16_t *path,
                                     efi_file_protocol_t **file_out) {
    efi_loaded_image_protocol_t *loaded = NULL;
    efi_simple_file_system_protocol_t *fs = NULL;
    efi_file_protocol_t *root = NULL;
    efi_file_protocol_t *file = NULL;
    efi_status_t status;

    status = st->boot_services->open_protocol(image_handle, &loaded_image_protocol_guid,
                                              (void **)&loaded, image_handle, NULL,
                                              EFI_OPEN_PROTOCOL_BY_HANDLE_PROTOCOL);
    if (is_error(status)) return status;

    status = st->boot_services->open_protocol(loaded->device_handle,
                                              &simple_file_system_protocol_guid,
                                              (void **)&fs, image_handle, NULL,
                                              EFI_OPEN_PROTOCOL_BY_HANDLE_PROTOCOL);
    if (is_error(status)) return status;

    status = fs->open_volume(fs, &root);
    if (is_error(status)) return status;

    status = root->open(root, &file, path, EFI_FILE_MODE_READ, 0);
    if (is_error(status)) {
        root->close(root);
        return status;
    }

    *file_out = file;
    root->close(root);
    return EFI_SUCCESS;
}

static int load_requested_video_mode(efi_handle_t image_handle,
                                     efi_system_table_t *st,
                                     uint32_t *width_out,
                                     uint32_t *height_out) {
    efi_file_protocol_t *file = NULL;
    efi_status_t status;
    char buffer[32];
    uint64_t size = sizeof(buffer) - 1u;
    uint32_t width = 0;
    uint32_t height = 0;
    uint64_t index = 0;

    if (!width_out || !height_out) return 0;
    status = open_volume_file(image_handle, st, u"\\boot\\video.cfg", &file);
    if (is_error(status) || !file) return 0;
    status = file->read(file, &size, buffer);
    file->close(file);
    if (is_error(status) || size < 3u) return 0;
    buffer[size] = 0;
    while (index < size && buffer[index] >= '0' && buffer[index] <= '9') {
        width = width * 10u + (uint32_t)(buffer[index++] - '0');
    }
    if (index >= size || (buffer[index] != 'x' && buffer[index] != 'X')) return 0;
    index++;
    while (index < size && buffer[index] >= '0' && buffer[index] <= '9') {
        height = height * 10u + (uint32_t)(buffer[index++] - '0');
    }
    if (!width || !height) return 0;
    *width_out = width;
    *height_out = height;
    return 1;
}

static uint64_t append_utf16_command_line(
    char *buffer, uint64_t length, uint64_t capacity,
    const efi_char16_t *options, uint64_t option_bytes) {
    uint64_t units = option_bytes / sizeof(efi_char16_t);
    uint64_t index = 0;

    if (!buffer || !capacity || !options) return length;
    while (index < units &&
           (options[index] == 0 || options[index] == ' ' ||
            options[index] == '\t'))
        index++;
    if (index < units && length && length + 1u < capacity)
        buffer[length++] = ' ';
    while (index < units && options[index] != 0) {
        uint32_t codepoint = options[index++];

        if (codepoint >= 0xd800u && codepoint <= 0xdbffu &&
            index < units && options[index] >= 0xdc00u &&
            options[index] <= 0xdfffu) {
            codepoint = 0x10000u +
                ((codepoint - 0xd800u) << 10) +
                (options[index++] - 0xdc00u);
        } else if (codepoint >= 0xd800u && codepoint <= 0xdfffu) {
            codepoint = 0xfffdu;
        }
        if (codepoint < 0x80u) {
            if (length + 1u >= capacity) break;
            buffer[length++] = (char)codepoint;
        } else if (codepoint < 0x800u) {
            if (length + 2u >= capacity) break;
            buffer[length++] = (char)(0xc0u | (codepoint >> 6));
            buffer[length++] = (char)(0x80u | (codepoint & 0x3fu));
        } else if (codepoint < 0x10000u) {
            if (length + 3u >= capacity) break;
            buffer[length++] = (char)(0xe0u | (codepoint >> 12));
            buffer[length++] = (char)(0x80u | ((codepoint >> 6) & 0x3fu));
            buffer[length++] = (char)(0x80u | (codepoint & 0x3fu));
        } else {
            if (length + 4u >= capacity) break;
            buffer[length++] = (char)(0xf0u | (codepoint >> 18));
            buffer[length++] = (char)(0x80u | ((codepoint >> 12) & 0x3fu));
            buffer[length++] = (char)(0x80u | ((codepoint >> 6) & 0x3fu));
            buffer[length++] = (char)(0x80u | (codepoint & 0x3fu));
        }
    }
    while (length && (buffer[length - 1u] == ' ' ||
                      buffer[length - 1u] == '\t'))
        length--;
    buffer[length] = 0;
    return length;
}

static void load_boot_command_line(efi_handle_t image_handle,
                                   efi_system_table_t *st,
                                   efi_loaded_image_protocol_t *loaded) {
    efi_file_protocol_t *file = NULL;
    efi_status_t status;
    char buffer[EDGEOS_BOOT_COMMAND_LINE_MAX];
    uint64_t length = 0;
    uint64_t size = sizeof(buffer) - 1u;

    buffer[0] = 0;
    status = open_volume_file(image_handle, st, u"\\boot\\cmdline", &file);
    if (!is_error(status) && file) {
        status = file->read(file, &size, buffer);
        file->close(file);
        if (!is_error(status)) {
            if (size >= sizeof(buffer)) size = sizeof(buffer) - 1u;
            while (size &&
                   (buffer[size - 1u] == '\n' ||
                    buffer[size - 1u] == '\r' ||
                    buffer[size - 1u] == 0))
                size--;
            buffer[size] = 0;
            length = size;
        }
    }
    if (loaded && loaded->load_options && loaded->load_options_size) {
        length = append_utf16_command_line(
            buffer, length, sizeof(buffer),
            (const efi_char16_t *)loaded->load_options,
            loaded->load_options_size);
    }
    (void)length;
    kernel_boot_command_line_set(buffer);
}

static efi_status_t load_file_image(efi_handle_t image_handle,
                                    efi_system_table_t *st,
                                    const efi_char16_t *path,
                                    uint64_t minimum_size,
                                    void **base_out, uint64_t *size_out) {
    efi_file_protocol_t *file = NULL;
    efi_status_t status;
    uint8_t info_buf[512];
    uint64_t info_len = sizeof(info_buf);
    efi_file_info_t *info = (efi_file_info_t *)info_buf;
    uint64_t file_size;
    uint64_t pages;
    uint64_t phys = 0;
    uint64_t off = 0;
    uint8_t *dst;

    if (!st || !st->boot_services || !base_out || !size_out) return EFI_LOAD_ERROR;
    *base_out = NULL;
    *size_out = 0;

    status = open_volume_file(image_handle, st, path, &file);
    if (is_error(status)) return status;

    status = file->get_info(file, &file_info_guid, &info_len, info_buf);
    if (is_error(status) || info_len < sizeof(*info) ||
        info->file_size < minimum_size) {
        file->close(file);
        return is_error(status) ? status : EFI_LOAD_ERROR;
    }

    file_size = info->file_size;
    pages = (file_size + 4095u) >> 12;
    status = st->boot_services->allocate_pages(EFI_ALLOCATE_ANY_PAGES, EFI_LOADER_DATA,
                                               pages, &phys);
    if (is_error(status) || phys == 0) {
        file->close(file);
        return is_error(status) ? status : EFI_LOAD_ERROR;
    }

    dst = (uint8_t *)(uintptr_t)phys;
    if (file->set_position) {
        status = file->set_position(file, 0);
        if (is_error(status)) {
            file->close(file);
            st->boot_services->free_pages(phys, pages);
            return status;
        }
    }

    while (off < file_size) {
        uint64_t chunk = file_size - off;
        if (chunk > (1024u * 1024u)) chunk = 1024u * 1024u;
        status = file->read(file, &chunk, dst + off);
        if (is_error(status) || chunk == 0) {
            file->close(file);
            st->boot_services->free_pages(phys, pages);
            return is_error(status) ? status : EFI_LOAD_ERROR;
        }
        off += chunk;
    }
    file->close(file);

    *base_out = dst;
    *size_out = file_size;
    return EFI_SUCCESS;
}

static efi_status_t load_rootfs_image(efi_handle_t image_handle,
                                      efi_system_table_t *st,
                                      void **base_out, uint64_t *size_out) {
    efi_status_t status = load_file_image(
        image_handle, st, u"\\boot\\rootfs.img", 1082u,
        base_out, size_out);

    if (is_error(status)) return status;
    if (((uint8_t *)*base_out)[1080] != 0x53 ||
        ((uint8_t *)*base_out)[1081] != 0xef) {
        st->boot_services->free_pages(
            (uint64_t)(uintptr_t)*base_out, (*size_out + 4095u) >> 12);
        *base_out = NULL;
        *size_out = 0;
        return EFI_LOAD_ERROR;
    }
    return EFI_SUCCESS;
}

static int utf8_path_to_uefi(const char *path, efi_char16_t *output,
                             uint64_t capacity) {
    const uint8_t *cursor = (const uint8_t *)path;
    uint64_t length = 0;

    if (!path || !path[0] || !output || capacity < 2u) return -1;
    if (path[0] != '/' && path[0] != '\\')
        output[length++] = '\\';
    while (*cursor) {
        uint32_t codepoint;

        if (*cursor < 0x80u) {
            codepoint = *cursor++;
        } else if (cursor[1] != 0 &&
                   (*cursor & 0xe0u) == 0xc0u &&
                   (cursor[1] & 0xc0u) == 0x80u) {
            codepoint = ((uint32_t)(cursor[0] & 0x1fu) << 6) |
                        (uint32_t)(cursor[1] & 0x3fu);
            if (codepoint < 0x80u) return -1;
            cursor += 2;
        } else if (cursor[1] != 0 && cursor[2] != 0 &&
                   (*cursor & 0xf0u) == 0xe0u &&
                   (cursor[1] & 0xc0u) == 0x80u &&
                   (cursor[2] & 0xc0u) == 0x80u) {
            codepoint = ((uint32_t)(cursor[0] & 0x0fu) << 12) |
                        ((uint32_t)(cursor[1] & 0x3fu) << 6) |
                        (uint32_t)(cursor[2] & 0x3fu);
            if (codepoint < 0x800u ||
                (codepoint >= 0xd800u && codepoint <= 0xdfffu))
                return -1;
            cursor += 3;
        } else if (cursor[1] != 0 && cursor[2] != 0 &&
                   cursor[3] != 0 &&
                   (*cursor & 0xf8u) == 0xf0u &&
                   (cursor[1] & 0xc0u) == 0x80u &&
                   (cursor[2] & 0xc0u) == 0x80u &&
                   (cursor[3] & 0xc0u) == 0x80u) {
            codepoint = ((uint32_t)(cursor[0] & 0x07u) << 18) |
                        ((uint32_t)(cursor[1] & 0x3fu) << 12) |
                        ((uint32_t)(cursor[2] & 0x3fu) << 6) |
                        (uint32_t)(cursor[3] & 0x3fu);
            if (codepoint < 0x10000u || codepoint > 0x10ffffu)
                return -1;
            cursor += 4;
        } else {
            return -1;
        }
        if (codepoint == '/') codepoint = '\\';
        if (codepoint < 0x10000u) {
            if (length + 1u >= capacity) return -1;
            output[length++] = (efi_char16_t)codepoint;
        } else {
            if (length + 2u >= capacity) return -1;
            codepoint -= 0x10000u;
            output[length++] =
                (efi_char16_t)(0xd800u | (codepoint >> 10));
            output[length++] =
                (efi_char16_t)(0xdc00u | (codepoint & 0x3ffu));
        }
    }
    output[length] = 0;
    return 0;
}

static efi_status_t load_initramfs_image(
    efi_handle_t image_handle, efi_system_table_t *st,
    void **base_out, uint64_t *size_out, int *requested_out) {
    char requested_path[256];
    efi_char16_t uefi_path[256];
    const efi_char16_t *path = u"\\boot\\initramfs.img";
    efi_status_t status;

    if (requested_out) *requested_out = 0;
    if (kernel_boot_option_get(
            "initrd", requested_path, sizeof(requested_path)) > 0) {
        if (utf8_path_to_uefi(
                requested_path, uefi_path,
                sizeof(uefi_path) / sizeof(uefi_path[0])) < 0)
            return EFI_INVALID_PARAMETER;
        path = uefi_path;
        if (requested_out) *requested_out = 1;
    }
    status = load_file_image(
        image_handle, st, path, 110u, base_out, size_out);
    if (is_error(status) && requested_out && !*requested_out)
        status = load_file_image(
            image_handle, st, u"\\boot\\initramfs.cpio", 110u,
            base_out, size_out);
    if (is_error(status) && st && st->boot_services &&
        st->boot_services->locate_protocol) {
        efi_load_file_protocol_t *load_file2 = NULL;
        uint64_t buffer_size = 0;
        uint64_t pages;
        uint64_t phys = 0;

        status = st->boot_services->locate_protocol(
            &load_file2_protocol_guid, NULL, (void **)&load_file2);
        if (!is_error(status) && load_file2 && load_file2->load_file) {
            status = load_file2->load_file(
                load_file2, NULL, 0, &buffer_size, NULL);
            if (status == EFI_BUFFER_TOO_SMALL && buffer_size >= 110u) {
                pages = (buffer_size + 4095u) >> 12;
                status = st->boot_services->allocate_pages(
                    EFI_ALLOCATE_ANY_PAGES, EFI_LOADER_DATA, pages, &phys);
                if (!is_error(status) && phys != 0) {
                    uint64_t loaded_size = buffer_size;

                    status = load_file2->load_file(
                        load_file2, NULL, 0, &loaded_size,
                        (void *)(uintptr_t)phys);
                    if (!is_error(status) && loaded_size >= 110u) {
                        *base_out = (void *)(uintptr_t)phys;
                        *size_out = loaded_size;
                    } else {
                        st->boot_services->free_pages(phys, pages);
                    }
                }
            }
        }
    }
    if (is_error(status)) return status;
    if (!initramfs_buffer_has_archive(*base_out, *size_out)) {
        st->boot_services->free_pages(
            (uint64_t)(uintptr_t)*base_out, (*size_out + 4095u) >> 12);
        *base_out = NULL;
        *size_out = 0;
        return EFI_LOAD_ERROR;
    }
    return EFI_SUCCESS;
}

static efi_status_t collect_efi_memory_map(efi_system_table_t *st, uint64_t *map_key) {
    efi_status_t status;
    uint64_t map_size = sizeof(g_efi_mmap_storage);
    uint64_t descriptor_size = 0;
    uint32_t descriptor_version = 0;

    if (!st || !st->boot_services || !st->boot_services->get_memory_map || !map_key) {
        return EFI_LOAD_ERROR;
    }

    status = st->boot_services->get_memory_map(&map_size, g_efi_mmap_storage, map_key,
                                               &descriptor_size, &descriptor_version);
    if (is_error(status)) return status;

    g_bootinfo.efi_mmap.map = (uint64_t)(uintptr_t)g_efi_mmap_storage;
    g_bootinfo.efi_mmap.size = map_size;
    g_bootinfo.efi_mmap.descriptor_size = descriptor_size;
    g_bootinfo.efi_mmap.descriptor_version = descriptor_version;
    g_bootinfo.flags |= EDGEOS_ARM64_BOOTINFO_FLAG_EFI_MMAP;
    return EFI_SUCCESS;
}

static efi_status_t build_bootinfo(efi_system_table_t *st) {
    efi_status_t status;

    g_bootinfo.magic = EDGEOS_ARM64_BOOTINFO_MAGIC;
    g_bootinfo.version = EDGEOS_ARM64_BOOTINFO_VERSION;
    g_bootinfo.efi_system_table = (uint64_t)(uintptr_t)st;
    status = capture_fdt(st);
    if (is_error(status)) return status;
    capture_acpi(st);
    if (g_fb && g_fb_base && g_fb_size) {
        g_bootinfo.fb.base = g_fb_base;
        g_bootinfo.fb.size = g_fb_size;
        g_bootinfo.fb.width = g_fb_width;
        g_bootinfo.fb.height = g_fb_height;
        g_bootinfo.fb.pitch = g_fb_pitch;
        g_bootinfo.fb.bpp = g_fb_bpp;
        g_bootinfo.fb.r_pos = g_fb_r_pos;
        g_bootinfo.fb.g_pos = g_fb_g_pos;
        g_bootinfo.fb.b_pos = g_fb_b_pos;
        g_bootinfo.fb.r_mask = g_fb_r_mask;
        g_bootinfo.fb.g_mask = g_fb_g_mask;
        g_bootinfo.fb.b_mask = g_fb_b_mask;
        g_bootinfo.flags |= EDGEOS_ARM64_BOOTINFO_FLAG_GOP_FB;
    }
    if (g_rootfs_base && g_rootfs_size) {
        g_bootinfo.rootfs.base = (uint64_t)(uintptr_t)g_rootfs_base;
        g_bootinfo.rootfs.size = g_rootfs_size;
        g_bootinfo.rootfs.type = 1;
        g_bootinfo.flags |= EDGEOS_ARM64_BOOTINFO_FLAG_ROOTFS;
    }
    if (g_initramfs_base && g_initramfs_size) {
        g_bootinfo.initramfs.base =
            (uint64_t)(uintptr_t)g_initramfs_base;
        g_bootinfo.initramfs.size = g_initramfs_size;
        g_bootinfo.initramfs.type = 3;
        g_bootinfo.flags |= EDGEOS_ARM64_BOOTINFO_FLAG_INITRAMFS;
    }
    g_bootinfo.kernel_image.base = g_kernel_image_base;
    g_bootinfo.kernel_image.size = g_kernel_image_size;
    g_bootinfo.kernel_image.type = 2;
    return EFI_SUCCESS;
}

efi_status_t EFIAPI efi_main(efi_handle_t image_handle, efi_system_table_t *st) {
    efi_status_t status;
    uint64_t map_key = 0;
    efi_loaded_image_protocol_t *loaded = NULL;
    uint32_t requested_width = 0;
    uint32_t requested_height = 0;
    int initramfs_requested = 0;

    if (!is_error(st->boot_services->open_protocol(
            image_handle, &loaded_image_protocol_guid, (void **)&loaded,
            image_handle, NULL, EFI_OPEN_PROTOCOL_BY_HANDLE_PROTOCOL)) && loaded) {
        g_kernel_image_base = (uint64_t)(uintptr_t)loaded->image_base;
        g_kernel_image_size = loaded->image_size;
    }

    g_con = st ? st->con_out : NULL;
    pl011_init();
#if defined(CONFIG_BSD_DRIVER_BRIDGE) && defined(CONFIG_DEVICE_TREE)
    if (!is_error(capture_fdt(st)) &&
        (g_bootinfo.flags & EDGEOS_ARM64_BOOTINFO_FLAG_FDT) != 0 &&
        bsd_ofw_fdt_install(
            (const void *)(uintptr_t)g_bootinfo.fdt_base,
            (size_t)g_bootinfo.fdt_size) == 0)
        (void)edgeos_arm64_platform_configure(&g_bootinfo);
#endif
    load_boot_command_line(image_handle, st, loaded);
    load_requested_video_mode(image_handle, st, &requested_width, &requested_height);
    fb_init(st, requested_width, requested_height);
    serial_puts("\nEdgeOS arm64 generic UEFI boot\n");
    serial_puts("arch=aarch64 platform=uefi kernel=edgeos\n");
    puts16(u"\r\nEdgeOS arm64 generic UEFI boot\r\n");
    puts16(u"arch=aarch64 platform=uefi kernel=edgeos\r\n");
    fb_log("arch=aarch64 platform=uefi", pixel(181, 229, 255));
    fb_log("kernel=EdgeOS BOOTAA64.EFI", pixel(181, 229, 255));
    fb_log("fbcon=uefi-gop active", pixel(181, 229, 255));

    status = load_rootfs_image(image_handle, st, &g_rootfs_base, &g_rootfs_size);
    g_rootfs_status = status;
    if (is_error(status)) {
        puts16(u"rootfs: load \\boot\\rootfs.img failed status=");
        put_hex64(status);
        puts16(u"\r\n");
        serial_puts("rootfs: load /boot/rootfs.img failed status=");
        serial_hex64(status);
        serial_putc('\n');
        fb_log("rootfs=load failed", pixel(255, 130, 130));
    } else {
        g_rootfs_ok = 1;
        puts16(u"rootfs: arm64 ext4 image loaded from \\boot\\rootfs.img\r\n");
        serial_puts("rootfs: arm64 ext4 image loaded from /boot/rootfs.img base=");
        serial_hex64((uint64_t)(uintptr_t)g_rootfs_base);
        serial_puts(" size=");
        serial_hex64(g_rootfs_size);
        serial_putc('\n');
        fb_log("rootfs=arm64 ext4 loaded", pixel(156, 255, 190));
    }

    status = load_initramfs_image(
        image_handle, st, &g_initramfs_base, &g_initramfs_size,
        &initramfs_requested);
    if (!is_error(status)) {
        serial_puts("initramfs: cpio image loaded base=");
        serial_hex64((uint64_t)(uintptr_t)g_initramfs_base);
        serial_puts(" size=");
        serial_hex64(g_initramfs_size);
        serial_putc('\n');
        fb_log("initramfs=cpio loaded", pixel(156, 255, 190));
    } else if (initramfs_requested) {
        serial_puts("initramfs: requested image load failed status=");
        serial_hex64(status);
        serial_putc('\n');
        fb_log("initramfs=requested load failed", pixel(255, 130, 130));
    }

    status = build_bootinfo(st);
    if (is_error(status)) {
        puts16(u"uefi: preserve firmware tables failed status=");
        put_hex64(status);
        puts16(u"\r\n");
        serial_puts("uefi: preserve firmware tables failed status=");
        serial_hex64(status);
        serial_putc('\n');
        fb_log("uefi-firmware-tables=failed", pixel(255, 130, 130));
        for (;;) __asm__ __volatile__("wfe");
    }
    status = collect_efi_memory_map(st, &map_key);
    if (is_error(status)) {
        puts16(u"uefi: GetMemoryMap failed status=");
        put_hex64(status);
        puts16(u"\r\n");
        serial_puts("uefi: GetMemoryMap failed status=");
        serial_hex64(status);
        serial_putc('\n');
        fb_log("uefi-memory-map=failed", pixel(255, 130, 130));
        for (;;) __asm__ __volatile__("wfe");
    }

    serial_puts("bootinfo: flags=");
    serial_hex64(g_bootinfo.flags);
    serial_puts(" kernel=");
    serial_hex64(g_bootinfo.kernel_image.base);
    serial_puts(" kernel_size=");
    serial_hex64(g_bootinfo.kernel_image.size);
    serial_puts(" mmap=");
    serial_hex64(g_bootinfo.efi_mmap.map);
    serial_puts(" mmap_size=");
    serial_hex64(g_bootinfo.efi_mmap.size);
    serial_puts(" desc=");
    serial_hex64(g_bootinfo.efi_mmap.descriptor_size);
    serial_putc('\n');
    fb_log("bootinfo=ready for EL1 kernel handoff", pixel(156, 255, 190));

    /*
     * ExitBootServices invalidates every Boot Services protocol.  The memory
     * map key is deliberately acquired immediately before this call, and is
     * reacquired if firmware reports that a concurrent firmware allocation
     * made it stale.  Post-success execution is EdgeOS-only code.
     */
    serial_puts("uefi: ExitBootServices\n");
    status = st->boot_services->exit_boot_services(image_handle, map_key);
    if (status == EFI_INVALID_PARAMETER) {
        status = collect_efi_memory_map(st, &map_key);
        if (!is_error(status)) {
            status = st->boot_services->exit_boot_services(image_handle, map_key);
        }
    }
    if (is_error(status)) {
        puts16(u"uefi: ExitBootServices failed status=");
        put_hex64(status);
        puts16(u"\r\n");
        serial_puts("uefi: ExitBootServices failed status=");
        serial_hex64(status);
        serial_putc('\n');
        fb_log("uefi-exit-boot-services=failed", pixel(255, 130, 130));
        for (;;) __asm__ __volatile__("wfe");
    }

    if (g_fb && g_fb_width && g_fb_height)
        fb_flush_rect(0, 0, (int)g_fb_width, (int)g_fb_height);
    /*
     * Raspberry Pi U-Boot invokes EFI applications at EL2.  Prepare EL1's
     * translation registers while EL2 mappings are still active so the eret
     * in edgeos_arm64_kernel_entry cannot land on stale firmware EL1 state.
     * EDK2/QEMU normally invokes us at EL1 and keeps the existing path.
     */
    if (current_exception_level() == 2u &&
        edgeos_arm64_mmu_init(&g_bootinfo) < 0) {
        for (;;) __asm__ __volatile__("wfe");
    }
    (void)g_rootfs_ok;
    edgeos_arm64_kernel_entry(&g_bootinfo);
}
