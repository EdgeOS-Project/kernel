/* SPDX-License-Identifier: MPL-2.0 */
/* Unit tests for the shared Linux DRM/KMS dumb-buffer runtime. */

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "display.h"
#include "fb.h"
#include "kernel/anonymous_fd.h"
#include "kernel/drm_runtime.h"
#include "kernel/linux_errno.h"

#define DRM_IOCTL_VERSION                0xc0406400u
#define DRM_IOCTL_GET_CAP                0xc010640cu
#define DRM_IOCTL_SET_CLIENT_CAP         0x4010640du
#define DRM_IOCTL_WAIT_VBLANK            0xc018643au
#define DRM_IOCTL_PRIME_HANDLE_TO_FD     0xc00c642du
#define DRM_IOCTL_PRIME_FD_TO_HANDLE     0xc00c642eu
#define DRM_IOCTL_SET_MASTER             0x0000641eu
#define DRM_IOCTL_MODE_GETRESOURCES      0xc04064a0u
#define DRM_IOCTL_MODE_SETCRTC           0xc06864a2u
#define DRM_IOCTL_MODE_GETCONNECTOR      0xc05064a7u
#define DRM_IOCTL_MODE_GETPROPBLOB       0xc01064acu
#define DRM_IOCTL_MODE_PAGE_FLIP         0xc01864b0u
#define DRM_IOCTL_MODE_CREATE_DUMB       0xc02064b2u
#define DRM_IOCTL_MODE_MAP_DUMB          0xc01064b3u
#define DRM_IOCTL_MODE_GETPLANERESOURCES 0xc01064b5u
#define DRM_IOCTL_MODE_GETPLANE          0xc02064b6u
#define DRM_IOCTL_MODE_ADDFB2            0xc06864b8u
#define DRM_IOCTL_MODE_OBJ_GETPROPERTIES 0xc02064b9u
#define DRM_IOCTL_MODE_OBJ_SETPROPERTY   0xc01864bau
#define DRM_IOCTL_MODE_ATOMIC            0xc03864bcu
#define DRM_IOCTL_MODE_CREATEPROPBLOB    0xc01064bdu
#define DRM_IOCTL_MODE_DESTROYPROPBLOB   0xc00464beu
#define DRM_IOCTL_MODE_LIST_LESSEES      0xc01064c7u
#define DRM_MODE_PAGE_FLIP_EVENT         0x01u
#define DRM_VBLANK_RELATIVE              0x00000001u
#define DRM_VBLANK_EVENT                 0x04000000u
#define DRM_MODE_ATOMIC_TEST_ONLY        0x0100u
#define DRM_MODE_ATOMIC_ALLOW_MODESET    0x0400u
#define DRM_FORMAT_XRGB8888              0x34325258u
#define DRM_FORMAT_ARGB8888              0x34325241u
#define DRM_CLIENT_CAP_UNIVERSAL_PLANES  2u
#define DRM_CLIENT_CAP_ATOMIC            3u
#define DRM_CAP_DUMB_BUFFER              0x01u
#define DRM_CAP_VBLANK_HIGH_CRTC         0x02u
#define DRM_CAP_DUMB_PREFERRED_DEPTH     0x03u
#define DRM_CAP_DUMB_PREFER_SHADOW       0x04u
#define DRM_CAP_PRIME                    0x05u
#define DRM_CAP_TIMESTAMP_MONOTONIC      0x06u
#define DRM_CAP_ASYNC_PAGE_FLIP          0x07u
#define DRM_CAP_CURSOR_WIDTH             0x08u
#define DRM_CAP_CURSOR_HEIGHT            0x09u
#define DRM_CAP_ADDFB2_MODIFIERS         0x10u
#define DRM_CAP_PAGE_FLIP_TARGET         0x11u
#define DRM_CAP_CRTC_IN_VBLANK_EVENT     0x12u
#define DRM_CLOEXEC                      0x00080000u
#define DRM_RDWR                         0x00000002u
#define DRM_MODE_OBJECT_CRTC             0xccccccccu
#define DRM_MODE_OBJECT_PLANE            0xeeeeeeeeu

typedef struct {
    uint64_t capability;
    uint64_t value;
} test_drm_get_cap_t;

typedef union {
    struct {
        uint32_t type;
        uint32_t sequence;
        uint64_t signal;
    } request;
    struct {
        uint32_t type;
        uint32_t sequence;
        int64_t tv_sec;
        int64_t tv_usec;
    } reply;
} test_drm_wait_vblank_t;

typedef struct {
    int32_t version_major;
    int32_t version_minor;
    int32_t version_patchlevel;
    uint32_t pad;
    uint64_t name_len;
    uint64_t name;
    uint64_t date_len;
    uint64_t date;
    uint64_t desc_len;
    uint64_t desc;
} test_drm_version_t;

typedef struct {
    uint32_t clock;
    uint16_t hdisplay;
    uint16_t hsync_start;
    uint16_t hsync_end;
    uint16_t htotal;
    uint16_t hskew;
    uint16_t vdisplay;
    uint16_t vsync_start;
    uint16_t vsync_end;
    uint16_t vtotal;
    uint16_t vscan;
    uint32_t vrefresh;
    uint32_t flags;
    uint32_t type;
    char name[32];
} test_drm_modeinfo_t;

typedef struct {
    uint64_t fb_id_ptr;
    uint64_t crtc_id_ptr;
    uint64_t connector_id_ptr;
    uint64_t encoder_id_ptr;
    uint32_t count_fbs;
    uint32_t count_crtcs;
    uint32_t count_connectors;
    uint32_t count_encoders;
    uint32_t min_width;
    uint32_t max_width;
    uint32_t min_height;
    uint32_t max_height;
} test_drm_card_res_t;

typedef struct {
    uint64_t encoders_ptr;
    uint64_t modes_ptr;
    uint64_t props_ptr;
    uint64_t prop_values_ptr;
    uint32_t count_modes;
    uint32_t count_props;
    uint32_t count_encoders;
    uint32_t encoder_id;
    uint32_t connector_id;
    uint32_t connector_type;
    uint32_t connector_type_id;
    uint32_t connection;
    uint32_t mm_width;
    uint32_t mm_height;
    uint32_t subpixel;
    uint32_t pad;
} test_drm_connector_t;

typedef struct {
    uint32_t height;
    uint32_t width;
    uint32_t bpp;
    uint32_t flags;
    uint32_t handle;
    uint32_t pitch;
    uint64_t size;
} test_drm_create_dumb_t;

typedef struct {
    uint32_t handle;
    uint32_t pad;
    uint64_t offset;
} test_drm_map_dumb_t;

typedef struct {
    uint32_t handle;
    uint32_t flags;
    int32_t fd;
} test_drm_prime_handle_t;

typedef struct {
    uint32_t fb_id;
    uint32_t width;
    uint32_t height;
    uint32_t pixel_format;
    uint32_t flags;
    uint32_t handles[4];
    uint32_t pitches[4];
    uint32_t offsets[4];
    uint64_t modifier[4];
} test_drm_fb_cmd2_t;

typedef struct {
    uint64_t set_connectors_ptr;
    uint32_t count_connectors;
    uint32_t crtc_id;
    uint32_t fb_id;
    uint32_t x;
    uint32_t y;
    uint32_t gamma_size;
    uint32_t mode_valid;
    test_drm_modeinfo_t mode;
} test_drm_crtc_t;

typedef struct {
    uint32_t crtc_id;
    uint32_t fb_id;
    uint32_t flags;
    uint32_t reserved;
    uint64_t user_data;
} test_drm_page_flip_t;

typedef struct {
    uint64_t plane_id_ptr;
    uint32_t count_planes;
    uint32_t pad;
} test_drm_plane_res_t;

typedef struct {
    uint32_t plane_id;
    uint32_t crtc_id;
    uint32_t fb_id;
    uint32_t possible_crtcs;
    uint32_t gamma_size;
    uint32_t count_format_types;
    uint64_t format_type_ptr;
} test_drm_plane_t;

typedef struct {
    uint32_t type;
    uint32_t length;
    uint64_t user_data;
    uint32_t tv_sec;
    uint32_t tv_usec;
    uint32_t sequence;
    uint32_t crtc_id;
} test_drm_event_t;

typedef struct {
    uint64_t capability;
    uint64_t value;
} test_drm_set_client_cap_t;

typedef struct {
    uint32_t blob_id;
    uint32_t length;
    uint64_t data;
} test_drm_get_blob_t;

typedef struct {
    uint64_t data;
    uint32_t length;
    uint32_t blob_id;
} test_drm_create_blob_t;

typedef struct {
    uint32_t blob_id;
} test_drm_destroy_blob_t;

typedef struct {
    uint32_t count_lessees;
    uint32_t pad;
    uint64_t lessees_ptr;
} test_drm_mode_list_lessees_t;

typedef struct {
    int16_t x1;
    int16_t y1;
    int16_t x2;
    int16_t y2;
} test_drm_mode_rect_t;

typedef struct {
    uint64_t value;
    uint32_t prop_id;
    uint32_t obj_id;
    uint32_t obj_type;
    uint32_t pad;
} test_drm_obj_set_property_t;

typedef struct {
    uint64_t props_ptr;
    uint64_t prop_values_ptr;
    uint32_t count_props;
    uint32_t obj_id;
    uint32_t obj_type;
    uint32_t pad;
} test_drm_obj_get_properties_t;

typedef struct {
    uint32_t flags;
    uint32_t count_objs;
    uint64_t objs_ptr;
    uint64_t count_props_ptr;
    uint64_t props_ptr;
    uint64_t prop_values_ptr;
    uint64_t reserved;
    uint64_t user_data;
} test_drm_atomic_t;

typedef struct {
    display_mode_t mode;
    display_mode_t modes[2];
    uint32_t mode_count;
    uint32_t polls;
    uint8_t edid[128];
} test_display_t;

fb_t fb;

static uint8_t g_scanout[640u * 480u * 4u];
static uint32_t g_flushes;
static uint32_t g_last_flush_rect_count;
static uint32_t g_writeprotect_calls;
static uint64_t g_flush_advance_us;
static uint64_t g_now_us = 1234567u;
static int g_console_drm_owned;
static int32_t g_prime_descriptor = -1;
static int32_t g_prime_object = -1;

int virtio_gpu_cursor_available(void) {
    return 0;
}

int virtio_gpu_cursor_update(const uint8_t *pixels, uint32_t width,
                             uint32_t height, uint32_t pitch,
                             uint32_t source_x, uint32_t source_y,
                             uint32_t cursor_width, uint32_t cursor_height,
                             int32_t x, int32_t y,
                             uint32_t hotspot_x, uint32_t hotspot_y) {
    (void)pixels;
    (void)width;
    (void)height;
    (void)pitch;
    (void)source_x;
    (void)source_y;
    (void)cursor_width;
    (void)cursor_height;
    (void)x;
    (void)y;
    (void)hotspot_x;
    (void)hotspot_y;
    return -1;
}

int virtio_gpu_cursor_hide(void) {
    return -1;
}

void *arch_vm_alloc_pages(uint64_t page_count) {
    void *memory = 0;
    if (posix_memalign(&memory, 4096u, (size_t)page_count * 4096u) != 0)
        return 0;
    return memory;
}

void arch_vm_free_page(void *page) {
    (void)page;
}

int kernel_eventfd_retain(int event_id) {
    return event_id == 1 ? 0 : -EDGE_LINUX_EBADF;
}

void kernel_eventfd_release(int event_id) {
    assert(event_id == 1);
}

int64_t kernel_eventfd_write_value(int event_id, int nonblocking,
                                   uint64_t value) {
    assert(event_id == 1);
    assert(nonblocking == 1);
    assert(value == 1u);
    return 8;
}

void kernel_drm_sync_state_changed(int32_t object_id) {
    (void)object_id;
}

int kernel_runtime_yield(void) {
    return 1;
}

int kernel_runtime_wait_sequence(volatile uint64_t *sequence,
                                 uint64_t observed,
                                 uint64_t deadline_microseconds) {
    if (sequence &&
        __atomic_load_n(sequence, __ATOMIC_ACQUIRE) != observed)
        return 1;
    if (deadline_microseconds != UINT64_MAX &&
        g_now_us < deadline_microseconds)
        g_now_us = deadline_microseconds;
    return 0;
}

int64_t kernel_current_sleep_until(uint64_t deadline_microseconds,
                                   uint64_t remaining_user,
                                   int write_remaining,
                                   int remaining_time32,
                                   void *user_registers) {
    (void)remaining_user;
    (void)write_remaining;
    (void)remaining_time32;
    (void)user_registers;
    if (g_now_us < deadline_microseconds)
        g_now_us = deadline_microseconds;
    return 0;
}

void kernel_runtime_notify_sequence(volatile uint64_t *sequence) {
    (void)sequence;
}

int arch_vm_write_notify_supported(void) {
    return 1;
}

int arch_vm_writeprotect_physical_aliases(uint64_t physical_address,
                                          uint64_t length) {
    assert(physical_address != 0u);
    assert(length != 0u);
    ++g_writeprotect_calls;
    return 1;
}

int kernel_anonymous_fd_install_descriptor(
    kernel_anonymous_fd_kind_t kind, int32_t object_id,
    uint32_t status_flags, uint32_t descriptor_flags) {
    assert(kind == KERNEL_ANONYMOUS_FD_PRIME);
    assert(status_flags == DRM_RDWR);
    assert(descriptor_flags == DRM_CLOEXEC);
    assert(g_prime_descriptor < 0);
    g_prime_descriptor = 71;
    g_prime_object = object_id;
    return g_prime_descriptor;
}

int kernel_anonymous_fd_descriptor_object_id(
    int32_t descriptor, kernel_anonymous_fd_kind_t kind) {
    if (descriptor != g_prime_descriptor ||
        kind != KERNEL_ANONYMOUS_FD_PRIME)
        return -EDGE_LINUX_EBADF;
    return g_prime_object;
}

int kernel_fd_close(int32_t descriptor) {
    if (descriptor != g_prime_descriptor)
        return -EDGE_LINUX_EBADF;
    edge_drm_prime_release(g_prime_object);
    g_prime_descriptor = -1;
    g_prime_object = -1;
    return 0;
}

uint64_t boottime_monotonic_us(void) {
    return g_now_us++;
}

void fb_flush_rect(int x, int y, int width, int height) {
    assert(x >= 0 && y >= 0);
    assert(width > 0 && height > 0);
    g_flushes++;
    g_last_flush_rect_count = 1u;
    g_now_us += g_flush_advance_us;
    g_flush_advance_us = 0;
}

void fb_flush_rects(const display_rect_t *rects, uint32_t count) {
    assert(rects != NULL);
    assert(count > 0u);
    for (uint32_t index = 0; index < count; ++index) {
        assert(rects[index].width > 0u);
        assert(rects[index].height > 0u);
    }
    g_flushes++;
    g_last_flush_rect_count = count;
    g_now_us += g_flush_advance_us;
    g_flush_advance_us = 0;
}

void fb_console_set_drm_owned(int owned) {
    g_console_drm_owned = owned ? 1 : 0;
}

static int test_copy_from(void *context, void *destination,
                          uint64_t source, uint64_t length) {
    (void)context;
    memcpy(destination, (const void *)(uintptr_t)source, (size_t)length);
    return 0;
}

static int test_copy_to(void *context, uint64_t destination,
                        const void *source, uint64_t length) {
    (void)context;
    memcpy((void *)(uintptr_t)destination, source, (size_t)length);
    return 0;
}

static int test_get_mode(void *context, display_mode_t *mode) {
    test_display_t *display = context;
    *mode = display->mode;
    return 0;
}

static uint32_t test_get_modes(void *context, display_mode_t *modes,
                               uint32_t capacity) {
    test_display_t *display = context;
    uint32_t count = display->mode_count < capacity ?
        display->mode_count : capacity;

    for (uint32_t index = 0; modes && index < count; ++index)
        modes[index] = display->modes[index];
    return display->mode_count;
}

static uint32_t test_get_edid(void *context, uint8_t *edid,
                              uint32_t capacity) {
    test_display_t *display = context;
    uint32_t count = capacity < sizeof(display->edid) ?
        capacity : sizeof(display->edid);

    if (edid && count)
        memcpy(edid, display->edid, count);
    return sizeof(display->edid);
}

static int test_set_mode(void *context, const display_mode_t *mode) {
    test_display_t *display = context;
    display->mode = *mode;
    return 0;
}

static int test_poll(void *context) {
    test_display_t *display = context;
    display->polls++;
    return 0;
}

static void test_present(void *context, uint32_t x, uint32_t y,
                         uint32_t width, uint32_t height) {
    (void)context;
    assert(x < 640u && y < 480u);
    assert(width > 0u && height > 0u);
}

static int64_t test_ioctl(uint64_t client, uint32_t command, void *argument) {
    kernel_ioctl_request_t request = {
        .descriptor = 7,
        .command = command,
        .argument = (uint64_t)(uintptr_t)argument,
        .copy_context = 0,
        .copy_from_user = test_copy_from,
        .copy_to_user = test_copy_to,
    };
    return edge_drm_ioctl(client, &request);
}

static void test_fill_buffer(uint64_t client,
                             const test_drm_create_dumb_t *buffer,
                             const test_drm_map_dumb_t *mapping,
                             uint32_t pixel) {
    uint32_t pages;
    assert(edge_drm_mmap_prepare(client, mapping->offset,
                                 buffer->size, &pages) == 0);
    assert(pages == buffer->size / 4096u);
    for (uint32_t page = 0; page < pages; ++page) {
        uint32_t *address = 0;
        assert(edge_drm_mmap_page(client, mapping->offset,
                                  page, (void **)&address) == 0);
        for (uint32_t index = 0; index < 4096u / sizeof(uint32_t); ++index)
            address[index] = pixel;
    }
}

int main(void) {
    static const uint64_t client = 0x1234u;
    static const uint64_t importing_client = 0x5678u;
    test_display_t display = {
        .mode = {
            .width = 640u,
            .height = 480u,
            .refresh_millihz = 60000u,
        },
        .modes = {
            {
                .width = 640u,
                .height = 480u,
                .refresh_millihz = 60000u,
            },
            {
                .width = 7680u,
                .height = 4320u,
                .refresh_millihz = 1000000u,
                .flags = DISPLAY_MODE_PREFERRED,
            },
        },
        .mode_count = 2u,
    };
    int owner;
    display_backend_t backend = {
        .name = "unit-display",
        .owner = &owner,
        .context = &display,
        .flags = DISPLAY_BACKEND_DYNAMIC_MODE,
        .operations = {
            .get_mode = test_get_mode,
            .get_modes = test_get_modes,
            .get_edid = test_get_edid,
            .set_mode = test_set_mode,
            .poll = test_poll,
        },
    };
    char name[32] = {0};
    test_drm_version_t version = {
        .name_len = sizeof(name),
        .name = (uint64_t)(uintptr_t)name,
    };
    test_drm_card_res_t resources = {0};
    test_drm_connector_t connector = {
        .connector_id = 1u,
    };
    test_drm_modeinfo_t modes[10];
    test_drm_create_dumb_t first = {
        .height = 480u,
        .width = 640u,
        .bpp = 32u,
    };
    test_drm_create_dumb_t second = first;
    test_drm_create_dumb_t compatibility = {
        .height = 64u,
        .width = 2048u,
        .bpp = 24u,
    };
    test_drm_create_dumb_t cursor_buffer = {
        .height = 16u,
        .width = 16u,
        .bpp = 32u,
    };
    test_drm_map_dumb_t first_map;
    test_drm_map_dumb_t second_map;
    test_drm_map_dumb_t cursor_map;
    test_drm_fb_cmd2_t first_fb = {
        .width = 640u,
        .height = 480u,
        .pixel_format = DRM_FORMAT_XRGB8888,
    };
    test_drm_fb_cmd2_t second_fb = first_fb;
    test_drm_fb_cmd2_t cursor_fb = {
        .width = 16u,
        .height = 16u,
        .pixel_format = DRM_FORMAT_ARGB8888,
    };
    test_drm_fb_cmd2_t cross_imported_fb = first_fb;
    uint32_t connector_id = 1u;
    test_drm_crtc_t crtc = {
        .set_connectors_ptr = (uint64_t)(uintptr_t)&connector_id,
        .count_connectors = 1u,
        .crtc_id = 3u,
        .mode_valid = 1u,
    };
    test_drm_page_flip_t flip;
    test_drm_event_t event;
    test_drm_set_client_cap_t atomic_cap = {
        .capability = DRM_CLIENT_CAP_ATOMIC,
        .value = 1u,
    };
    test_drm_set_client_cap_t universal_planes_cap = {
        .capability = DRM_CLIENT_CAP_UNIVERSAL_PLANES,
        .value = 1u,
    };
    uint32_t plane_ids[2] = {0};
    test_drm_plane_res_t plane_resources = {
        .plane_id_ptr = (uint64_t)(uintptr_t)plane_ids,
        .count_planes = 2u,
    };
    uint32_t cursor_formats[2] = {0};
    test_drm_plane_t cursor_plane = {
        .plane_id = 5u,
        .count_format_types = 2u,
        .format_type_ptr = (uint64_t)(uintptr_t)cursor_formats,
    };
    uint32_t cursor_property_ids[16] = {0};
    uint64_t cursor_property_values[16] = {0};
    test_drm_obj_get_properties_t cursor_properties = {
        .props_ptr = (uint64_t)(uintptr_t)cursor_property_ids,
        .prop_values_ptr =
            (uint64_t)(uintptr_t)cursor_property_values,
        .count_props = 16u,
        .obj_id = 5u,
        .obj_type = DRM_MODE_OBJECT_PLANE,
    };
    uint32_t primary_property_ids[16] = {0};
    uint64_t primary_property_values[16] = {0};
    test_drm_obj_get_properties_t primary_properties = {
        .props_ptr = (uint64_t)(uintptr_t)primary_property_ids,
        .prop_values_ptr =
            (uint64_t)(uintptr_t)primary_property_values,
        .count_props = 16u,
        .obj_id = 4u,
        .obj_type = DRM_MODE_OBJECT_PLANE,
    };
    test_drm_create_blob_t create_blob = {
        .data = (uint64_t)(uintptr_t)&modes[0],
        .length = sizeof(modes[0]),
    };
    test_drm_get_blob_t get_blob;
    uint8_t edid_blob[128];
    test_drm_destroy_blob_t destroy_blob;
    test_drm_obj_set_property_t wrong_type_property = {
        .value = 0u,
        .prop_id = 11u,
        .obj_id = 1u,
        .obj_type = DRM_MODE_OBJECT_CRTC,
    };
    uint32_t legacy_property_ids[4];
    uint64_t legacy_property_values[4];
    test_drm_obj_get_properties_t legacy_connector_properties = {
        .props_ptr = (uint64_t)(uintptr_t)legacy_property_ids,
        .prop_values_ptr =
            (uint64_t)(uintptr_t)legacy_property_values,
        .count_props = 4u,
        .obj_id = 1u,
        .obj_type = 0xc0c0c0c0u,
    };
    test_drm_get_cap_t cursor_width = {
        .capability = DRM_CAP_CURSOR_WIDTH,
    };
    test_drm_get_cap_t cursor_height = {
        .capability = DRM_CAP_CURSOR_HEIGHT,
    };
    test_drm_get_cap_t prime_capability = {
        .capability = DRM_CAP_PRIME,
    };
    const struct {
        uint64_t capability;
        uint64_t value;
    } linux_capabilities[] = {
        { DRM_CAP_DUMB_BUFFER, 1u },
        { DRM_CAP_VBLANK_HIGH_CRTC, 1u },
        { DRM_CAP_DUMB_PREFERRED_DEPTH, 0u },
        { DRM_CAP_DUMB_PREFER_SHADOW, 0u },
        { DRM_CAP_PRIME, 3u },
        { DRM_CAP_TIMESTAMP_MONOTONIC, 1u },
        { DRM_CAP_ASYNC_PAGE_FLIP, 0u },
        { DRM_CAP_CURSOR_WIDTH, 64u },
        { DRM_CAP_CURSOR_HEIGHT, 64u },
        { DRM_CAP_ADDFB2_MODIFIERS, 0u },
        { DRM_CAP_PAGE_FLIP_TARGET, 0u },
        { DRM_CAP_CRTC_IN_VBLANK_EVENT, 1u },
    };
    test_drm_wait_vblank_t wait_vblank;
    test_drm_prime_handle_t prime;
    test_drm_prime_handle_t imported;
    test_drm_prime_handle_t cross_imported;
    test_drm_mode_list_lessees_t lessees = {
        .count_lessees = 4u,
        .pad = 0xffffffffu,
        .lessees_ptr = 1u,
    };
    uint32_t atomic_objects[3] = { 1u, 3u, 4u };
    uint32_t atomic_counts[3] = { 1u, 2u, 10u };
    uint32_t atomic_properties[13] = {
        10u,
        20u, 21u,
        30u, 31u, 32u, 33u, 34u, 35u, 36u, 37u, 38u, 39u,
    };
    uint64_t atomic_values[13] = {
        3u,
        0u, 1u,
        0u, 3u, 0u, 0u,
        (uint64_t)640u << 16, (uint64_t)480u << 16,
        0u, 0u, 640u, 480u,
    };
    test_drm_atomic_t atomic = {
        .count_objs = 3u,
        .objs_ptr = (uint64_t)(uintptr_t)atomic_objects,
        .count_props_ptr = (uint64_t)(uintptr_t)atomic_counts,
        .props_ptr = (uint64_t)(uintptr_t)atomic_properties,
        .prop_values_ptr = (uint64_t)(uintptr_t)atomic_values,
    };

    memset(&fb, 0, sizeof(fb));
    display.edid[0] = 0x00u;
    memset(display.edid + 1u, 0xff, 6u);
    display.edid[7] = 0x00u;
    display.edid[18] = 1u;
    display.edid[19] = 4u;
    display.edid[21] = 60u;
    display.edid[22] = 34u;
    for (uint32_t index = 38u; index < 54u; index += 2u) {
        display.edid[index] = 0x01u;
        display.edid[index + 1u] = 0x01u;
    }
    {
        uint8_t checksum = 0u;
        for (uint32_t index = 0; index < 127u; ++index)
            checksum = (uint8_t)(checksum + display.edid[index]);
        display.edid[127] = (uint8_t)(0u - checksum);
    }
    fb.addr = g_scanout;
    fb.width = 640u;
    fb.height = 480u;
    fb.pitch = 640u * 4u;
    fb.bpp = 32u;
    fb.r_pos = 16u;
    fb.g_pos = 8u;
    fb.b_pos = 0u;
    assert(display_backend_register(&backend) == 0);
    assert(!edge_drm_scanout_refresh_required());
    assert(edge_drm_path_is_card("/dev/dri/card0"));
    assert(!edge_drm_path_is_card("/dev/dri/renderD128"));

    assert(test_ioctl(client, DRM_IOCTL_VERSION, &version) == 0);
    assert(version.version_major == 1);
    assert(strcmp(name, "edgeos-kms") == 0);
    assert(test_ioctl(client, DRM_IOCTL_GET_CAP, &prime_capability) == 0);
    assert(prime_capability.value == 3u);
    for (uint32_t index = 0;
         index < sizeof(linux_capabilities) / sizeof(linux_capabilities[0]);
         ++index) {
        test_drm_get_cap_t capability = {
            .capability = linux_capabilities[index].capability,
        };

        assert(test_ioctl(client, DRM_IOCTL_GET_CAP, &capability) == 0);
        assert(capability.value == linux_capabilities[index].value);
    }
    assert(test_ioctl(client, DRM_IOCTL_SET_MASTER, 0) == 0);
    memset(&wait_vblank, 0, sizeof(wait_vblank));
    wait_vblank.request.type = DRM_VBLANK_RELATIVE;
    wait_vblank.request.sequence = 1u;
    assert(test_ioctl(client, DRM_IOCTL_WAIT_VBLANK, &wait_vblank) == 0);
    assert(wait_vblank.reply.sequence >= 1u);
    memset(&wait_vblank, 0, sizeof(wait_vblank));
    wait_vblank.request.type = DRM_VBLANK_RELATIVE | DRM_VBLANK_EVENT;
    wait_vblank.request.sequence = 1u;
    wait_vblank.request.signal = 0x12345678u;
    assert(test_ioctl(client, DRM_IOCTL_WAIT_VBLANK, &wait_vblank) == 0);
    g_now_us += 20000u;
    edge_drm_pump_deferred();
    assert(edge_drm_read(client, &event, sizeof(event)) ==
           (int64_t)sizeof(event));
    assert(event.type == 1u);
    assert(event.user_data == 0x12345678u);
    assert(test_ioctl(client, DRM_IOCTL_MODE_LIST_LESSEES, &lessees) == 0);
    assert(lessees.count_lessees == 0u);
    assert(lessees.pad == 0u);
    assert(test_ioctl(importing_client, DRM_IOCTL_MODE_LIST_LESSEES,
                      &lessees) == 0);
    assert(lessees.count_lessees == 0u);
    assert(lessees.pad == 0u);
    assert(test_ioctl(client, DRM_IOCTL_MODE_GETRESOURCES, &resources) == 0);
    assert(resources.count_crtcs == 1u);
    assert(resources.count_connectors == 1u);
    assert(resources.count_encoders == 1u);

    connector.count_modes = 10u;
    connector.modes_ptr = (uint64_t)(uintptr_t)modes;
    assert(test_ioctl(client, DRM_IOCTL_MODE_GETCONNECTOR, &connector) == 0);
    assert(connector.connection == 1u);
    assert(connector.count_modes > 1u);
    assert(connector.count_props == 2u);
    assert(connector.mm_width == 600u && connector.mm_height == 340u);
    assert(modes[0].hdisplay == 640u && modes[0].vdisplay == 480u);
    assert(modes[1].hdisplay == 7680u && modes[1].vdisplay == 4320u);
    assert(modes[1].vrefresh == 1000u);
    assert(test_ioctl(client, DRM_IOCTL_MODE_OBJ_GETPROPERTIES,
                      &legacy_connector_properties) == 0);
    assert(legacy_connector_properties.count_props == 2u);
    assert(legacy_property_ids[0] == 12u);
    assert(legacy_property_values[0] == 0u);
    assert(legacy_property_ids[1] == 13u);
    assert(legacy_property_values[1] == 42u);
    memset(&get_blob, 0, sizeof(get_blob));
    get_blob.blob_id = 42u;
    get_blob.length = sizeof(edid_blob);
    get_blob.data = (uint64_t)(uintptr_t)edid_blob;
    assert(test_ioctl(client, DRM_IOCTL_MODE_GETPROPBLOB, &get_blob) == 0);
    assert(get_blob.length == sizeof(edid_blob));
    assert(memcmp(edid_blob, display.edid, sizeof(edid_blob)) == 0);
    assert(test_ioctl(client, DRM_IOCTL_GET_CAP, &cursor_width) == 0);
    assert(test_ioctl(client, DRM_IOCTL_GET_CAP, &cursor_height) == 0);
    assert(cursor_width.value == 64u);
    assert(cursor_height.value == 64u);

    assert(test_ioctl(client, DRM_IOCTL_MODE_CREATE_DUMB, &first) == 0);
    assert(test_ioctl(client, DRM_IOCTL_MODE_CREATE_DUMB, &second) == 0);
    assert(test_ioctl(client, DRM_IOCTL_MODE_CREATE_DUMB,
                      &cursor_buffer) == 0);
    assert(test_ioctl(client, DRM_IOCTL_MODE_CREATE_DUMB,
                      &compatibility) == 0);
    assert(compatibility.pitch >= 2048u * 3u);
    assert((compatibility.pitch & 63u) == 0u);
    assert((compatibility.size & 4095u) == 0u);
    memset(&prime, 0, sizeof(prime));
    prime.handle = first.handle;
    prime.flags = DRM_RDWR | DRM_CLOEXEC;
    assert(test_ioctl(client, DRM_IOCTL_PRIME_HANDLE_TO_FD, &prime) == 0);
    assert(prime.fd == 71);
    memset(&imported, 0, sizeof(imported));
    imported.fd = prime.fd;
    assert(test_ioctl(client, DRM_IOCTL_PRIME_FD_TO_HANDLE, &imported) == 0);
    assert(imported.handle == first.handle);
    memset(&cross_imported, 0, sizeof(cross_imported));
    cross_imported.fd = prime.fd;
    assert(test_ioctl(importing_client, DRM_IOCTL_PRIME_FD_TO_HANDLE,
                      &cross_imported) == 0);
    assert(cross_imported.handle != 0u);
    assert(cross_imported.handle != first.handle);
    first_map.handle = first.handle;
    second_map.handle = second.handle;
    cursor_map.handle = cursor_buffer.handle;
    assert(test_ioctl(client, DRM_IOCTL_MODE_MAP_DUMB, &first_map) == 0);
    assert(test_ioctl(client, DRM_IOCTL_MODE_MAP_DUMB, &second_map) == 0);
    assert(test_ioctl(client, DRM_IOCTL_MODE_MAP_DUMB, &cursor_map) == 0);
    test_fill_buffer(client, &first, &first_map, 0x00112233u);
    test_fill_buffer(client, &second, &second_map, 0x00445566u);
    test_fill_buffer(client, &cursor_buffer, &cursor_map, 0xffff0000u);

    first_fb.handles[0] = first.handle;
    first_fb.pitches[0] = first.pitch;
    second_fb.handles[0] = second.handle;
    second_fb.pitches[0] = second.pitch;
    cursor_fb.handles[0] = cursor_buffer.handle;
    cursor_fb.pitches[0] = cursor_buffer.pitch;
    cross_imported_fb.handles[0] = cross_imported.handle;
    cross_imported_fb.pitches[0] = first.pitch;
    assert(test_ioctl(client, DRM_IOCTL_MODE_ADDFB2, &first_fb) == 0);
    assert(test_ioctl(client, DRM_IOCTL_MODE_ADDFB2, &second_fb) == 0);
    assert(test_ioctl(client, DRM_IOCTL_MODE_ADDFB2, &cursor_fb) == 0);
    assert(test_ioctl(importing_client, DRM_IOCTL_MODE_ADDFB2,
                      &cross_imported_fb) == 0);
    crtc.fb_id = cross_imported_fb.fb_id;
    crtc.mode = modes[0];
    assert(test_ioctl(client, DRM_IOCTL_MODE_SETCRTC, &crtc) == 0);
    assert(edge_drm_scanout_refresh_required());
    assert(g_scanout[0] == 0x33u && g_scanout[1] == 0x22u &&
           g_scanout[2] == 0x11u);
    assert(kernel_fd_close(prime.fd) == 0);
    assert(g_console_drm_owned);
    assert(g_scanout[0] == 0x33u && g_scanout[1] == 0x22u &&
           g_scanout[2] == 0x11u);
    assert(g_flushes == 1u);

    memset(&flip, 0, sizeof(flip));
    flip.crtc_id = 3u;
    flip.fb_id = second_fb.fb_id;
    flip.flags = DRM_MODE_PAGE_FLIP_EVENT;
    flip.user_data = 0xabcdefu;
    /*
     * Model a software scanout copy that consumes more than one refresh
     * interval. Completion must be anchored to submission time so the copy
     * cost does not get followed by another complete vblank interval.
     */
    g_flush_advance_us = 20000u;
    assert(test_ioctl(client, DRM_IOCTL_MODE_PAGE_FLIP, &flip) == 0);
    assert(g_scanout[0] == 0x66u && g_scanout[1] == 0x55u &&
           g_scanout[2] == 0x44u);
    {
        uint32_t polls_before_readable = display.polls;

        assert(edge_drm_poll_readable(client));
        assert(edge_drm_read(client, &event, sizeof(event)) ==
               (int64_t)sizeof(event));
        assert(event.type == 2u && event.length == sizeof(event));
        assert(event.user_data == flip.user_data);
        assert(event.crtc_id == 3u);
        assert(!edge_drm_poll_readable(client));
        assert(display.polls == polls_before_readable);
    }
    edge_drm_release_client(importing_client);
    {
        uint32_t *mapped = 0;
        uint32_t flushes_after_prime;
        assert(edge_drm_mmap_page(client, second_map.offset,
                                  0u, (void **)&mapped) == 0);
        g_now_us += 20000u;
        edge_drm_pump_deferred();
        flushes_after_prime = g_flushes;
        g_now_us += 20000u;
        edge_drm_pump_deferred();
        assert(g_flushes == flushes_after_prime);
        for (uint32_t idle = 0; idle < 6u; ++idle) {
            g_now_us += 20000u;
            edge_drm_pump_deferred();
        }
        mapped[0] = 0x00778899u;
        g_now_us += 20000u;
        edge_drm_pump_deferred();
        assert(g_scanout[0] != 0x99u);
        edge_drm_scanout_activity();
        edge_drm_pump_deferred();
        assert(g_scanout[0] == 0x99u && g_scanout[1] == 0x88u &&
               g_scanout[2] == 0x77u);
        assert(g_flushes == flushes_after_prime + 1u);
        mapped[0] = 0xff778899u;
        edge_drm_scanout_activity();
        edge_drm_pump_deferred();
        assert(g_flushes == flushes_after_prime + 1u);
        {
            test_drm_page_flip_t equal_flip = {
                .crtc_id = 3u,
                .fb_id = first_fb.fb_id,
            };
            uint32_t *first_mapped = 0;
            uint32_t flushes_before_equal_flip;
            uint32_t flushes_after_equal_flip;

            test_fill_buffer(client, &first, &first_map, 0x00445566u);
            assert(edge_drm_mmap_page(
                       client, first_map.offset, 0u,
                       (void **)&first_mapped) == 0);
            first_mapped[0] = 0x00778899u;
            flushes_before_equal_flip = g_flushes;
            assert(test_ioctl(
                       client, DRM_IOCTL_MODE_PAGE_FLIP, &equal_flip) == 0);
            flushes_after_equal_flip = g_flushes;
            assert(flushes_after_equal_flip == flushes_before_equal_flip);
            edge_drm_scanout_activity();
            edge_drm_pump_deferred();
            assert(g_flushes == flushes_after_equal_flip);
            assert(!edge_drm_mmap_write_tracking_required(
                        client, first_map.offset));
            assert(edge_drm_mmap_enable_write_tracking(
                       client, first_map.offset) == 0);
            first_mapped[0] = 0x00010203u;
            assert(edge_drm_note_mmap_dirty_physical(
                       (uint64_t)(uintptr_t)first_mapped, 4096u));
            g_now_us += 16667u;
            edge_drm_pump_deferred();
            assert(g_scanout[0] == 0x03u && g_scanout[1] == 0x02u &&
                   g_scanout[2] == 0x01u);
            assert(g_writeprotect_calls > 0u);
        }
    }

    assert(test_ioctl(client, DRM_IOCTL_SET_CLIENT_CAP,
                      &universal_planes_cap) == 0);
    assert(test_ioctl(client, DRM_IOCTL_SET_CLIENT_CAP, &atomic_cap) == 0);
    display_backend_unregister(&owner);
    backend.flags |= DISPLAY_BACKEND_EXPLICIT_PRESENT;
    backend.operations.present_rect = test_present;
    assert(display_backend_register(&backend) == 0);
    assert(test_ioctl(client, DRM_IOCTL_MODE_GETPLANERESOURCES,
                      &plane_resources) == 0);
    assert(plane_resources.count_planes == 2u);
    assert(plane_ids[0] == 4u && plane_ids[1] == 5u);
    assert(test_ioctl(client, DRM_IOCTL_MODE_GETPLANE,
                      &cursor_plane) == 0);
    assert(cursor_plane.possible_crtcs == 1u);
    assert(cursor_plane.count_format_types == 1u);
    assert(cursor_formats[0] == DRM_FORMAT_ARGB8888);
    assert(test_ioctl(client, DRM_IOCTL_MODE_OBJ_GETPROPERTIES,
                      &cursor_properties) == 0);
    assert(cursor_properties.count_props == 12u);
    {
        int found_cursor_type = 0;
        for (uint32_t index = 0;
             index < cursor_properties.count_props; ++index) {
            if (cursor_property_ids[index] == 42u &&
                cursor_property_values[index] == 2u)
                found_cursor_type = 1;
        }
        assert(found_cursor_type);
    }
    assert(test_ioctl(client, DRM_IOCTL_MODE_OBJ_GETPROPERTIES,
                      &primary_properties) == 0);
    assert(primary_properties.count_props == 13u);
    {
        int found_damage_clips = 0;
        for (uint32_t index = 0;
             index < primary_properties.count_props; ++index) {
            if (primary_property_ids[index] == 44u &&
                primary_property_values[index] == 0u)
                found_damage_clips = 1;
        }
        assert(found_damage_clips);
    }
    assert(test_ioctl(client, DRM_IOCTL_MODE_OBJ_SETPROPERTY,
                      &wrong_type_property) == -2);
    assert(test_ioctl(client, DRM_IOCTL_MODE_CREATEPROPBLOB,
                      &create_blob) == 0);
    atomic_values[1] = create_blob.blob_id;
    atomic_values[3] = second_fb.fb_id;
    atomic.flags = DRM_MODE_ATOMIC_TEST_ONLY;
    assert(test_ioctl(client, DRM_IOCTL_MODE_ATOMIC, &atomic) == -22);
    atomic.flags =
        DRM_MODE_ATOMIC_TEST_ONLY | DRM_MODE_ATOMIC_ALLOW_MODESET;
    assert(test_ioctl(client, DRM_IOCTL_MODE_ATOMIC, &atomic) == 0);
    atomic.flags =
        DRM_MODE_ATOMIC_ALLOW_MODESET | DRM_MODE_PAGE_FLIP_EVENT;
    atomic.user_data = 0x12345678u;
    assert(test_ioctl(client, DRM_IOCTL_MODE_ATOMIC, &atomic) == 0);
    assert(!edge_drm_poll_readable(client));
    g_now_us += 20000u;
    edge_drm_pump_deferred();
    assert(edge_drm_read(client, &event, sizeof(event)) ==
           (int64_t)sizeof(event));
    assert(event.user_data == atomic.user_data);

    {
        uint32_t cursor_object = 5u;
        uint32_t cursor_count = 10u;
        uint32_t cursor_properties_to_set[10] = {
            30u, 31u, 32u, 33u, 34u,
            35u, 36u, 37u, 38u, 39u,
        };
        uint64_t cursor_values_to_set[10] = {
            cursor_fb.fb_id, 3u, 0u, 0u,
            (uint64_t)16u << 16, (uint64_t)16u << 16,
            10u, 10u, 16u, 16u,
        };
        test_drm_atomic_t cursor_enable = {
            .count_objs = 1u,
            .objs_ptr = (uint64_t)(uintptr_t)&cursor_object,
            .count_props_ptr = (uint64_t)(uintptr_t)&cursor_count,
            .props_ptr =
                (uint64_t)(uintptr_t)cursor_properties_to_set,
            .prop_values_ptr =
                (uint64_t)(uintptr_t)cursor_values_to_set,
        };
        uint32_t move_count = 2u;
        uint32_t move_properties[2] = { 36u, 37u };
        uint64_t move_values[2] = { 100u, 100u };
        test_drm_atomic_t cursor_move = {
            .count_objs = 1u,
            .objs_ptr = (uint64_t)(uintptr_t)&cursor_object,
            .count_props_ptr = (uint64_t)(uintptr_t)&move_count,
            .props_ptr = (uint64_t)(uintptr_t)move_properties,
            .prop_values_ptr = (uint64_t)(uintptr_t)move_values,
        };
        uint32_t disable_count = 2u;
        uint32_t disable_properties[2] = { 30u, 31u };
        uint64_t disable_values[2] = { 0u, 0u };
        test_drm_atomic_t cursor_disable = {
            .count_objs = 1u,
            .objs_ptr = (uint64_t)(uintptr_t)&cursor_object,
            .count_props_ptr = (uint64_t)(uintptr_t)&disable_count,
            .props_ptr = (uint64_t)(uintptr_t)disable_properties,
            .prop_values_ptr = (uint64_t)(uintptr_t)disable_values,
        };
        uint32_t old_offset = (10u * 640u + 10u) * 4u;
        uint32_t new_offset = (100u * 640u + 100u) * 4u;
        uint32_t flushes_before_cursor;

        flushes_before_cursor = g_flushes;
        assert(test_ioctl(client, DRM_IOCTL_MODE_ATOMIC,
                          &cursor_enable) == 0);
        assert(g_flushes == flushes_before_cursor + 1u);
        assert(g_last_flush_rect_count == 1u);
        assert(g_scanout[old_offset + 2u] == 0xffu);

        {
            uint32_t pixel = 11u * 640u + 11u;
            uint32_t page = pixel / (4096u / sizeof(uint32_t));
            uint32_t index = pixel % (4096u / sizeof(uint32_t));
            uint32_t *mapped_page = 0;

            assert(edge_drm_mmap_page(
                       client, second_map.offset, page,
                       (void **)&mapped_page) == 0);
            mapped_page[index] = 0x00010203u;
            g_now_us += 20000u;
            edge_drm_scanout_activity();
            flushes_before_cursor = g_flushes;
            edge_drm_pump_deferred();
            assert(g_flushes == flushes_before_cursor + 1u);
            assert(g_last_flush_rect_count == 2u);
            assert(g_scanout[old_offset + 2u] == 0xffu);
        }

        flushes_before_cursor = g_flushes;
        assert(test_ioctl(client, DRM_IOCTL_MODE_ATOMIC,
                          &cursor_move) == 0);
        assert(g_flushes == flushes_before_cursor + 1u);
        assert(g_last_flush_rect_count == 2u);
        assert(g_scanout[old_offset] == 0x66u);
        assert(g_scanout[old_offset + 1u] == 0x55u);
        assert(g_scanout[old_offset + 2u] == 0x44u);
        assert(g_scanout[new_offset + 2u] == 0xffu);

        flushes_before_cursor = g_flushes;
        assert(test_ioctl(client, DRM_IOCTL_MODE_ATOMIC,
                          &cursor_disable) == 0);
        assert(g_flushes == flushes_before_cursor + 1u);
        assert(g_last_flush_rect_count == 1u);
        assert(g_scanout[new_offset] == 0x66u);
        assert(g_scanout[new_offset + 1u] == 0x55u);
        assert(g_scanout[new_offset + 2u] == 0x44u);
    }

    {
        uint32_t primary_object = 4u;
        uint32_t primary_count = 1u;
        uint32_t primary_property = 30u;
        uint64_t primary_value = second_fb.fb_id;
        test_drm_atomic_t primary_recommit = {
            .count_objs = 1u,
            .objs_ptr = (uint64_t)(uintptr_t)&primary_object,
            .count_props_ptr = (uint64_t)(uintptr_t)&primary_count,
            .props_ptr = (uint64_t)(uintptr_t)&primary_property,
            .prop_values_ptr = (uint64_t)(uintptr_t)&primary_value,
        };
        uint32_t *mapped = 0;
        uint32_t flushes_before_recommit;

        assert(edge_drm_mmap_page(client, second_map.offset,
                                  0u, (void **)&mapped) == 0);
        mapped[0] = 0x00090807u;
        flushes_before_recommit = g_flushes;
        assert(test_ioctl(client, DRM_IOCTL_MODE_ATOMIC,
                          &primary_recommit) == 0);
        assert(g_flushes == flushes_before_recommit + 1u);
        assert(g_scanout[0] == 0x07u && g_scanout[1] == 0x08u &&
               g_scanout[2] == 0x09u);
        flushes_before_recommit = g_flushes;
        assert(test_ioctl(client, DRM_IOCTL_MODE_ATOMIC,
                          &primary_recommit) == 0);
        assert(g_flushes == flushes_before_recommit);
    }

    {
        test_drm_mode_rect_t damage = {
            .x1 = 10,
            .y1 = 0,
            .x2 = 11,
            .y2 = 1,
        };
        test_drm_create_blob_t damage_blob = {
            .data = (uint64_t)(uintptr_t)&damage,
            .length = sizeof(damage),
        };
        uint32_t damage_object = 4u;
        uint32_t damage_count = 1u;
        uint32_t damage_property = 44u;
        uint64_t damage_value;
        test_drm_atomic_t damage_atomic = {
            .count_objs = 1u,
            .objs_ptr = (uint64_t)(uintptr_t)&damage_object,
            .count_props_ptr = (uint64_t)(uintptr_t)&damage_count,
            .props_ptr = (uint64_t)(uintptr_t)&damage_property,
            .prop_values_ptr = (uint64_t)(uintptr_t)&damage_value,
        };
        uint32_t *mapped = 0;
        uint32_t flushes_before_damage;

        assert(edge_drm_mmap_page(client, second_map.offset,
                                  0u, (void **)&mapped) == 0);
        mapped[10] = 0x00010203u;
        mapped[20] = 0x00040506u;
        assert(test_ioctl(client, DRM_IOCTL_MODE_CREATEPROPBLOB,
                          &damage_blob) == 0);
        damage_value = damage_blob.blob_id;
        flushes_before_damage = g_flushes;
        assert(test_ioctl(client, DRM_IOCTL_MODE_ATOMIC,
                          &damage_atomic) == 0);
        assert(g_flushes == flushes_before_damage + 1u);
        assert(g_scanout[10u * 4u] == 0x03u);
        assert(g_scanout[20u * 4u] != 0x06u);
        {
            uint32_t primary_object = 4u;
            uint32_t primary_count = 1u;
            uint32_t primary_property = 30u;
            uint64_t primary_value = second_fb.fb_id;
            test_drm_atomic_t primary_recommit = {
                .count_objs = 1u,
                .objs_ptr = (uint64_t)(uintptr_t)&primary_object,
                .count_props_ptr = (uint64_t)(uintptr_t)&primary_count,
                .props_ptr = (uint64_t)(uintptr_t)&primary_property,
                .prop_values_ptr = (uint64_t)(uintptr_t)&primary_value,
            };

            mapped[20] = 0x00040506u;
            flushes_before_damage = g_flushes;
            assert(test_ioctl(client, DRM_IOCTL_MODE_ATOMIC,
                              &primary_recommit) == 0);
            assert(g_flushes == flushes_before_damage + 1u);
        assert(g_scanout[20u * 4u] == 0x06u);
        }
        {
            uint32_t flushes_before_poll;

            assert(!edge_drm_poll_readable(client));
            mapped[30] = 0x00070809u;
            flushes_before_poll = g_flushes;
            /* Readiness probes must not bypass the 60 Hz scanout cadence. */
            assert(!edge_drm_poll_readable(client));
            assert(g_flushes == flushes_before_poll);
            g_now_us += 120000u;
            assert(!edge_drm_poll_readable(client));
            assert(g_flushes == flushes_before_poll);
            edge_drm_pump_deferred();
            assert(g_flushes == flushes_before_poll + 1u);
            assert(g_scanout[30u * 4u] == 0x09u);
        }
        destroy_blob.blob_id = damage_blob.blob_id;
        assert(test_ioctl(client, DRM_IOCTL_MODE_DESTROYPROPBLOB,
                          &destroy_blob) == 0);
    }

    {
        test_drm_mode_rect_t damage[2] = {
            { .x1 = 12, .y1 = 0, .x2 = 13, .y2 = 1 },
            { .x1 = 24, .y1 = 0, .x2 = 25, .y2 = 1 },
        };
        test_drm_create_blob_t damage_blob = {
            .data = (uint64_t)(uintptr_t)damage,
            .length = sizeof(damage),
        };
        uint32_t damage_object = 4u;
        uint32_t damage_count = 1u;
        uint32_t damage_property = 44u;
        uint64_t damage_value;
        test_drm_atomic_t damage_atomic = {
            .count_objs = 1u,
            .objs_ptr = (uint64_t)(uintptr_t)&damage_object,
            .count_props_ptr = (uint64_t)(uintptr_t)&damage_count,
            .props_ptr = (uint64_t)(uintptr_t)&damage_property,
            .prop_values_ptr = (uint64_t)(uintptr_t)&damage_value,
        };
        uint32_t *mapped = 0;
        uint32_t flushes_before_damage;

        assert(edge_drm_mmap_page(client, second_map.offset,
                                  0u, (void **)&mapped) == 0);
        mapped[12] = 0x00112233u;
        mapped[24] = 0x00445566u;
        assert(test_ioctl(client, DRM_IOCTL_MODE_CREATEPROPBLOB,
                          &damage_blob) == 0);
        damage_value = damage_blob.blob_id;
        flushes_before_damage = g_flushes;
        assert(test_ioctl(client, DRM_IOCTL_MODE_ATOMIC,
                          &damage_atomic) == 0);
        assert(g_flushes == flushes_before_damage + 1u);
        assert(g_scanout[12u * 4u] == 0x33u);
        assert(g_scanout[24u * 4u] == 0x66u);
        destroy_blob.blob_id = damage_blob.blob_id;
        assert(test_ioctl(client, DRM_IOCTL_MODE_DESTROYPROPBLOB,
                          &destroy_blob) == 0);
    }

    {
        test_drm_mode_rect_t damage[5] = {
            { .x1 = 1, .y1 = 1, .x2 = 2, .y2 = 2 },
            { .x1 = 3, .y1 = 1, .x2 = 4, .y2 = 2 },
            { .x1 = 5, .y1 = 1, .x2 = 6, .y2 = 2 },
            { .x1 = 7, .y1 = 1, .x2 = 8, .y2 = 2 },
            { .x1 = 9, .y1 = 1, .x2 = 10, .y2 = 2 },
        };
        test_drm_create_blob_t damage_blob = {
            .data = (uint64_t)(uintptr_t)damage,
            .length = sizeof(damage),
        };
        uint32_t damage_object = 4u;
        uint32_t damage_count = 1u;
        uint32_t damage_property = 44u;
        uint64_t damage_value;
        test_drm_atomic_t damage_atomic = {
            .count_objs = 1u,
            .objs_ptr = (uint64_t)(uintptr_t)&damage_object,
            .count_props_ptr = (uint64_t)(uintptr_t)&damage_count,
            .props_ptr = (uint64_t)(uintptr_t)&damage_property,
            .prop_values_ptr = (uint64_t)(uintptr_t)&damage_value,
        };
        uint32_t flushes_before_damage;

        assert(test_ioctl(client, DRM_IOCTL_MODE_CREATEPROPBLOB,
                          &damage_blob) == 0);
        damage_value = damage_blob.blob_id;
        flushes_before_damage = g_flushes;
        assert(test_ioctl(client, DRM_IOCTL_MODE_ATOMIC,
                          &damage_atomic) == 0);
        assert(g_flushes == flushes_before_damage + 1u);
        destroy_blob.blob_id = damage_blob.blob_id;
        assert(test_ioctl(client, DRM_IOCTL_MODE_DESTROYPROPBLOB,
                          &destroy_blob) == 0);
    }

    destroy_blob.blob_id = create_blob.blob_id;
    assert(test_ioctl(client, DRM_IOCTL_MODE_DESTROYPROPBLOB,
                      &destroy_blob) == 0);
    memset(&get_blob, 0, sizeof(get_blob));
    memset(&crtc.mode, 0, sizeof(crtc.mode));
    get_blob.blob_id = create_blob.blob_id;
    get_blob.length = sizeof(crtc.mode);
    get_blob.data = (uint64_t)(uintptr_t)&crtc.mode;
    assert(test_ioctl(client, DRM_IOCTL_MODE_GETPROPBLOB, &get_blob) == 0);
    assert(get_blob.length == sizeof(crtc.mode));
    assert(crtc.mode.hdisplay == 640u && crtc.mode.vdisplay == 480u);

    edge_drm_release_client(client);
    assert(!edge_drm_scanout_refresh_required());
    assert(!g_console_drm_owned);
    display_backend_unregister(&owner);
    puts("drm_runtime_unit: PASS");
    return 0;
}
