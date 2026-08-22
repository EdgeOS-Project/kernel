/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Architecture-independent Linux DRM/KMS dumb-buffer implementation.
 *
 * The userspace layouts and ioctl numbers below follow the MIT-licensed Linux
 * DRM UAPI. No Linux kernel implementation code is used here.
 */

#include <stddef.h>
#include <stdint.h>

#include "display.h"
#include "fb.h"
#include "fb_console.h"
#include "kernel/anonymous_fd.h"
#include "kernel/deferred_work.h"
#include "kernel/drm_runtime.h"
#include "kernel/fd_runtime.h"
#include "kernel/linux_errno.h"
#include "kernel/virtgpu_runtime.h"
#include "mm/arch_vm.h"
#include "string.h"
#include "sys/boottime.h"

#define EDGE_DRM_IOCTL_VERSION               0xc0406400u
#define EDGE_DRM_IOCTL_GET_UNIQUE            0xc0106401u
#define EDGE_DRM_IOCTL_GET_MAGIC             0x80046402u
#define EDGE_DRM_IOCTL_GEM_CLOSE             0x40086409u
#define EDGE_DRM_IOCTL_AUTH_MAGIC            0x40046411u
#define EDGE_DRM_IOCTL_GET_CAP               0xc010640cu
#define EDGE_DRM_IOCTL_SET_CLIENT_CAP        0x4010640du
#define EDGE_DRM_IOCTL_PRIME_HANDLE_TO_FD    0xc00c642du
#define EDGE_DRM_IOCTL_PRIME_FD_TO_HANDLE    0xc00c642eu
#define EDGE_DRM_IOCTL_SET_MASTER            0x0000641eu
#define EDGE_DRM_IOCTL_DROP_MASTER           0x0000641fu
#define EDGE_DRM_IOCTL_MODE_GETRESOURCES     0xc04064a0u
#define EDGE_DRM_IOCTL_MODE_GETCRTC          0xc06864a1u
#define EDGE_DRM_IOCTL_MODE_SETCRTC          0xc06864a2u
#define EDGE_DRM_IOCTL_MODE_GETENCODER       0xc01464a6u
#define EDGE_DRM_IOCTL_MODE_GETCONNECTOR     0xc05064a7u
#define EDGE_DRM_IOCTL_MODE_GETPROPERTY      0xc04064aau
#define EDGE_DRM_IOCTL_MODE_SETPROPERTY      0xc01064abu
#define EDGE_DRM_IOCTL_MODE_GETPROPBLOB      0xc01064acu
#define EDGE_DRM_IOCTL_MODE_GETFB            0xc01c64adu
#define EDGE_DRM_IOCTL_MODE_ADDFB            0xc01c64aeu
#define EDGE_DRM_IOCTL_MODE_RMFB             0xc00464afu
#define EDGE_DRM_IOCTL_MODE_PAGE_FLIP        0xc01864b0u
#define EDGE_DRM_IOCTL_MODE_DIRTYFB          0xc01864b1u
#define EDGE_DRM_IOCTL_MODE_CREATE_DUMB      0xc02064b2u
#define EDGE_DRM_IOCTL_MODE_MAP_DUMB         0xc01064b3u
#define EDGE_DRM_IOCTL_MODE_DESTROY_DUMB     0xc00464b4u
#define EDGE_DRM_IOCTL_MODE_GETPLANERESOURCES 0xc01064b5u
#define EDGE_DRM_IOCTL_MODE_GETPLANE         0xc02064b6u
#define EDGE_DRM_IOCTL_MODE_SETPLANE         0xc03064b7u
#define EDGE_DRM_IOCTL_MODE_ADDFB2           0xc06864b8u
#define EDGE_DRM_IOCTL_MODE_OBJ_GETPROPERTIES 0xc02064b9u
#define EDGE_DRM_IOCTL_MODE_OBJ_SETPROPERTY  0xc01864bau
#define EDGE_DRM_IOCTL_MODE_ATOMIC           0xc03864bcu
#define EDGE_DRM_IOCTL_MODE_CREATEPROPBLOB   0xc01064bdu
#define EDGE_DRM_IOCTL_MODE_DESTROYPROPBLOB  0xc00464beu
#define EDGE_DRM_IOCTL_MODE_LIST_LESSEES     0xc01064c7u
#define EDGE_DRM_IOCTL_MODE_CLOSEFB          0xc00864d0u

#define EDGE_DRM_CLIENT_CAP_STEREO_3D        1u
#define EDGE_DRM_CLIENT_CAP_UNIVERSAL_PLANES 2u
#define EDGE_DRM_CLIENT_CAP_ATOMIC           3u
#define EDGE_DRM_CLIENT_CAP_ASPECT_RATIO     4u

#define EDGE_DRM_MODE_CONNECTED              1u
#define EDGE_DRM_MODE_ENCODER_VIRTUAL        5u
#define EDGE_DRM_MODE_CONNECTOR_VIRTUAL      15u
#define EDGE_DRM_MODE_SUBPIXEL_UNKNOWN       0u
#define EDGE_DRM_MODE_TYPE_PREFERRED         (1u << 3)
#define EDGE_DRM_MODE_TYPE_DRIVER            (1u << 6)
#define EDGE_DRM_MODE_PAGE_FLIP_EVENT        0x01u
#define EDGE_DRM_MODE_PAGE_FLIP_ASYNC        0x02u
#define EDGE_DRM_MODE_ATOMIC_TEST_ONLY       0x0100u
#define EDGE_DRM_MODE_ATOMIC_NONBLOCK        0x0200u
#define EDGE_DRM_MODE_ATOMIC_ALLOW_MODESET   0x0400u
#define EDGE_DRM_MODE_ATOMIC_FLAGS           0x0703u
#define EDGE_DRM_EVENT_FLIP_COMPLETE         0x02u
#define EDGE_DRM_PRIME_RDWR                  0x00000002u
#define EDGE_DRM_PRIME_CLOEXEC               0x00080000u
#define EDGE_DRM_PRIME_FLAGS                 \
    (EDGE_DRM_PRIME_RDWR | EDGE_DRM_PRIME_CLOEXEC)

#define EDGE_DRM_MODE_PROP_RANGE             (1u << 1)
#define EDGE_DRM_MODE_PROP_IMMUTABLE         (1u << 2)
#define EDGE_DRM_MODE_PROP_ENUM              (1u << 3)
#define EDGE_DRM_MODE_PROP_BLOB              (1u << 4)
#define EDGE_DRM_MODE_PROP_OBJECT            (1u << 6)
#define EDGE_DRM_MODE_PROP_SIGNED_RANGE      (2u << 6)
#define EDGE_DRM_MODE_PROP_ATOMIC            0x80000000u

#define EDGE_DRM_MODE_OBJECT_CRTC            0xccccccccu
#define EDGE_DRM_MODE_OBJECT_CONNECTOR       0xc0c0c0c0u
#define EDGE_DRM_MODE_OBJECT_FB              0xfbfbfbfbu
#define EDGE_DRM_MODE_OBJECT_PLANE           0xeeeeeeeeu

#define EDGE_DRM_FORMAT_XRGB8888             0x34325258u
#define EDGE_DRM_FORMAT_ARGB8888             0x34325241u

#define EDGE_DRM_CONNECTOR_ID 1u
#define EDGE_DRM_ENCODER_ID   2u
#define EDGE_DRM_CRTC_ID      3u
#define EDGE_DRM_PRIMARY_PLANE_ID 4u
#define EDGE_DRM_CURSOR_PLANE_ID  5u
#define EDGE_DRM_PLANE_ID          EDGE_DRM_PRIMARY_PLANE_ID
#define EDGE_DRM_FB_ID_BASE   100u
#define EDGE_DRM_CURRENT_MODE_BLOB_ID 40u
#define EDGE_DRM_IN_FORMATS_BLOB_ID   41u
#define EDGE_DRM_EDID_BLOB_ID         42u
#define EDGE_DRM_SCANOUT_DEFAULT_INTERVAL_US 16667ull
#define EDGE_DRM_SCANOUT_IDLE_INTERVAL_US   250000ull
#define EDGE_DRM_SCANOUT_IDLE_THRESHOLD     6u
#define EDGE_DRM_EXPLICIT_VERIFY_INTERVAL_US 33333ull
#define EDGE_DRM_SCANOUT_TILE_WIDTH   64u
#define EDGE_DRM_SCANOUT_TILE_HEIGHT  64u
#define EDGE_DRM_SCANOUT_TILE_COLUMNS \
    ((EDGE_DRM_MAX_WIDTH + EDGE_DRM_SCANOUT_TILE_WIDTH - 1u) / \
     EDGE_DRM_SCANOUT_TILE_WIDTH)
#define EDGE_DRM_SCANOUT_TILE_ROWS \
    ((EDGE_DRM_MAX_HEIGHT + EDGE_DRM_SCANOUT_TILE_HEIGHT - 1u) / \
     EDGE_DRM_SCANOUT_TILE_HEIGHT)
#define EDGE_DRM_SCANOUT_TILE_COUNT \
    (EDGE_DRM_SCANOUT_TILE_COLUMNS * EDGE_DRM_SCANOUT_TILE_ROWS)
#define EDGE_DRM_CURSOR_MAX_WIDTH  64u
#define EDGE_DRM_CURSOR_MAX_HEIGHT 64u

#define EDGE_DRM_PROP_CONNECTOR_CRTC_ID 10u
#define EDGE_DRM_PROP_LINK_STATUS       11u
#define EDGE_DRM_PROP_NON_DESKTOP       12u
#define EDGE_DRM_PROP_EDID              13u
#define EDGE_DRM_PROP_CRTC_MODE_ID      20u
#define EDGE_DRM_PROP_CRTC_ACTIVE       21u
#define EDGE_DRM_PROP_PLANE_FB_ID       30u
#define EDGE_DRM_PROP_PLANE_CRTC_ID     31u
#define EDGE_DRM_PROP_PLANE_SRC_X       32u
#define EDGE_DRM_PROP_PLANE_SRC_Y       33u
#define EDGE_DRM_PROP_PLANE_SRC_W       34u
#define EDGE_DRM_PROP_PLANE_SRC_H       35u
#define EDGE_DRM_PROP_PLANE_CRTC_X      36u
#define EDGE_DRM_PROP_PLANE_CRTC_Y      37u
#define EDGE_DRM_PROP_PLANE_CRTC_W      38u
#define EDGE_DRM_PROP_PLANE_CRTC_H      39u
#define EDGE_DRM_PROP_PLANE_TYPE        42u
#define EDGE_DRM_PROP_PLANE_IN_FORMATS  43u
#define EDGE_DRM_PROP_PLANE_FB_DAMAGE_CLIPS 44u

#define EDGE_DRM_MAX_WIDTH  7680u
#define EDGE_DRM_MAX_HEIGHT 4320u
#define EDGE_DRM_MAX_BUFFER_DIMENSION 8192u
#define EDGE_DRM_BUFFER_COUNT 64u
#define EDGE_DRM_FRAMEBUFFER_COUNT 128u
#define EDGE_DRM_CLIENT_COUNT 64u
#define EDGE_DRM_EVENT_COUNT 32u
#define EDGE_DRM_MODE_COUNT 32u
#define EDGE_DRM_BLOB_COUNT 16u
#define EDGE_DRM_BLOB_CAPACITY DISPLAY_MODE_EDID_MAX_BYTES
#define EDGE_DRM_BLOB_ID_BASE 1000u
#define EDGE_DRM_DAMAGE_RECT_LIMIT 8u
#define EDGE_DRM_SCANOUT_BATCH_RECTS 8u
#define EDGE_DRM_PRIME_OBJECT_BASE 0x4000u
#define EDGE_DRM_ATOMIC_OBJECT_COUNT 8u
#define EDGE_DRM_ATOMIC_PROPERTY_COUNT 64u
#define EDGE_DRM_PAGE_SIZE 4096u
#define EDGE_DRM_PITCH_ALIGN 64u
#define EDGE_DRM_BUFFER_CAPACITY (128u * 1024u * 1024u)
#define EDGE_DRM_MAX_BUFFER_PAGES \
    (EDGE_DRM_BUFFER_CAPACITY / EDGE_DRM_PAGE_SIZE)
#define EDGE_DRM_DIRTY_PAGE_WORDS \
    ((EDGE_DRM_MAX_BUFFER_PAGES + 31u) / 32u)

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
} edge_drm_version_t;

typedef struct {
    uint64_t unique_len;
    uint64_t unique;
} edge_drm_unique_t;

typedef struct {
    uint64_t capability;
    uint64_t value;
} edge_drm_get_cap_t;

typedef struct {
    uint64_t capability;
    uint64_t value;
} edge_drm_set_client_cap_t;

typedef struct {
    uint32_t handle;
    uint32_t pad;
} edge_drm_gem_close_t;

typedef struct {
    uint32_t handle;
    uint32_t flags;
    int32_t fd;
} edge_drm_prime_handle_t;

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
} edge_drm_modeinfo_t;

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
} edge_drm_card_res_t;

typedef struct {
    uint64_t set_connectors_ptr;
    uint32_t count_connectors;
    uint32_t crtc_id;
    uint32_t fb_id;
    uint32_t x;
    uint32_t y;
    uint32_t gamma_size;
    uint32_t mode_valid;
    edge_drm_modeinfo_t mode;
} edge_drm_crtc_t;

typedef struct {
    uint32_t encoder_id;
    uint32_t encoder_type;
    uint32_t crtc_id;
    uint32_t possible_crtcs;
    uint32_t possible_clones;
} edge_drm_encoder_t;

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
} edge_drm_connector_t;

typedef struct {
    uint32_t fb_id;
    uint32_t width;
    uint32_t height;
    uint32_t pitch;
    uint32_t bpp;
    uint32_t depth;
    uint32_t handle;
} edge_drm_fb_cmd_t;

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
} edge_drm_fb_cmd2_t;

typedef struct {
    uint32_t crtc_id;
    uint32_t fb_id;
    uint32_t flags;
    uint32_t reserved;
    uint64_t user_data;
} edge_drm_page_flip_t;

typedef struct {
    uint32_t fb_id;
    uint32_t flags;
    uint32_t color;
    uint32_t num_clips;
    uint64_t clips_ptr;
} edge_drm_dirty_fb_t;

typedef struct {
    uint16_t x1;
    uint16_t y1;
    uint16_t x2;
    uint16_t y2;
} edge_drm_clip_rect_t;

typedef struct {
    uint32_t height;
    uint32_t width;
    uint32_t bpp;
    uint32_t flags;
    uint32_t handle;
    uint32_t pitch;
    uint64_t size;
} edge_drm_create_dumb_t;

typedef struct {
    uint32_t handle;
    uint32_t pad;
    uint64_t offset;
} edge_drm_map_dumb_t;

typedef struct {
    uint32_t handle;
} edge_drm_destroy_dumb_t;

typedef struct {
    uint64_t plane_id_ptr;
    uint32_t count_planes;
    uint32_t pad;
} edge_drm_plane_res_t;

typedef struct {
    uint32_t plane_id;
    uint32_t crtc_id;
    uint32_t fb_id;
    uint32_t possible_crtcs;
    uint32_t gamma_size;
    uint32_t count_format_types;
    uint64_t format_type_ptr;
} edge_drm_plane_t;

typedef struct {
    uint32_t plane_id;
    uint32_t crtc_id;
    uint32_t fb_id;
    uint32_t flags;
    int32_t crtc_x;
    int32_t crtc_y;
    uint32_t crtc_w;
    uint32_t crtc_h;
    uint32_t src_x;
    uint32_t src_y;
    uint32_t src_h;
    uint32_t src_w;
} edge_drm_set_plane_t;

typedef struct {
    uint64_t value;
    char name[32];
} edge_drm_property_enum_t;

typedef struct {
    uint64_t values_ptr;
    uint64_t enum_blob_ptr;
    uint32_t prop_id;
    uint32_t flags;
    char name[32];
    uint32_t count_values;
    uint32_t count_enum_blobs;
} edge_drm_get_property_t;

typedef struct {
    uint64_t value;
    uint32_t prop_id;
    uint32_t connector_id;
} edge_drm_connector_set_property_t;

typedef struct {
    uint64_t props_ptr;
    uint64_t prop_values_ptr;
    uint32_t count_props;
    uint32_t obj_id;
    uint32_t obj_type;
    uint32_t pad;
} edge_drm_obj_get_properties_t;

typedef struct {
    uint64_t value;
    uint32_t prop_id;
    uint32_t obj_id;
    uint32_t obj_type;
    uint32_t pad;
} edge_drm_obj_set_property_t;

typedef struct {
    uint32_t blob_id;
    uint32_t length;
    uint64_t data;
} edge_drm_get_blob_t;

typedef struct {
    uint64_t data;
    uint32_t length;
    uint32_t blob_id;
} edge_drm_create_blob_t;

typedef struct {
    uint32_t blob_id;
} edge_drm_destroy_blob_t;

typedef struct {
    uint32_t count_lessees;
    uint32_t pad;
    uint64_t lessees_ptr;
} edge_drm_mode_list_lessees_t;

typedef struct {
    uint32_t flags;
    uint32_t count_objs;
    uint64_t objs_ptr;
    uint64_t count_props_ptr;
    uint64_t props_ptr;
    uint64_t prop_values_ptr;
    uint64_t reserved;
    uint64_t user_data;
} edge_drm_atomic_t;

typedef struct {
    int16_t x1;
    int16_t y1;
    int16_t x2;
    int16_t y2;
} edge_drm_mode_rect_t;

typedef struct {
    uint32_t type;
    uint32_t length;
    uint64_t user_data;
    uint32_t tv_sec;
    uint32_t tv_usec;
    uint32_t sequence;
    uint32_t crtc_id;
} edge_drm_event_vblank_t;

typedef struct {
    uint8_t used;
    uint8_t handle_open;
    uint8_t map_authorized;
    uint8_t mapped;
    uint8_t write_tracking;
    uint8_t scanout_pad[3];
    uint32_t handle;
    uint32_t width;
    uint32_t height;
    uint32_t pitch;
    uint32_t size;
    uint32_t page_count;
    uint32_t prime_refs;
    uint32_t alias_refs;
    uint32_t backing_index;
    uint64_t owner;
    uint64_t map_offset;
    uint8_t *storage;
    uint32_t dirty_pages[EDGE_DRM_DIRTY_PAGE_WORDS];
    uint32_t scanout_source_x;
    uint32_t scanout_source_y;
    uint32_t scanout_width;
    uint32_t scanout_height;
    uint32_t scanout_pitch;
    uint64_t scanout_page_hashes[EDGE_DRM_MAX_BUFFER_PAGES];
    uint8_t scanout_page_hash_valid[EDGE_DRM_MAX_BUFFER_PAGES];
} edge_drm_buffer_t;

typedef struct {
    uint8_t used;
    uint8_t virtgpu;
    uint8_t user_live;
    uint8_t pad;
    uint32_t id;
    uint32_t buffer_index;
    uint32_t virtgpu_handle;
    uint32_t width;
    uint32_t height;
    uint32_t pitch;
    uint32_t pixel_format;
    uint32_t depth;
    uint32_t bpp;
    uint64_t owner;
} edge_drm_framebuffer_t;

typedef struct {
    uint32_t fb_id;
    uint32_t pad;
} edge_drm_closefb_t;

typedef struct {
    uint8_t used;
    uint8_t universal_planes;
    uint8_t aspect_ratio;
    uint8_t atomic;
    uint8_t flip_pending;
    uint8_t event_pad[3];
    uint64_t identity;
    uint64_t flip_user_data;
    uint64_t flip_due_us;
    uint32_t magic;
    uint32_t event_head;
    uint32_t event_count;
    uint64_t readiness_sequence;
    edge_drm_event_vblank_t events[EDGE_DRM_EVENT_COUNT];
} edge_drm_client_t;

typedef struct {
    uint8_t used;
    uint8_t user_live;
    uint16_t reference_count;
    uint32_t id;
    uint32_t length;
    uint32_t pad;
    uint64_t owner;
    uint8_t data[EDGE_DRM_BLOB_CAPACITY];
} edge_drm_blob_t;

typedef struct {
    uint32_t flags;
    const char *name;
    uint32_t value_count;
    uint32_t enum_count;
    uint64_t values[2];
    edge_drm_property_enum_t enums[3];
} edge_drm_property_spec_t;

typedef struct {
    uint32_t connector_crtc_id;
    uint32_t crtc_active;
    uint32_t mode_blob_id;
    uint32_t plane_fb_id;
    uint32_t plane_crtc_id;
    uint32_t src_x;
    uint32_t src_y;
    uint32_t src_w;
    uint32_t src_h;
    int32_t crtc_x;
    int32_t crtc_y;
    uint32_t crtc_w;
    uint32_t crtc_h;
    uint32_t damage_blob_id;
    uint32_t cursor_fb_id;
    uint32_t cursor_crtc_id;
    uint32_t cursor_src_x;
    uint32_t cursor_src_y;
    uint32_t cursor_src_w;
    uint32_t cursor_src_h;
    int32_t cursor_crtc_x;
    int32_t cursor_crtc_y;
    uint32_t cursor_crtc_w;
    uint32_t cursor_crtc_h;
} edge_drm_atomic_state_t;

typedef struct {
    uint32_t fb_id;
    uint32_t crtc_id;
    uint32_t src_x;
    uint32_t src_y;
    uint32_t src_w;
    uint32_t src_h;
    int32_t crtc_x;
    int32_t crtc_y;
    uint32_t crtc_w;
    uint32_t crtc_h;
} edge_drm_cursor_state_t;

typedef struct {
    uint8_t *data;
    uint64_t owner;
    uint32_t virtgpu_handle;
    uint32_t width;
    uint32_t height;
    uint32_t pitch;
    uint32_t pixel_format;
    uint32_t source_x;
    uint32_t source_y;
} edge_drm_present_source_t;

_Static_assert(sizeof(edge_drm_version_t) == 64,
               "Linux DRM version layout mismatch");
_Static_assert(sizeof(edge_drm_modeinfo_t) == 68,
               "Linux DRM modeinfo layout mismatch");
_Static_assert(sizeof(edge_drm_card_res_t) == 64,
               "Linux DRM resource layout mismatch");
_Static_assert(sizeof(edge_drm_crtc_t) == 104,
               "Linux DRM CRTC layout mismatch");
_Static_assert(sizeof(edge_drm_connector_t) == 80,
               "Linux DRM connector layout mismatch");
_Static_assert(sizeof(edge_drm_fb_cmd2_t) == 104,
               "Linux DRM framebuffer2 layout mismatch");
_Static_assert(sizeof(edge_drm_get_property_t) == 64,
               "Linux DRM property layout mismatch");
_Static_assert(sizeof(edge_drm_obj_get_properties_t) == 32,
               "Linux DRM object property layout mismatch");
_Static_assert(sizeof(edge_drm_atomic_t) == 56,
               "Linux DRM atomic layout mismatch");
_Static_assert(sizeof(edge_drm_event_vblank_t) == 32,
               "Linux DRM event layout mismatch");
_Static_assert(sizeof(edge_drm_prime_handle_t) == 12,
               "Linux DRM PRIME handle layout mismatch");
_Static_assert(sizeof(edge_drm_mode_list_lessees_t) == 16,
               "Linux DRM lease list layout mismatch");

static edge_drm_buffer_t g_edge_drm_buffers[EDGE_DRM_BUFFER_COUNT];
static edge_drm_framebuffer_t
    g_edge_drm_framebuffers[EDGE_DRM_FRAMEBUFFER_COUNT];
static edge_drm_client_t g_edge_drm_clients[EDGE_DRM_CLIENT_COUNT];
static edge_drm_blob_t g_edge_drm_blobs[EDGE_DRM_BLOB_COUNT];
static volatile unsigned int g_edge_drm_guard;
static volatile unsigned int g_edge_drm_atomic_guard;
static uint64_t g_edge_drm_master;
static uint32_t g_edge_drm_next_handle = 1u;
static uint32_t g_edge_drm_next_fb_id = EDGE_DRM_FB_ID_BASE;
static uint32_t g_edge_drm_next_magic = 1u;
static uint32_t g_edge_drm_next_blob_id = EDGE_DRM_BLOB_ID_BASE;
static uint32_t g_edge_drm_active_fb;
static uint32_t g_edge_drm_crtc_x;
static uint32_t g_edge_drm_crtc_y;
static uint32_t g_edge_drm_mode_blob_id;
static uint8_t g_edge_drm_crtc_active;
static volatile uint32_t g_edge_drm_scanout_refresh_required;
static edge_drm_cursor_state_t g_edge_drm_cursor;
static uint32_t g_edge_drm_flip_sequence;
static volatile uint64_t g_edge_drm_next_scanout_us;
static volatile uint64_t g_edge_drm_scanout_interval_us =
    EDGE_DRM_SCANOUT_DEFAULT_INTERVAL_US;
static uint64_t g_edge_drm_vblank_epoch_us;
static uint64_t g_edge_drm_vblank_interval_us;
static volatile uint32_t g_edge_drm_scanout_idle_frames;
static volatile uint32_t g_edge_drm_scanout_activity_sequence;
static volatile unsigned int g_edge_drm_scanout_guard;
static volatile uint64_t g_edge_drm_explicit_verify_us;
static uint64_t
    g_edge_drm_scanout_hashes[EDGE_DRM_SCANOUT_TILE_COUNT];
static uint8_t
    g_edge_drm_scanout_hash_valid[EDGE_DRM_SCANOUT_TILE_COUNT];
static uint64_t
    g_edge_drm_scanout_page_hashes[EDGE_DRM_MAX_BUFFER_PAGES];
static uint8_t
    g_edge_drm_scanout_page_hash_valid[EDGE_DRM_MAX_BUFFER_PAGES];
static uint32_t g_edge_drm_scanout_source_x;
static uint32_t g_edge_drm_scanout_source_y;
static uint32_t g_edge_drm_scanout_width;
static uint32_t g_edge_drm_scanout_height;
static uint32_t g_edge_drm_scanout_pitch;
static edge_drm_runtime_stats_t g_edge_drm_runtime_stats;

static void edge_drm_mode_blob_reference_locked(uint32_t id);
static void edge_drm_buffer_maybe_release_locked(uint32_t buffer_index);
static void edge_drm_mode_blob_unreference_locked(uint32_t id);
static int edge_drm_blob_snapshot(uint32_t id, uint8_t *data,
                                  uint32_t *length);
static void edge_drm_pump_flip_events(uint64_t now_us);

static void edge_drm_relax(void) {
#if defined(__x86_64__)
    __asm__ __volatile__("pause");
#elif defined(__aarch64__)
    __asm__ __volatile__("yield");
#endif
}

static void edge_drm_lock(void) {
    while (__atomic_test_and_set(&g_edge_drm_guard, __ATOMIC_ACQUIRE))
        edge_drm_relax();
}

static void edge_drm_unlock(void) {
    __atomic_clear(&g_edge_drm_guard, __ATOMIC_RELEASE);
}

static void edge_drm_scanout_lock(void) {
    while (__atomic_test_and_set(
               &g_edge_drm_scanout_guard, __ATOMIC_ACQUIRE))
        edge_drm_relax();
}

static void edge_drm_scanout_unlock(void) {
    __atomic_clear(&g_edge_drm_scanout_guard, __ATOMIC_RELEASE);
}

static void edge_drm_stat_max(uint64_t *value, uint64_t candidate) {
    uint64_t current = __atomic_load_n(value, __ATOMIC_RELAXED);

    while (candidate > current &&
           !__atomic_compare_exchange_n(
               value, &current, candidate, 0,
               __ATOMIC_RELAXED, __ATOMIC_RELAXED)) {
    }
}

static void edge_drm_publish_scanout_state_locked(void) {
    if (!g_edge_drm_crtc_active || !g_edge_drm_active_fb)
        __atomic_store_n(&g_edge_drm_explicit_verify_us, 0u,
                         __ATOMIC_RELEASE);
    __atomic_store_n(
        &g_edge_drm_scanout_refresh_required,
        g_edge_drm_crtc_active && g_edge_drm_active_fb ? 1u : 0u,
        __ATOMIC_RELEASE);
}

static void edge_drm_atomic_lock(void) {
    while (__atomic_test_and_set(
               &g_edge_drm_atomic_guard, __ATOMIC_ACQUIRE))
        edge_drm_relax();
}

static void edge_drm_atomic_unlock(void) {
    __atomic_clear(&g_edge_drm_atomic_guard, __ATOMIC_RELEASE);
}

static uint32_t edge_drm_align_up(uint32_t value, uint32_t alignment) {
    return (value + alignment - 1u) & ~(alignment - 1u);
}

static uint32_t edge_drm_min_u32(uint32_t left, uint32_t right) {
    return left < right ? left : right;
}

static int edge_drm_copy_from(const kernel_ioctl_request_t *request,
                              void *destination, uint64_t source,
                              uint64_t length) {
    if (!request || !request->copy_from_user || (!source && length))
        return -1;
    return request->copy_from_user(request->copy_context, destination,
                                   source, length);
}

static int edge_drm_copy_to(const kernel_ioctl_request_t *request,
                            uint64_t destination, const void *source,
                            uint64_t length) {
    if (!request || !request->copy_to_user || (!destination && length))
        return -1;
    return request->copy_to_user(request->copy_context, destination,
                                 source, length);
}

static int edge_drm_copy_string(const kernel_ioctl_request_t *request,
                                uint64_t destination, uint64_t capacity,
                                const char *source, uint64_t source_length) {
    uint64_t count = capacity < source_length ? capacity : source_length;
    if (!count) return 0;
    return edge_drm_copy_to(request, destination, source, count);
}

static edge_drm_client_t *edge_drm_client_locked(uint64_t identity,
                                                  int create) {
    edge_drm_client_t *free_client = 0;

    if (!identity) return 0;
    for (uint32_t index = 0; index < EDGE_DRM_CLIENT_COUNT; ++index) {
        edge_drm_client_t *client = &g_edge_drm_clients[index];
        if (client->used && client->identity == identity)
            return client;
        if (!client->used && !free_client) free_client = client;
    }
    if (!create || !free_client) return 0;
    memset(free_client, 0, sizeof(*free_client));
    free_client->used = 1;
    free_client->identity = identity;
    free_client->magic = g_edge_drm_next_magic++;
    if (!free_client->magic) free_client->magic = g_edge_drm_next_magic++;
    return free_client;
}

static edge_drm_buffer_t *edge_drm_buffer_handle_locked(
    uint64_t owner, uint32_t handle, uint32_t *index_out) {
    for (uint32_t index = 0; index < EDGE_DRM_BUFFER_COUNT; ++index) {
        edge_drm_buffer_t *buffer = &g_edge_drm_buffers[index];
        if (buffer->used && buffer->owner == owner &&
            buffer->handle == handle && buffer->handle_open) {
            if (index_out) *index_out = index;
            return buffer;
        }
    }
    return 0;
}

static edge_drm_framebuffer_t *edge_drm_framebuffer_locked(
    uint32_t id, uint32_t *index_out) {
    for (uint32_t index = 0; index < EDGE_DRM_FRAMEBUFFER_COUNT; ++index) {
        edge_drm_framebuffer_t *framebuffer = &g_edge_drm_framebuffers[index];
        if (framebuffer->used && framebuffer->id == id) {
            if (index_out) *index_out = index;
            return framebuffer;
        }
    }
    return 0;
}

static int edge_drm_framebuffer_scanout_referenced_locked(uint32_t id) {
    return g_edge_drm_active_fb == id || g_edge_drm_cursor.fb_id == id;
}

static uint32_t edge_drm_detached_framebuffers_release_locked(
    uint64_t *virtgpu_owners, uint32_t *virtgpu_handles,
    uint32_t capacity) {
    uint32_t virtgpu_count = 0;

    for (uint32_t index = 0; index < EDGE_DRM_FRAMEBUFFER_COUNT; ++index) {
        edge_drm_framebuffer_t *framebuffer =
            &g_edge_drm_framebuffers[index];
        uint32_t buffer_index;

        if (!framebuffer->used || framebuffer->user_live ||
            edge_drm_framebuffer_scanout_referenced_locked(framebuffer->id))
            continue;
        buffer_index = framebuffer->buffer_index;
        if (framebuffer->virtgpu && virtgpu_count < capacity) {
            virtgpu_owners[virtgpu_count] = framebuffer->owner;
            virtgpu_handles[virtgpu_count] = framebuffer->virtgpu_handle;
            ++virtgpu_count;
        }
        memset(framebuffer, 0, sizeof(*framebuffer));
        if (buffer_index < EDGE_DRM_BUFFER_COUNT)
            edge_drm_buffer_maybe_release_locked(buffer_index);
    }
    return virtgpu_count;
}

static edge_drm_blob_t *edge_drm_blob_locked(uint32_t id) {
    for (uint32_t index = 0; index < EDGE_DRM_BLOB_COUNT; ++index)
        if (g_edge_drm_blobs[index].used &&
            g_edge_drm_blobs[index].id == id)
            return &g_edge_drm_blobs[index];
    return 0;
}

static void edge_drm_blob_maybe_release_locked(edge_drm_blob_t *blob) {
    if (blob && blob->used && !blob->user_live &&
        !blob->reference_count)
        memset(blob, 0, sizeof(*blob));
}

static int edge_drm_client_atomic_locked(uint64_t identity) {
    edge_drm_client_t *client = edge_drm_client_locked(identity, 0);
    return client && client->atomic;
}

static void edge_drm_property_enum_set(edge_drm_property_enum_t *entry,
                                       uint64_t value, const char *name) {
    memset(entry, 0, sizeof(*entry));
    entry->value = value;
    if (name) {
        uint32_t index = 0;
        while (name[index] && index + 1u < sizeof(entry->name)) {
            entry->name[index] = name[index];
            ++index;
        }
    }
}

static int edge_drm_property_spec(uint32_t id,
                                  edge_drm_property_spec_t *spec) {
    if (!spec) return 0;
    memset(spec, 0, sizeof(*spec));
    switch (id) {
        case EDGE_DRM_PROP_CONNECTOR_CRTC_ID:
            spec->name = "CRTC_ID";
            spec->flags = EDGE_DRM_MODE_PROP_OBJECT |
                EDGE_DRM_MODE_PROP_ATOMIC;
            spec->value_count = 1u;
            spec->values[0] = EDGE_DRM_MODE_OBJECT_CRTC;
            return 1;
        case EDGE_DRM_PROP_LINK_STATUS:
            spec->name = "link-status";
            spec->flags = EDGE_DRM_MODE_PROP_ENUM |
                EDGE_DRM_MODE_PROP_ATOMIC;
            spec->enum_count = 2u;
            edge_drm_property_enum_set(&spec->enums[0], 0u, "Good");
            edge_drm_property_enum_set(&spec->enums[1], 1u, "Bad");
            return 1;
        case EDGE_DRM_PROP_NON_DESKTOP:
            spec->name = "non-desktop";
            spec->flags = EDGE_DRM_MODE_PROP_RANGE |
                EDGE_DRM_MODE_PROP_IMMUTABLE;
            spec->value_count = 2u;
            spec->values[0] = 0u;
            spec->values[1] = 1u;
            return 1;
        case EDGE_DRM_PROP_EDID:
            spec->name = "EDID";
            spec->flags = EDGE_DRM_MODE_PROP_BLOB |
                EDGE_DRM_MODE_PROP_IMMUTABLE;
            return 1;
        case EDGE_DRM_PROP_CRTC_MODE_ID:
            spec->name = "MODE_ID";
            spec->flags = EDGE_DRM_MODE_PROP_BLOB |
                EDGE_DRM_MODE_PROP_ATOMIC;
            return 1;
        case EDGE_DRM_PROP_CRTC_ACTIVE:
            spec->name = "ACTIVE";
            spec->flags = EDGE_DRM_MODE_PROP_RANGE |
                EDGE_DRM_MODE_PROP_ATOMIC;
            spec->value_count = 2u;
            spec->values[0] = 0u;
            spec->values[1] = 1u;
            return 1;
        case EDGE_DRM_PROP_PLANE_FB_ID:
            spec->name = "FB_ID";
            spec->flags = EDGE_DRM_MODE_PROP_OBJECT |
                EDGE_DRM_MODE_PROP_ATOMIC;
            spec->value_count = 1u;
            spec->values[0] = EDGE_DRM_MODE_OBJECT_FB;
            return 1;
        case EDGE_DRM_PROP_PLANE_CRTC_ID:
            spec->name = "CRTC_ID";
            spec->flags = EDGE_DRM_MODE_PROP_OBJECT |
                EDGE_DRM_MODE_PROP_ATOMIC;
            spec->value_count = 1u;
            spec->values[0] = EDGE_DRM_MODE_OBJECT_CRTC;
            return 1;
        case EDGE_DRM_PROP_PLANE_SRC_X:
            spec->name = "SRC_X";
            break;
        case EDGE_DRM_PROP_PLANE_SRC_Y:
            spec->name = "SRC_Y";
            break;
        case EDGE_DRM_PROP_PLANE_SRC_W:
            spec->name = "SRC_W";
            break;
        case EDGE_DRM_PROP_PLANE_SRC_H:
            spec->name = "SRC_H";
            break;
        case EDGE_DRM_PROP_PLANE_CRTC_X:
            spec->name = "CRTC_X";
            spec->flags = EDGE_DRM_MODE_PROP_SIGNED_RANGE |
                EDGE_DRM_MODE_PROP_ATOMIC;
            spec->value_count = 2u;
            spec->values[0] = (uint64_t)(int64_t)INT32_MIN;
            spec->values[1] = (uint64_t)(int64_t)INT32_MAX;
            return 1;
        case EDGE_DRM_PROP_PLANE_CRTC_Y:
            spec->name = "CRTC_Y";
            spec->flags = EDGE_DRM_MODE_PROP_SIGNED_RANGE |
                EDGE_DRM_MODE_PROP_ATOMIC;
            spec->value_count = 2u;
            spec->values[0] = (uint64_t)(int64_t)INT32_MIN;
            spec->values[1] = (uint64_t)(int64_t)INT32_MAX;
            return 1;
        case EDGE_DRM_PROP_PLANE_CRTC_W:
            spec->name = "CRTC_W";
            break;
        case EDGE_DRM_PROP_PLANE_CRTC_H:
            spec->name = "CRTC_H";
            break;
        case EDGE_DRM_PROP_PLANE_TYPE:
            spec->name = "type";
            spec->flags = EDGE_DRM_MODE_PROP_ENUM |
                EDGE_DRM_MODE_PROP_IMMUTABLE;
            spec->enum_count = 3u;
            edge_drm_property_enum_set(&spec->enums[0], 0u, "Overlay");
            edge_drm_property_enum_set(&spec->enums[1], 1u, "Primary");
            edge_drm_property_enum_set(&spec->enums[2], 2u, "Cursor");
            return 1;
        case EDGE_DRM_PROP_PLANE_IN_FORMATS:
            spec->name = "IN_FORMATS";
            spec->flags = EDGE_DRM_MODE_PROP_BLOB |
                EDGE_DRM_MODE_PROP_IMMUTABLE;
            return 1;
        case EDGE_DRM_PROP_PLANE_FB_DAMAGE_CLIPS:
            spec->name = "FB_DAMAGE_CLIPS";
            spec->flags = EDGE_DRM_MODE_PROP_BLOB |
                EDGE_DRM_MODE_PROP_ATOMIC;
            return 1;
        default:
            return 0;
    }
    spec->flags = EDGE_DRM_MODE_PROP_RANGE | EDGE_DRM_MODE_PROP_ATOMIC;
    spec->value_count = 2u;
    spec->values[0] = 0u;
    spec->values[1] = UINT32_MAX;
    return 1;
}

static int edge_drm_property_visible(uint32_t property_id,
                                     int atomic_client) {
    edge_drm_property_spec_t spec;

    if (!edge_drm_property_spec(property_id, &spec)) return 0;
    return atomic_client ||
        (spec.flags & EDGE_DRM_MODE_PROP_ATOMIC) == 0;
}

static int edge_drm_buffer_referenced_locked(uint32_t buffer_index) {
    for (uint32_t index = 0; index < EDGE_DRM_FRAMEBUFFER_COUNT; ++index)
        if (g_edge_drm_framebuffers[index].used &&
            g_edge_drm_framebuffers[index].buffer_index == buffer_index)
            return 1;
    return 0;
}

static edge_drm_buffer_t *edge_drm_buffer_backing_locked(
    edge_drm_buffer_t *buffer, uint32_t *index_out) {
    uint32_t index;

    if (!buffer || buffer < g_edge_drm_buffers ||
        buffer >= g_edge_drm_buffers + EDGE_DRM_BUFFER_COUNT ||
        !buffer->used)
        return 0;
    index = (uint32_t)(buffer - g_edge_drm_buffers);
    if (buffer->backing_index != UINT32_MAX) {
        index = buffer->backing_index;
        if (index >= EDGE_DRM_BUFFER_COUNT ||
            !g_edge_drm_buffers[index].used ||
            g_edge_drm_buffers[index].backing_index != UINT32_MAX)
            return 0;
        buffer = &g_edge_drm_buffers[index];
    }
    if (index_out) *index_out = index;
    return buffer;
}

static void edge_drm_buffer_maybe_release_locked(uint32_t buffer_index) {
    edge_drm_buffer_t *buffer;
    uint32_t backing_index;
    uint8_t *storage;
    uint32_t page_count;

    if (buffer_index >= EDGE_DRM_BUFFER_COUNT) return;
    buffer = &g_edge_drm_buffers[buffer_index];
    if (!buffer->used || buffer->handle_open ||
        edge_drm_buffer_referenced_locked(buffer_index))
        return;
    if (buffer->backing_index != UINT32_MAX) {
        backing_index = buffer->backing_index;
        memset(buffer, 0, sizeof(*buffer));
        if (backing_index < EDGE_DRM_BUFFER_COUNT &&
            g_edge_drm_buffers[backing_index].used &&
            g_edge_drm_buffers[backing_index].alias_refs) {
            --g_edge_drm_buffers[backing_index].alias_refs;
            edge_drm_buffer_maybe_release_locked(backing_index);
        }
        return;
    }
    if (!buffer->prime_refs && !buffer->alias_refs) {
        storage = buffer->storage;
        page_count = buffer->page_count;
        memset(buffer, 0, sizeof(*buffer));
        for (uint32_t page = 0; storage && page < page_count; ++page)
            arch_vm_free_page(
                storage + (uint64_t)page * EDGE_DRM_PAGE_SIZE);
    }
}

static int edge_drm_mode_available(display_mode_t *mode,
                                   uint32_t *backend_flags) {
    display_backend_t backend;

    if (!mode || !fb.addr || !fb.width || !fb.height || fb.bpp != 32u)
        return 0;
    memset(mode, 0, sizeof(*mode));
    mode->width = fb.width;
    mode->height = fb.height;
    mode->refresh_millihz = DISPLAY_MODE_DEFAULT_REFRESH_MILLIHZ;
    if (display_backend_get_mode(mode) < 0) {
        mode->width = fb.width;
        mode->height = fb.height;
        mode->refresh_millihz = DISPLAY_MODE_DEFAULT_REFRESH_MILLIHZ;
    }
    if (!mode->refresh_millihz)
        mode->refresh_millihz = DISPLAY_MODE_DEFAULT_REFRESH_MILLIHZ;
    if (!display_mode_valid(mode))
        return 0;
    __atomic_store_n(&g_edge_drm_scanout_interval_us,
                     display_mode_frame_interval_us(mode),
                     __ATOMIC_RELEASE);
    if (backend_flags) {
        *backend_flags = 0;
        if (display_backend_snapshot(&backend, 0))
            *backend_flags = backend.flags;
    }
    return mode->width != 0 && mode->height != 0;
}

static uint64_t edge_drm_scanout_active_interval(void) {
    uint64_t interval = __atomic_load_n(
        &g_edge_drm_scanout_interval_us, __ATOMIC_ACQUIRE);

    return interval ? interval : EDGE_DRM_SCANOUT_DEFAULT_INTERVAL_US;
}

static uint64_t edge_drm_next_vblank_locked(uint64_t submitted_us) {
    uint64_t interval_us = edge_drm_scanout_active_interval();
    uint64_t elapsed_us;
    uint64_t periods;

    if (!interval_us) interval_us = EDGE_DRM_SCANOUT_DEFAULT_INTERVAL_US;
    if (!g_edge_drm_vblank_epoch_us ||
        g_edge_drm_vblank_interval_us != interval_us ||
        submitted_us < g_edge_drm_vblank_epoch_us) {
        g_edge_drm_vblank_epoch_us = submitted_us;
        g_edge_drm_vblank_interval_us = interval_us;
    }
    elapsed_us = submitted_us - g_edge_drm_vblank_epoch_us;
    periods = elapsed_us / interval_us + 1u;
    if (periods >
        (UINT64_MAX - g_edge_drm_vblank_epoch_us) / interval_us)
        return submitted_us > UINT64_MAX - interval_us ?
            UINT64_MAX : submitted_us + interval_us;
    return g_edge_drm_vblank_epoch_us + periods * interval_us;
}

static void edge_drm_schedule_explicit_verification(uint64_t now_us) {
    uint64_t interval_us = edge_drm_scanout_active_interval() * 2u;
    uint64_t deadline_us;
    uint64_t expected_us = 0u;
    uint64_t next_scanout_us;

    if (interval_us < EDGE_DRM_EXPLICIT_VERIFY_INTERVAL_US)
        interval_us = EDGE_DRM_EXPLICIT_VERIFY_INTERVAL_US;
    deadline_us = now_us + interval_us;

    /*
     * FB_DAMAGE_CLIPS is an optimization hint. A compositor may omit pixels
     * which native scanout hardware would observe directly, including window
     * shadows and decoration cleanup. Verify the committed dumb buffer at a
     * bounded cadence, and never let later commits postpone an already
     * scheduled verification. Otherwise a continuous drag can leave old
     * pixels visible indefinitely. Two display intervals cap the verification
     * work at roughly 30 Hz on a 60 Hz display so it cannot compete with the
     * compositor's explicit fast path.
     */
    if (!__atomic_compare_exchange_n(
            &g_edge_drm_explicit_verify_us, &expected_us, deadline_us, 0,
            __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
        deadline_us = expected_us;

    next_scanout_us = __atomic_load_n(
        &g_edge_drm_next_scanout_us, __ATOMIC_ACQUIRE);
    while (next_scanout_us == 0u || next_scanout_us > deadline_us) {
        if (__atomic_compare_exchange_n(
                &g_edge_drm_next_scanout_us, &next_scanout_us, deadline_us,
                0, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
            break;
    }
}

static void edge_drm_append_decimal(char *destination, uint32_t *position,
                                    uint32_t capacity, uint32_t value) {
    char reverse[10];
    uint32_t count = 0;

    do {
        reverse[count++] = (char)('0' + value % 10u);
        value /= 10u;
    } while (value && count < sizeof(reverse));
    while (count && *position + 1u < capacity)
        destination[(*position)++] = reverse[--count];
}

static void edge_drm_fill_mode(edge_drm_modeinfo_t *output,
                               const display_mode_t *mode,
                               int preferred) {
    uint32_t position = 0;
    uint64_t pixels;
    uint32_t width = mode->width;
    uint32_t height = mode->height;
    uint32_t refresh_millihz = mode->refresh_millihz;

    memset(output, 0, sizeof(*output));
    output->hdisplay = (uint16_t)width;
    output->hsync_start = mode->hsync_start ?
        mode->hsync_start : (uint16_t)(width + 16u);
    output->hsync_end = mode->hsync_end ?
        mode->hsync_end : (uint16_t)(width + 48u);
    output->htotal = mode->htotal ?
        mode->htotal : (uint16_t)(width + 80u);
    output->vdisplay = (uint16_t)height;
    output->vsync_start = mode->vsync_start ?
        mode->vsync_start : (uint16_t)(height + 3u);
    output->vsync_end = mode->vsync_end ?
        mode->vsync_end : (uint16_t)(height + 8u);
    output->vtotal = mode->vtotal ?
        mode->vtotal : (uint16_t)(height + 23u);
    output->vrefresh = refresh_millihz ?
        (refresh_millihz + 500u) / 1000u : 60u;
    pixels = (uint64_t)output->htotal * output->vtotal *
             output->vrefresh;
    output->clock = mode->pixel_clock_khz ?
        mode->pixel_clock_khz : (uint32_t)((pixels + 500u) / 1000u);
    if (mode->flags & DISPLAY_MODE_PHSYNC) output->flags |= 1u << 0;
    if (mode->flags & DISPLAY_MODE_NHSYNC) output->flags |= 1u << 1;
    if (mode->flags & DISPLAY_MODE_PVSYNC) output->flags |= 1u << 2;
    if (mode->flags & DISPLAY_MODE_NVSYNC) output->flags |= 1u << 3;
    if (mode->flags & DISPLAY_MODE_INTERLACE) output->flags |= 1u << 4;
    output->type = EDGE_DRM_MODE_TYPE_DRIVER |
        (preferred ? EDGE_DRM_MODE_TYPE_PREFERRED : 0u);
    edge_drm_append_decimal(output->name, &position,
                            sizeof(output->name), width);
    if (position + 1u < sizeof(output->name))
        output->name[position++] = 'x';
    edge_drm_append_decimal(output->name, &position,
                            sizeof(output->name), height);
    output->name[position] = 0;
}

static void edge_drm_display_mode_from_modeinfo(
    const edge_drm_modeinfo_t *input, display_mode_t *output) {
    uint64_t timing_pixels;

    memset(output, 0, sizeof(*output));
    output->width = input->hdisplay;
    output->height = input->vdisplay;
    timing_pixels = (uint64_t)input->htotal * input->vtotal;
    if (input->clock && timing_pixels) {
        output->refresh_millihz = (uint32_t)(
            ((uint64_t)input->clock * 1000000ull + timing_pixels / 2u) /
            timing_pixels);
    } else {
        output->refresh_millihz = input->vrefresh ?
            input->vrefresh * 1000u : DISPLAY_MODE_DEFAULT_REFRESH_MILLIHZ;
    }
    output->pixel_clock_khz = input->clock;
    output->hsync_start = input->hsync_start;
    output->hsync_end = input->hsync_end;
    output->htotal = input->htotal;
    output->vsync_start = input->vsync_start;
    output->vsync_end = input->vsync_end;
    output->vtotal = input->vtotal;
    if (input->flags & (1u << 0)) output->flags |= DISPLAY_MODE_PHSYNC;
    if (input->flags & (1u << 1)) output->flags |= DISPLAY_MODE_NHSYNC;
    if (input->flags & (1u << 2)) output->flags |= DISPLAY_MODE_PVSYNC;
    if (input->flags & (1u << 3)) output->flags |= DISPLAY_MODE_NVSYNC;
    if (input->flags & (1u << 4)) output->flags |= DISPLAY_MODE_INTERLACE;
}

static int edge_drm_mode_duplicate(const edge_drm_modeinfo_t *modes,
                                   uint32_t count,
                                   const display_mode_t *mode) {
    for (uint32_t index = 0; index < count; ++index)
        if (modes[index].hdisplay == mode->width &&
            modes[index].vdisplay == mode->height &&
            modes[index].vrefresh ==
                (mode->refresh_millihz + 500u) / 1000u &&
            ((modes[index].flags >> 4) & 1u) ==
                ((mode->flags & DISPLAY_MODE_INTERLACE) != 0))
            return 1;
    return 0;
}

static uint32_t edge_drm_collect_modes(edge_drm_modeinfo_t *modes) {
    static const uint16_t common[][2] = {
        { 7680u, 4320u }, { 5120u, 2880u }, { 5120u, 2160u },
        { 3840u, 2160u }, { 3440u, 1440u }, { 2560u, 1440u },
        { 1920u, 1080u }, { 1600u, 900u }, { 1440u, 900u },
        { 1366u, 768u }, { 1280u, 1024u }, { 1280u, 800u },
        { 1280u, 720u }, { 1024u, 768u }, { 800u, 600u },
    };
    display_mode_t current;
    display_mode_t backend_modes[DISPLAY_MODE_EDID_MAX_MODES];
    uint32_t backend_flags = 0;
    uint32_t backend_count;
    uint32_t count = 0;

    if (!modes || !edge_drm_mode_available(&current, &backend_flags))
        return 0;
    edge_drm_fill_mode(&modes[count++], &current, 1);
    backend_count = display_backend_get_modes(
        backend_modes, DISPLAY_MODE_EDID_MAX_MODES);
    if (backend_count > DISPLAY_MODE_EDID_MAX_MODES)
        backend_count = DISPLAY_MODE_EDID_MAX_MODES;
    for (uint32_t index = 0;
         index < backend_count && count < EDGE_DRM_MODE_COUNT; ++index) {
        display_mode_t *candidate = &backend_modes[index];

        if (!display_mode_valid(candidate) ||
            candidate->width > EDGE_DRM_MAX_WIDTH ||
            candidate->height > EDGE_DRM_MAX_HEIGHT ||
            edge_drm_mode_duplicate(modes, count, candidate))
            continue;
        edge_drm_fill_mode(&modes[count++], candidate,
                           (candidate->flags & DISPLAY_MODE_PREFERRED) != 0);
    }
    if (!(backend_flags & DISPLAY_BACKEND_DYNAMIC_MODE)) return count;
    for (uint32_t index = 0;
         index < sizeof(common) / sizeof(common[0]) &&
         count < EDGE_DRM_MODE_COUNT; ++index) {
        uint32_t width = common[index][0];
        uint32_t height = common[index][1];
        display_mode_t candidate = {
            .width = width,
            .height = height,
            .refresh_millihz = current.refresh_millihz,
        };
        if (width > EDGE_DRM_MAX_WIDTH || height > EDGE_DRM_MAX_HEIGHT ||
            edge_drm_mode_duplicate(modes, count, &candidate))
            continue;
        edge_drm_fill_mode(&modes[count++], &candidate, 0);
    }
    return count;
}

static int edge_drm_require_master_locked(uint64_t identity) {
    if (!g_edge_drm_master) g_edge_drm_master = identity;
    return g_edge_drm_master == identity ? 0 : -EDGE_LINUX_EACCES;
}

static int edge_drm_present_source_locked(
    uint32_t framebuffer_id, edge_drm_present_source_t *source) {
    edge_drm_framebuffer_t *framebuffer;
    edge_drm_buffer_t *buffer;

    framebuffer = edge_drm_framebuffer_locked(framebuffer_id, 0);
    if (!framebuffer)
        return -EDGE_LINUX_ENOENT;
    if (framebuffer->virtgpu) {
        memset(source, 0, sizeof(*source));
        source->owner = framebuffer->owner;
        source->virtgpu_handle = framebuffer->virtgpu_handle;
        source->width = framebuffer->width;
        source->height = framebuffer->height;
        source->pitch = framebuffer->pitch;
        source->pixel_format = framebuffer->pixel_format;
        source->source_x = g_edge_drm_crtc_x;
        source->source_y = g_edge_drm_crtc_y;
        return 0;
    }
    if (framebuffer->buffer_index >= EDGE_DRM_BUFFER_COUNT)
        return -EDGE_LINUX_ENOENT;
    buffer = &g_edge_drm_buffers[framebuffer->buffer_index];
    buffer = edge_drm_buffer_backing_locked(buffer, 0);
    if (!buffer || !buffer->used || framebuffer->pitch > buffer->pitch ||
        framebuffer->width > buffer->width ||
        framebuffer->height > buffer->height)
        return -EDGE_LINUX_EIO;
    memset(source, 0, sizeof(*source));
    source->data = buffer->storage;
    source->width = framebuffer->width;
    source->height = framebuffer->height;
    source->pitch = framebuffer->pitch;
    source->pixel_format = framebuffer->pixel_format;
    source->source_x = g_edge_drm_crtc_x;
    source->source_y = g_edge_drm_crtc_y;
    return 0;
}

static int edge_drm_present_source_rect(
    const edge_drm_present_source_t *source,
    uint32_t destination_x, uint32_t destination_y,
    uint32_t width, uint32_t height, int flush) {
    uint32_t source_x;
    uint32_t source_y;
    int direct_layout;

    if (!source) return -EDGE_LINUX_EINVAL;
    if (!fb.addr || fb.bpp != 32u) return -EDGE_LINUX_ENODEV;

    source_x = source->source_x + destination_x;
    source_y = source->source_y + destination_y;
    if (destination_x >= fb.width || destination_y >= fb.height ||
        source_x >= source->width || source_y >= source->height)
        return -EDGE_LINUX_EINVAL;
    width = edge_drm_min_u32(width, fb.width - destination_x);
    width = edge_drm_min_u32(width, source->width - source_x);
    height = edge_drm_min_u32(height, fb.height - destination_y);
    height = edge_drm_min_u32(height, source->height - source_y);
    if (!width || !height) return -EDGE_LINUX_EINVAL;
    if (source->virtgpu_handle)
        return edge_virtgpu_framebuffer_present(
            source->owner, source->virtgpu_handle,
            source_x, source_y, width, height);

    (void)edge_virtgpu_framebuffer_reset();
    direct_layout = fb.r_pos == 16u && fb.g_pos == 8u && fb.b_pos == 0u;
    for (uint32_t row = 0; row < height; ++row) {
        const uint8_t *input = source->data +
            (uint64_t)(source_y + row) * source->pitch +
            (uint64_t)source_x * 4u;
        uint8_t *output = fb.addr +
            (uint64_t)(destination_y + row) * fb.pitch +
            (uint64_t)destination_x * 4u;
        if (direct_layout) {
            memcpy(output, input, (uint64_t)width * 4u);
        } else {
            for (uint32_t column = 0; column < width; ++column) {
                uint32_t pixel;
                memcpy(&pixel, input + (uint64_t)column * 4u,
                       sizeof(pixel));
                output[(uint64_t)column * 4u + (fb.r_pos >> 3)] =
                    (uint8_t)(pixel >> 16);
                output[(uint64_t)column * 4u + (fb.g_pos >> 3)] =
                    (uint8_t)(pixel >> 8);
                output[(uint64_t)column * 4u + (fb.b_pos >> 3)] =
                    (uint8_t)pixel;
                if (fb.r_pos != 24u && fb.g_pos != 24u &&
                    fb.b_pos != 24u)
                    output[(uint64_t)column * 4u + 3u] = 0xffu;
            }
        }
    }
    if (flush)
        fb_flush_rect((int)destination_x, (int)destination_y,
                      (int)width, (int)height);
    memset(g_edge_drm_scanout_page_hash_valid, 0,
           sizeof(g_edge_drm_scanout_page_hash_valid));
    return 0;
}

static int edge_drm_present_rect(uint32_t framebuffer_id,
                                 uint32_t destination_x,
                                 uint32_t destination_y,
                                 uint32_t width, uint32_t height) {
    edge_drm_present_source_t source;
    int result;

    edge_drm_lock();
    result = edge_drm_present_source_locked(framebuffer_id, &source);
    edge_drm_unlock();
    if (result < 0) return result;
    return edge_drm_present_source_rect(
        &source, destination_x, destination_y, width, height, 1);
}

static int edge_drm_present_full(uint32_t framebuffer_id) {
    return edge_drm_present_rect(framebuffer_id, 0, 0,
                                 fb.width, fb.height);
}

static int edge_drm_cursor_clip(const edge_drm_cursor_state_t *cursor,
                                uint32_t *destination_x,
                                uint32_t *destination_y,
                                uint32_t *source_x,
                                uint32_t *source_y,
                                uint32_t *width, uint32_t *height) {
    int64_t left;
    int64_t top;
    int64_t right;
    int64_t bottom;

    if (!cursor || !cursor->fb_id || !cursor->crtc_id ||
        !cursor->crtc_w || !cursor->crtc_h || !fb.width || !fb.height)
        return 0;
    left = cursor->crtc_x;
    top = cursor->crtc_y;
    right = left + cursor->crtc_w;
    bottom = top + cursor->crtc_h;
    if (right <= 0 || bottom <= 0 || left >= (int64_t)fb.width ||
        top >= (int64_t)fb.height)
        return 0;
    *source_x = cursor->src_x >> 16;
    *source_y = cursor->src_y >> 16;
    if (left < 0) {
        *source_x += (uint32_t)-left;
        left = 0;
    }
    if (top < 0) {
        *source_y += (uint32_t)-top;
        top = 0;
    }
    if (right > fb.width) right = fb.width;
    if (bottom > fb.height) bottom = fb.height;
    *destination_x = (uint32_t)left;
    *destination_y = (uint32_t)top;
    *width = (uint32_t)(right - left);
    *height = (uint32_t)(bottom - top);
    return *width && *height;
}

static int edge_drm_cursor_restore_internal(
    const edge_drm_cursor_state_t *cursor, uint32_t primary_fb_id,
    int flush, display_rect_t *damage) {
    edge_drm_present_source_t source;
    uint32_t destination_x;
    uint32_t destination_y;
    uint32_t source_x;
    uint32_t source_y;
    uint32_t width;
    uint32_t height;

    if (!primary_fb_id ||
        !edge_drm_cursor_clip(cursor, &destination_x, &destination_y,
                              &source_x, &source_y, &width, &height))
        return 0;
    (void)source_x;
    (void)source_y;
    edge_drm_lock();
    if (edge_drm_present_source_locked(primary_fb_id, &source) < 0) {
        edge_drm_unlock();
        return -EDGE_LINUX_ENOENT;
    }
    edge_drm_unlock();
    if (damage) {
        damage->x = destination_x;
        damage->y = destination_y;
        damage->width = width;
        damage->height = height;
    }
    return edge_drm_present_source_rect(
        &source, destination_x, destination_y, width, height, flush);
}

static int edge_drm_cursor_restore(const edge_drm_cursor_state_t *cursor,
                                   uint32_t primary_fb_id) {
    display_rect_t damage = {0};
    int result;

    edge_drm_scanout_lock();
    result = edge_drm_cursor_restore_internal(
        cursor, primary_fb_id, 0, &damage);
    if (damage.width && damage.height)
        fb_flush_rects(&damage, 1u);
    edge_drm_scanout_unlock();
    return result;
}

static uint8_t edge_drm_cursor_blend_channel(uint8_t source,
                                             uint8_t destination,
                                             uint8_t alpha) {
    uint32_t value = source +
        ((uint32_t)destination * (255u - alpha) + 127u) / 255u;
    return (uint8_t)(value > 255u ? 255u : value);
}

static int edge_drm_cursor_draw_internal(
    const edge_drm_cursor_state_t *cursor, int flush,
    display_rect_t *damage) {
    edge_drm_present_source_t source;
    uint32_t destination_x;
    uint32_t destination_y;
    uint32_t source_x;
    uint32_t source_y;
    uint32_t width;
    uint32_t height;
    int result;

    if (!edge_drm_cursor_clip(cursor, &destination_x, &destination_y,
                              &source_x, &source_y, &width, &height))
        return 0;
    edge_drm_lock();
    result = edge_drm_present_source_locked(cursor->fb_id, &source);
    edge_drm_unlock();
    if (result < 0) return result;
    if (!source.data || source.virtgpu_handle ||
        source.pixel_format != EDGE_DRM_FORMAT_ARGB8888 ||
        source_x > source.width || source_y > source.height ||
        width > source.width - source_x ||
        height > source.height - source_y)
        return -EDGE_LINUX_EINVAL;

    /*
     * Cursor buffers use premultiplied ARGB8888. Compositing this small plane
     * directly into the scanout aperture keeps pointer motion independent of
     * llvmpipe's primary-plane frame time. The old rectangle is restored from
     * the primary framebuffer before every move, matching a hardware cursor's
     * externally visible behavior without forcing a full-screen repaint.
     */
    for (uint32_t row = 0; row < height; ++row) {
        const uint8_t *input = source.data +
            (uint64_t)(source_y + row) * source.pitch +
            (uint64_t)source_x * 4u;
        uint8_t *output = fb.addr +
            (uint64_t)(destination_y + row) * fb.pitch +
            (uint64_t)destination_x * 4u;

        for (uint32_t column = 0; column < width; ++column) {
            uint32_t pixel;
            uint8_t alpha;
            uint8_t red;
            uint8_t green;
            uint8_t blue;
            uint8_t *destination = output + (uint64_t)column * 4u;

            memcpy(&pixel, input + (uint64_t)column * 4u,
                   sizeof(pixel));
            alpha = (uint8_t)(pixel >> 24);
            if (!alpha) continue;
            red = (uint8_t)(pixel >> 16);
            green = (uint8_t)(pixel >> 8);
            blue = (uint8_t)pixel;
            if (alpha == 255u) {
                destination[fb.r_pos >> 3] = red;
                destination[fb.g_pos >> 3] = green;
                destination[fb.b_pos >> 3] = blue;
            } else {
                destination[fb.r_pos >> 3] =
                    edge_drm_cursor_blend_channel(
                        red, destination[fb.r_pos >> 3], alpha);
                destination[fb.g_pos >> 3] =
                    edge_drm_cursor_blend_channel(
                        green, destination[fb.g_pos >> 3], alpha);
                destination[fb.b_pos >> 3] =
                    edge_drm_cursor_blend_channel(
                        blue, destination[fb.b_pos >> 3], alpha);
            }
        }
    }
    if (damage) {
        damage->x = destination_x;
        damage->y = destination_y;
        damage->width = width;
        damage->height = height;
    }
    if (flush)
        fb_flush_rect((int)destination_x, (int)destination_y,
                      (int)width, (int)height);
    return 0;
}

static int edge_drm_cursor_draw(const edge_drm_cursor_state_t *cursor) {
    display_rect_t damage = {0};
    int result;

    edge_drm_scanout_lock();
    result = edge_drm_cursor_draw_internal(cursor, 0, &damage);
    if (damage.width && damage.height)
        fb_flush_rects(&damage, 1u);
    edge_drm_scanout_unlock();
    return result;
}

static int edge_drm_cursor_transition(
    const edge_drm_cursor_state_t *previous,
    const edge_drm_cursor_state_t *next, uint32_t primary_fb_id) {
    display_rect_t damage[2];
    uint32_t count = 0;
    int result;

    edge_drm_scanout_lock();
    memset(damage, 0, sizeof(damage));
    result = edge_drm_cursor_restore_internal(
        previous, primary_fb_id, 0, &damage[count]);
    if (result < 0) goto out;
    if (damage[count].width && damage[count].height) ++count;
    result = edge_drm_cursor_draw_internal(next, 0, &damage[count]);
    if (result < 0) {
        goto out;
    }
    if (damage[count].width && damage[count].height) ++count;
out:
    if (count)
        fb_flush_rects(damage, count);
    edge_drm_scanout_unlock();
    return result;
}

static void edge_drm_cursor_snapshot(edge_drm_cursor_state_t *cursor) {
    if (!cursor) return;
    edge_drm_lock();
    *cursor = g_edge_drm_cursor;
    edge_drm_unlock();
}

static uint64_t edge_drm_hash_rotate_left(uint64_t value,
                                          uint32_t shift) {
    return (value << shift) | (value >> (64u - shift));
}

static void edge_drm_scanout_hash_quad(uint64_t *lane0, uint64_t *lane1,
                                       uint64_t *lane2, uint64_t *lane3,
                                       const uint8_t *input) {
    uint64_t word0;
    uint64_t word1;
    uint64_t word2;
    uint64_t word3;

    memcpy(&word0, input, sizeof(word0));
    memcpy(&word1, input + 8u, sizeof(word1));
    memcpy(&word2, input + 16u, sizeof(word2));
    memcpy(&word3, input + 24u, sizeof(word3));
    word0 &= 0x00ffffff00ffffffull;
    word1 &= 0x00ffffff00ffffffull;
    word2 &= 0x00ffffff00ffffffull;
    word3 &= 0x00ffffff00ffffffull;
    *lane0 = edge_drm_hash_rotate_left(*lane0 ^ word0, 13u) + *lane1;
    *lane1 = edge_drm_hash_rotate_left(*lane1 + word1, 17u) ^ *lane2;
    *lane2 = edge_drm_hash_rotate_left(*lane2 ^ word2, 29u) + *lane3;
    *lane3 = edge_drm_hash_rotate_left(*lane3 + word3, 37u) ^ *lane0;
}

static uint64_t edge_drm_scanout_hash_finish(uint64_t lane0,
                                             uint64_t lane1,
                                             uint64_t lane2,
                                             uint64_t lane3,
                                             uint64_t salt) {
    lane0 ^= edge_drm_hash_rotate_left(lane1, 11u);
    lane0 ^= edge_drm_hash_rotate_left(lane2, 23u);
    lane0 ^= edge_drm_hash_rotate_left(lane3, 41u);
    lane0 ^= salt;
    lane0 ^= lane0 >> 33;
    lane0 *= 0xff51afd7ed558ccdull;
    lane0 ^= lane0 >> 33;
    lane0 *= 0xc4ceb9fe1a85ec53ull;
    lane0 ^= lane0 >> 33;
    return lane0;
}

static uint64_t edge_drm_scanout_tile_hash(
    const uint8_t *storage, uint32_t pitch,
    uint32_t x, uint32_t y, uint32_t width, uint32_t height) {
    uint64_t lane0 = 0x243f6a8885a308d3ull;
    uint64_t lane1 = 0x13198a2e03707344ull;
    uint64_t lane2 = 0xa4093822299f31d0ull;
    uint64_t lane3 = 0x082efa98ec4e6c89ull;

    for (uint32_t row = 0; row < height; ++row) {
        const uint8_t *input =
            storage + (uint64_t)(y + row) * pitch + (uint64_t)x * 4u;
        uint32_t bytes = width * 4u;

        /*
         * Four independent rotate/add lanes avoid the serialized multiply in
         * FNV for every pair of pixels. The final avalanche remains 64-bit,
         * while the hot 1080p scan becomes simple integer operations that can
         * overlap on both supported architectures.
         */
        while (bytes >= 4u * sizeof(uint64_t)) {
            edge_drm_scanout_hash_quad(
                &lane0, &lane1, &lane2, &lane3, input);
            input += 4u * sizeof(uint64_t);
            bytes -= 4u * sizeof(uint64_t);
        }
        while (bytes >= sizeof(uint64_t)) {
            uint64_t word;
            memcpy(&word, input, sizeof(word));
            /*
             * KMS scanout treats both supported formats as opaque. XRGB's
             * unused high byte may be rewritten with indeterminate values by
             * userspace even though the visible pixels are unchanged. Ignore
             * that byte in each little-endian pixel so invisible churn cannot
             * keep the direct-display refresh loop active.
             */
            lane0 = edge_drm_hash_rotate_left(
                lane0 ^ (word & 0x00ffffff00ffffffull), 13u) + lane1;
            lane1 = edge_drm_hash_rotate_left(lane1, 17u) ^ lane0;
            input += sizeof(word);
            bytes -= sizeof(word);
        }
        if (bytes >= sizeof(uint32_t)) {
            uint32_t pixel;
            memcpy(&pixel, input, sizeof(pixel));
            lane2 = edge_drm_hash_rotate_left(
                lane2 ^ (pixel & 0x00ffffffu), 29u) + lane3;
        }
    }
    return edge_drm_scanout_hash_finish(
        lane0, lane1, lane2, lane3,
        ((uint64_t)width << 32) | height);
}

static uint64_t edge_drm_scanout_page_hash(const uint8_t *storage,
                                           uint32_t page) {
    const uint8_t *input =
        storage + (uint64_t)page * EDGE_DRM_PAGE_SIZE;
    uint64_t lane0 = 0x243f6a8885a308d3ull;
    uint64_t lane1 = 0x13198a2e03707344ull;
    uint64_t lane2 = 0xa4093822299f31d0ull;
    uint64_t lane3 = 0x082efa98ec4e6c89ull;

    for (uint32_t offset = 0; offset < EDGE_DRM_PAGE_SIZE;
         offset += 4u * sizeof(uint64_t))
        edge_drm_scanout_hash_quad(
            &lane0, &lane1, &lane2, &lane3, input + offset);
    return edge_drm_scanout_hash_finish(
        lane0, lane1, lane2, lane3, (uint64_t)page << 32);
}

static void edge_drm_scanout_invalidate(void) {
    memset(g_edge_drm_scanout_hash_valid, 0,
           sizeof(g_edge_drm_scanout_hash_valid));
}

static void edge_drm_scanout_page_invalidate(void) {
    memset(g_edge_drm_scanout_page_hash_valid, 0,
           sizeof(g_edge_drm_scanout_page_hash_valid));
}

static void edge_drm_scanout_damage_add(
    display_rect_t *batch, uint32_t *batch_count,
    const display_rect_t *rect) {
    display_rect_t merged;
    uint32_t right;
    uint32_t bottom;

    if (!batch || !batch_count || !rect ||
        !rect->width || !rect->height)
        return;
    if (*batch_count < EDGE_DRM_SCANOUT_BATCH_RECTS) {
        batch[(*batch_count)++] = *rect;
        return;
    }
    merged = batch[0];
    right = merged.x + merged.width;
    bottom = merged.y + merged.height;
    for (uint32_t index = 1u; index < *batch_count; ++index) {
        uint32_t rect_right = batch[index].x + batch[index].width;
        uint32_t rect_bottom = batch[index].y + batch[index].height;

        if (batch[index].x < merged.x) merged.x = batch[index].x;
        if (batch[index].y < merged.y) merged.y = batch[index].y;
        if (rect_right > right) right = rect_right;
        if (rect_bottom > bottom) bottom = rect_bottom;
    }
    if (rect->x < merged.x) merged.x = rect->x;
    if (rect->y < merged.y) merged.y = rect->y;
    if (rect->x + rect->width > right)
        right = rect->x + rect->width;
    if (rect->y + rect->height > bottom)
        bottom = rect->y + rect->height;
    merged.width = right - merged.x;
    merged.height = bottom - merged.y;
    batch[0] = merged;
    *batch_count = 1u;
}

static int edge_drm_rects_intersect(const display_rect_t *left,
                                    const display_rect_t *right) {
    if (!left || !right || !left->width || !left->height ||
        !right->width || !right->height)
        return 0;
    return left->x < right->x + right->width &&
           right->x < left->x + left->width &&
           left->y < right->y + right->height &&
           right->y < left->y + left->height;
}

static void edge_drm_scanout_flush_present(
    display_rect_t *batch, uint32_t *batch_count,
    int redraw_cursor, uint32_t primary_fb_id) {
    edge_drm_cursor_state_t cursor;
    display_rect_t cursor_rect;
    uint32_t destination_x;
    uint32_t destination_y;
    uint32_t source_x;
    uint32_t source_y;
    uint32_t width;
    uint32_t height;
    int cursor_damaged = 0;

    if (!batch || !batch_count || !*batch_count)
        return;
    memset(&cursor, 0, sizeof(cursor));
    memset(&cursor_rect, 0, sizeof(cursor_rect));
    if (redraw_cursor) {
        edge_drm_cursor_snapshot(&cursor);
        if (cursor.fb_id && edge_drm_cursor_clip(
                &cursor, &destination_x, &destination_y,
                &source_x, &source_y, &width, &height)) {
            cursor_rect.x = destination_x;
            cursor_rect.y = destination_y;
            cursor_rect.width = width;
            cursor_rect.height = height;
            for (uint32_t index = 0; index < *batch_count; ++index) {
                if (edge_drm_rects_intersect(
                        &batch[index], &cursor_rect)) {
                    cursor_damaged = 1;
                    break;
                }
            }
        }
    }
    if (cursor_damaged &&
        edge_drm_cursor_restore_internal(
            &cursor, primary_fb_id, 0, 0) == 0 &&
        edge_drm_cursor_draw_internal(&cursor, 0, 0) == 0)
        edge_drm_scanout_damage_add(
            batch, batch_count, &cursor_rect);
    fb_flush_rects(batch, *batch_count);
    *batch_count = 0;
}

static int edge_drm_scanout_queue_span(
    const edge_drm_present_source_t *source,
    uint32_t row, uint32_t first_column, uint32_t last_column,
    uint32_t width, uint32_t height,
    display_rect_t *batch, uint32_t *batch_count) {
    display_rect_t rect;
    int result;

    if (!source || !batch || !batch_count ||
        first_column > last_column)
        return -EDGE_LINUX_EINVAL;
    rect.x = first_column * EDGE_DRM_SCANOUT_TILE_WIDTH;
    rect.y = row * EDGE_DRM_SCANOUT_TILE_HEIGHT;
    if (rect.x >= width || rect.y >= height)
        return 0;
    rect.width =
        (last_column + 1u) * EDGE_DRM_SCANOUT_TILE_WIDTH - rect.x;
    if (rect.width > width - rect.x)
        rect.width = width - rect.x;
    rect.height = EDGE_DRM_SCANOUT_TILE_HEIGHT;
    if (rect.height > height - rect.y)
        rect.height = height - rect.y;
    result = edge_drm_present_source_rect(
        source, rect.x, rect.y, rect.width, rect.height, 0);
    if (result < 0)
        return result;
    edge_drm_scanout_damage_add(batch, batch_count, &rect);
    return 0;
}

static int edge_drm_dirty_page_test(const uint32_t *dirty_pages,
                                    uint32_t page) {
    return dirty_pages &&
        (dirty_pages[page >> 5] & (1u << (page & 31u))) != 0;
}

static void edge_drm_scanout_writeprotect_dirty(
    const uint8_t *storage, const uint32_t *dirty_pages,
    uint32_t page_count) {
    uint32_t page = 0;

    while (page < page_count) {
        uint32_t first;

        while (page < page_count &&
               !edge_drm_dirty_page_test(dirty_pages, page))
            ++page;
        if (page >= page_count) break;
        first = page++;
        while (page < page_count &&
               edge_drm_dirty_page_test(dirty_pages, page))
            ++page;
        (void)arch_vm_writeprotect_physical_aliases(
            (uint64_t)(uintptr_t)storage +
                (uint64_t)first * EDGE_DRM_PAGE_SIZE,
            (uint64_t)(page - first) * EDGE_DRM_PAGE_SIZE);
    }
}

static int edge_drm_scanout_present_page_run(
    const edge_drm_present_source_t *source, uint32_t first_page,
    uint32_t end_page, uint32_t pitch, uint32_t source_y,
    uint32_t width, uint32_t height,
    display_rect_t *batch, uint32_t *batch_count) {
    display_rect_t rect;
    uint64_t byte_start;
    uint64_t byte_end;
    uint32_t first_row;
    uint32_t last_row;
    uint32_t visible_end;

    if (!source || !batch || !batch_count ||
        first_page >= end_page || !pitch || !width || !height)
        return 0;
    byte_start = (uint64_t)first_page * EDGE_DRM_PAGE_SIZE;
    byte_end = (uint64_t)end_page * EDGE_DRM_PAGE_SIZE;
    first_row = (uint32_t)(byte_start / pitch);
    last_row = (uint32_t)((byte_end - 1u) / pitch);
    visible_end = source_y + height;
    if (last_row < source_y || first_row >= visible_end) return 0;
    if (first_row < source_y) first_row = source_y;
    if (last_row >= visible_end) last_row = visible_end - 1u;
    rect.x = 0u;
    rect.y = first_row - source_y;
    rect.width = width;
    rect.height = last_row - first_row + 1u;
    if (edge_drm_present_source_rect(
            source, rect.x, rect.y, rect.width, rect.height, 0) < 0)
        return -EDGE_LINUX_EIO;
    edge_drm_scanout_damage_add(batch, batch_count, &rect);
    return 0;
}

void edge_drm_scanout_activity(void) {
    uint64_t now_us;
    uint64_t next_scanout_us;
    uint64_t interval_us;

    /*
     * Direct scanout polling backs off while the screen is unchanged. Input
     * activity commonly precedes a cursor or desktop update, so wake the next
     * scan immediately. Explicit-present backends also use this state to skip
     * redundant transfers when a compositor recommits unchanged buffers.
     */
    __atomic_add_fetch(
        &g_edge_drm_scanout_activity_sequence, 1u, __ATOMIC_RELEASE);
    __atomic_store_n(&g_edge_drm_scanout_idle_frames, 0u, __ATOMIC_RELEASE);
    now_us = boottime_monotonic_us();
    interval_us = edge_drm_scanout_active_interval();
    next_scanout_us = __atomic_load_n(
        &g_edge_drm_next_scanout_us, __ATOMIC_ACQUIRE);
    if (next_scanout_us == 0u || next_scanout_us <= now_us ||
        next_scanout_us - now_us > interval_us) {
        __atomic_store_n(
            &g_edge_drm_next_scanout_us, 0u, __ATOMIC_RELEASE);
        kernel_display_work_request();
    }
}

int edge_drm_scanout_refresh_required(void) {
    uint64_t next_scanout_us;

    if (__atomic_load_n(&g_edge_drm_scanout_refresh_required,
                        __ATOMIC_ACQUIRE) == 0u)
        return 0;
    next_scanout_us = __atomic_load_n(
        &g_edge_drm_next_scanout_us, __ATOMIC_ACQUIRE);
    return next_scanout_us == 0u ||
           boottime_monotonic_us() >= next_scanout_us;
}

static void edge_drm_pump_deferred_internal(int redraw_cursor,
                                            int explicit_commit) {
    display_mode_t active_mode;
    edge_drm_framebuffer_t *framebuffer;
    edge_drm_buffer_t *buffer;
    edge_drm_buffer_t *tracked_buffer = 0;
    edge_drm_present_source_t present_source;
    display_rect_t present_batch[EDGE_DRM_SCANOUT_BATCH_RECTS];
    const uint8_t *storage;
    uint32_t dirty_pages[EDGE_DRM_DIRTY_PAGE_WORDS];
    uint32_t framebuffer_id;
    uint32_t page_count;
    uint32_t source_x;
    uint32_t source_y;
    uint32_t width;
    uint32_t height;
    uint32_t pitch;
    uint32_t columns;
    uint32_t rows;
    uint32_t activity_sequence;
    uint32_t present_batch_count = 0;
    int write_tracking = 0;
    int changed = 0;
    uint64_t now_us;

    (void)edge_drm_mode_available(&active_mode, 0);
    now_us = boottime_monotonic_us();
    edge_drm_pump_flip_events(now_us);
    if (!explicit_commit && g_edge_drm_next_scanout_us &&
        now_us < g_edge_drm_next_scanout_us)
        return;
    if (__atomic_test_and_set(
            &g_edge_drm_scanout_guard, __ATOMIC_ACQUIRE))
        return;
    if (!explicit_commit) {
        uint64_t verify_us = __atomic_load_n(
            &g_edge_drm_explicit_verify_us, __ATOMIC_ACQUIRE);

        if (verify_us && now_us < verify_us) {
            g_edge_drm_next_scanout_us = verify_us;
            goto out;
        }
        if (verify_us)
            (void)__atomic_compare_exchange_n(
                &g_edge_drm_explicit_verify_us, &verify_us, 0u, 0,
                __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE);
    }
    activity_sequence = __atomic_load_n(
        &g_edge_drm_scanout_activity_sequence, __ATOMIC_ACQUIRE);
    /*
     * The scheduler invokes this helper at ordinary blocking and yield
     * points. Keep the common not-due path free of framebuffer-sized stack
     * initialization: server workloads may execute millions of such waits
     * between display refreshes. The snapshot is only consumed after the
     * cadence and backend checks above have selected the direct scanout path.
     */
    memset(dirty_pages, 0, sizeof(dirty_pages));

    edge_drm_lock();
    if (!explicit_commit && g_edge_drm_next_scanout_us &&
        now_us < g_edge_drm_next_scanout_us) {
        edge_drm_unlock();
        goto out;
    }
    framebuffer_id = g_edge_drm_active_fb;
    framebuffer = g_edge_drm_crtc_active ?
        edge_drm_framebuffer_locked(framebuffer_id, 0) : 0;
    if (!framebuffer || framebuffer->virtgpu ||
        framebuffer->buffer_index >= EDGE_DRM_BUFFER_COUNT) {
        g_edge_drm_next_scanout_us = 0;
        edge_drm_unlock();
        goto out;
    }
    buffer = &g_edge_drm_buffers[framebuffer->buffer_index];
    buffer = edge_drm_buffer_backing_locked(buffer, 0);
    if (!buffer || !buffer->used || !buffer->mapped) {
        g_edge_drm_next_scanout_us = 0;
        edge_drm_unlock();
        goto out;
    }
    source_x = g_edge_drm_crtc_x;
    source_y = g_edge_drm_crtc_y;
    if (source_x >= buffer->width || source_y >= buffer->height) {
        g_edge_drm_next_scanout_us = 0;
        edge_drm_unlock();
        goto out;
    }
    width = edge_drm_min_u32(fb.width, buffer->width - source_x);
    height = edge_drm_min_u32(fb.height, buffer->height - source_y);
    pitch = buffer->pitch;
    storage = buffer->storage;
    page_count = buffer->page_count;
    memset(&present_source, 0, sizeof(present_source));
    present_source.data = buffer->storage;
    present_source.width = framebuffer->width;
    present_source.height = framebuffer->height;
    present_source.pitch = framebuffer->pitch;
    present_source.pixel_format = framebuffer->pixel_format;
    present_source.source_x = source_x;
    present_source.source_y = source_y;
    write_tracking = buffer->write_tracking != 0;
    if (write_tracking) {
        tracked_buffer = buffer;
        memcpy(dirty_pages, buffer->dirty_pages,
               sizeof(dirty_pages));
        memset(buffer->dirty_pages, 0,
               sizeof(buffer->dirty_pages));
        if (buffer->scanout_source_x != source_x ||
            buffer->scanout_source_y != source_y ||
            buffer->scanout_width != width ||
            buffer->scanout_height != height ||
            buffer->scanout_pitch != pitch) {
            memset(buffer->scanout_page_hash_valid, 0,
                   sizeof(buffer->scanout_page_hash_valid));
            buffer->scanout_source_x = source_x;
            buffer->scanout_source_y = source_y;
            buffer->scanout_width = width;
            buffer->scanout_height = height;
            buffer->scanout_pitch = pitch;
        }
        /*
         * Clear the damage snapshot and restore read-only write-notify PTEs
         * while holding the DRM lock. A concurrent writer can make its PTE
         * writable, but its fault then waits here and records fresh damage
         * after this snapshot is fully armed.
         */
        edge_drm_scanout_writeprotect_dirty(
            storage, dirty_pages, page_count);
    }
    edge_drm_unlock();

    /*
     * A Linux dumb buffer is a scanout object, not a one-time modeset upload.
     * Userspace writes through the shared mmap after SETCRTC and expects those
     * stores to become visible without issuing DIRTYFB or a page flip. Native
     * display hardware observes that memory directly. EdgeOS' generic KMS path
     * uses allocated backing pages, so inspect the active direct framebuffer
     * from process context at display cadence. Hash cacheable source tiles and
     * copy only changed horizontal spans into the potentially uncached display
     * aperture. This preserves 60 Hz responsiveness without continuously
     * rewriting an unchanged full screen. Virtio-gpu framebuffers retain their
     * explicit transfer and flush path and return above.
     */
    /*
     * Compare against the last pixels actually presented, not the identity of
     * the current dumb buffer. Desktop compositors may alternate equal front
     * buffers while idle; invalidating on every buffer switch turns that valid
     * page-flip pattern into a needless full-screen refresh loop.
     */
    if (g_edge_drm_scanout_source_x != source_x ||
        g_edge_drm_scanout_source_y != source_y ||
        g_edge_drm_scanout_width != width ||
        g_edge_drm_scanout_height != height ||
        g_edge_drm_scanout_pitch != pitch) {
        edge_drm_scanout_invalidate();
        edge_drm_scanout_page_invalidate();
        g_edge_drm_scanout_source_x = source_x;
        g_edge_drm_scanout_source_y = source_y;
        g_edge_drm_scanout_width = width;
        g_edge_drm_scanout_height = height;
        g_edge_drm_scanout_pitch = pitch;
    }
    if (write_tracking) {
        uint32_t changed_pages[EDGE_DRM_DIRTY_PAGE_WORDS];
        uint32_t page = 0;
        int result = 0;

        memset(changed_pages, 0, sizeof(changed_pages));
        for (page = 0; page < page_count; ++page) {
            uint64_t hash;

            if (!tracked_buffer->scanout_page_hash_valid[page] ||
                edge_drm_dirty_page_test(dirty_pages, page)) {
                tracked_buffer->scanout_page_hashes[page] =
                    edge_drm_scanout_page_hash(storage, page);
                tracked_buffer->scanout_page_hash_valid[page] = 1u;
            }
            hash = tracked_buffer->scanout_page_hashes[page];
            if (!g_edge_drm_scanout_page_hash_valid[page] ||
                g_edge_drm_scanout_page_hashes[page] != hash) {
                changed_pages[page >> 5] |=
                    1u << (page & 31u);
                changed = 1;
            }
        }
        page = 0;
        while (page < page_count) {
            uint32_t first;

            while (page < page_count &&
                   !edge_drm_dirty_page_test(changed_pages, page))
                ++page;
            if (page >= page_count) break;
            first = page++;
            while (page < page_count &&
                   edge_drm_dirty_page_test(changed_pages, page))
                ++page;
            result = edge_drm_scanout_present_page_run(
                &present_source, first, page, pitch,
                source_y, width, height,
                present_batch, &present_batch_count);
            if (result < 0) break;
        }
        edge_drm_scanout_invalidate();
        if (result < 0) {
            edge_drm_scanout_page_invalidate();
        } else {
            for (page = 0; page < page_count; ++page) {
                g_edge_drm_scanout_page_hashes[page] =
                    tracked_buffer->scanout_page_hashes[page];
                g_edge_drm_scanout_page_hash_valid[page] =
                    tracked_buffer->scanout_page_hash_valid[page];
            }
            for (; page < EDGE_DRM_MAX_BUFFER_PAGES; ++page)
                g_edge_drm_scanout_page_hash_valid[page] = 0u;
        }
        edge_drm_scanout_flush_present(
            present_batch, &present_batch_count,
            redraw_cursor, framebuffer_id);
        goto schedule;
    }
    edge_drm_scanout_page_invalidate();
    columns =
        (width + EDGE_DRM_SCANOUT_TILE_WIDTH - 1u) /
        EDGE_DRM_SCANOUT_TILE_WIDTH;
    rows =
        (height + EDGE_DRM_SCANOUT_TILE_HEIGHT - 1u) /
        EDGE_DRM_SCANOUT_TILE_HEIGHT;
    for (uint32_t row = 0; row < rows; ++row) {
        uint32_t first_changed = UINT32_MAX;
        uint32_t last_changed = 0;

        for (uint32_t column = 0; column < columns; ++column) {
            uint32_t x = column * EDGE_DRM_SCANOUT_TILE_WIDTH;
            uint32_t y = row * EDGE_DRM_SCANOUT_TILE_HEIGHT;
            uint32_t tile_width = EDGE_DRM_SCANOUT_TILE_WIDTH;
            uint32_t tile_height = EDGE_DRM_SCANOUT_TILE_HEIGHT;
            uint32_t index =
                row * EDGE_DRM_SCANOUT_TILE_COLUMNS + column;
            uint64_t hash;

            if (tile_width > width - x) tile_width = width - x;
            if (tile_height > height - y) tile_height = height - y;
            hash = edge_drm_scanout_tile_hash(
                storage, pitch, source_x + x, source_y + y,
                tile_width, tile_height);
            if (!g_edge_drm_scanout_hash_valid[index] ||
                g_edge_drm_scanout_hashes[index] != hash) {
                changed = 1;
                g_edge_drm_scanout_hashes[index] = hash;
                g_edge_drm_scanout_hash_valid[index] = 1u;
                if (first_changed == UINT32_MAX)
                    first_changed = column;
                last_changed = column;
            } else if (first_changed != UINT32_MAX) {
                if (edge_drm_scanout_queue_span(
                        &present_source, row, first_changed, last_changed,
                        width, height, present_batch,
                        &present_batch_count) < 0) {
                    for (uint32_t retry = first_changed;
                         retry <= last_changed; ++retry)
                        g_edge_drm_scanout_hash_valid[
                            row * EDGE_DRM_SCANOUT_TILE_COLUMNS + retry] =
                                0u;
                }
                first_changed = UINT32_MAX;
            }
        }
        if (first_changed != UINT32_MAX &&
            edge_drm_scanout_queue_span(
                &present_source, row, first_changed, last_changed,
                width, height, present_batch,
                &present_batch_count) < 0) {
            for (uint32_t retry = first_changed;
                 retry <= last_changed; ++retry)
                g_edge_drm_scanout_hash_valid[
                    row * EDGE_DRM_SCANOUT_TILE_COLUMNS + retry] = 0u;
        }
    }
    edge_drm_scanout_flush_present(
        present_batch, &present_batch_count,
        redraw_cursor, framebuffer_id);
schedule:
    {
        uint64_t interval_us = edge_drm_scanout_active_interval();

        if (__atomic_load_n(
                &g_edge_drm_scanout_activity_sequence, __ATOMIC_ACQUIRE) !=
            activity_sequence) {
            g_edge_drm_scanout_idle_frames = 0;
            g_edge_drm_next_scanout_us = now_us + interval_us;
        } else if (changed) {
            g_edge_drm_scanout_idle_frames = 0;
            g_edge_drm_next_scanout_us = now_us + interval_us;
        } else {
            if (g_edge_drm_scanout_idle_frames <
                EDGE_DRM_SCANOUT_IDLE_THRESHOLD)
                ++g_edge_drm_scanout_idle_frames;
            g_edge_drm_next_scanout_us =
                now_us +
                (g_edge_drm_scanout_idle_frames >=
                         EDGE_DRM_SCANOUT_IDLE_THRESHOLD ?
                     EDGE_DRM_SCANOUT_IDLE_INTERVAL_US :
                     interval_us);
        }
    }
out:
    edge_drm_scanout_unlock();
}

void edge_drm_pump_deferred(void) {
    /*
     * Device completion handling is part of the shared display worker turn.
     * Interrupt handlers only request that turn, so reap completed presents
     * before scanning for new damage. Otherwise two queued VirtIO-GPU frames
     * can occupy every persistent slot while the pending frame is repeatedly
     * replaced and userspace keeps repainting a scanout that never advances.
     */
    (void)display_backend_poll();
    edge_drm_pump_deferred_internal(1, 0);
}

static int edge_drm_present_damage(uint32_t framebuffer_id,
                                   uint32_t blob_id,
                                   int redraw_cursor) {
    edge_drm_mode_rect_t rects[
        EDGE_DRM_BLOB_CAPACITY / sizeof(edge_drm_mode_rect_t)];
    edge_drm_mode_rect_t visible[
        EDGE_DRM_BLOB_CAPACITY / sizeof(edge_drm_mode_rect_t)];
    uint8_t data[EDGE_DRM_BLOB_CAPACITY];
    uint32_t source_x;
    uint32_t source_y;
    uint32_t length = 0;
    uint32_t count;
    uint32_t visible_count = 0;
    edge_drm_present_source_t source;
    int result;

    if (!blob_id) return -EDGE_LINUX_EINVAL;
    result = edge_drm_blob_snapshot(blob_id, data, &length);
    if (result < 0 || !length ||
        length % sizeof(edge_drm_mode_rect_t))
        return -EDGE_LINUX_EINVAL;
    count = length / sizeof(edge_drm_mode_rect_t);
    memcpy(rects, data, length);

    edge_drm_lock();
    source_x = g_edge_drm_crtc_x;
    source_y = g_edge_drm_crtc_y;
    edge_drm_unlock();
    for (uint32_t index = 0; index < count; ++index) {
        int32_t x1 = rects[index].x1;
        int32_t y1 = rects[index].y1;
        int32_t x2 = rects[index].x2;
        int32_t y2 = rects[index].y2;
        int32_t source_right = (int32_t)source_x + (int32_t)fb.width;
        int32_t source_bottom = (int32_t)source_y + (int32_t)fb.height;

        if (x1 < (int32_t)source_x) x1 = (int32_t)source_x;
        if (y1 < (int32_t)source_y) y1 = (int32_t)source_y;
        if (x2 > source_right) x2 = source_right;
        if (y2 > source_bottom) y2 = source_bottom;
        if (x1 >= x2 || y1 >= y2) continue;
        x1 -= (int32_t)source_x;
        x2 -= (int32_t)source_x;
        y1 -= (int32_t)source_y;
        y2 -= (int32_t)source_y;

        visible[visible_count].x1 = (int16_t)x1;
        visible[visible_count].y1 = (int16_t)y1;
        visible[visible_count].x2 = (int16_t)x2;
        visible[visible_count].y2 = (int16_t)y2;
        ++visible_count;
    }

    /*
     * A software compositor can describe one frame as many small clips.
     * Virtio-gpu 2D presents require one transfer and one flush command per
     * rectangle, so unbounded clip submission stalls the compositor while it
     * waits for dozens of synchronous control-queue completions.  Coalesce
     * touching clips first, then use one bounding rectangle when fragmentation
     * remains high.  The extra pixel transfer is substantially cheaper than
     * the command latency and keeps input responsive during browser startup.
     */
    for (;;) {
        int merged = 0;

        for (uint32_t left = 0; left < visible_count && !merged; ++left) {
            for (uint32_t right = left + 1u; right < visible_count; ++right) {
                if (visible[left].x2 < visible[right].x1 ||
                    visible[left].x1 > visible[right].x2 ||
                    visible[left].y2 < visible[right].y1 ||
                    visible[left].y1 > visible[right].y2)
                    continue;
                if (visible[right].x1 < visible[left].x1)
                    visible[left].x1 = visible[right].x1;
                if (visible[right].y1 < visible[left].y1)
                    visible[left].y1 = visible[right].y1;
                if (visible[right].x2 > visible[left].x2)
                    visible[left].x2 = visible[right].x2;
                if (visible[right].y2 > visible[left].y2)
                    visible[left].y2 = visible[right].y2;
                visible[right] = visible[--visible_count];
                merged = 1;
                break;
            }
        }
        if (!merged) break;
    }
    if (visible_count > EDGE_DRM_DAMAGE_RECT_LIMIT) {
        for (uint32_t index = 1; index < visible_count; ++index) {
            if (visible[index].x1 < visible[0].x1)
                visible[0].x1 = visible[index].x1;
            if (visible[index].y1 < visible[0].y1)
                visible[0].y1 = visible[index].y1;
            if (visible[index].x2 > visible[0].x2)
                visible[0].x2 = visible[index].x2;
            if (visible[index].y2 > visible[0].y2)
                visible[0].y2 = visible[index].y2;
        }
        visible_count = 1u;
    }

    edge_drm_lock();
    result = edge_drm_present_source_locked(framebuffer_id, &source);
    edge_drm_unlock();
    if (result < 0) return result;
    if (!source.virtgpu_handle) {
        display_rect_t batch[EDGE_DRM_DAMAGE_RECT_LIMIT];
        uint32_t batch_count = visible_count;

        for (uint32_t index = 0; index < visible_count; ++index) {
            batch[index].x = (uint32_t)visible[index].x1;
            batch[index].y = (uint32_t)visible[index].y1;
            batch[index].width =
                (uint32_t)(visible[index].x2 - visible[index].x1);
            batch[index].height =
                (uint32_t)(visible[index].y2 - visible[index].y1);
            result = edge_drm_present_source_rect(
                &source, batch[index].x, batch[index].y,
                batch[index].width, batch[index].height, 0);
            if (result < 0) return result;
        }
        edge_drm_scanout_flush_present(
            batch, &batch_count, redraw_cursor, framebuffer_id);
    } else {
        for (uint32_t index = 0; index < visible_count; ++index) {
            result = edge_drm_present_source_rect(
                &source,
                (uint32_t)visible[index].x1,
                (uint32_t)visible[index].y1,
                (uint32_t)(visible[index].x2 - visible[index].x1),
                (uint32_t)(visible[index].y2 - visible[index].y1), 1);
            if (result < 0) return result;
        }
    }
    edge_drm_schedule_explicit_verification(boottime_monotonic_us());
    return 0;
}

static int edge_drm_present_flip(uint32_t framebuffer_id,
                                 uint32_t damage_blob_id,
                                 int redraw_cursor) {
    uint64_t started_us = boottime_monotonic_us();
    uint64_t duration_us;
    int result;

    __atomic_add_fetch(
        &g_edge_drm_runtime_stats.primary_present_calls, 1u,
        __ATOMIC_RELAXED);
    if (damage_blob_id) {
        __atomic_add_fetch(
            &g_edge_drm_runtime_stats.damage_present_calls, 1u,
            __ATOMIC_RELAXED);
        result = edge_drm_present_damage(
            framebuffer_id, damage_blob_id, redraw_cursor);
        goto out;
    }
    /*
     * EdgeOS dumb buffers are separate cacheable pages. Reuse the
     * content-aware scanout path for direct and explicit-present displays so
     * an idle compositor alternating equal buffers does not transfer the
     * complete screen on every flip. When requested, cursor composition joins
     * the same damage batch so no cursorless intermediate frame is visible.
     */
    edge_drm_scanout_activity();
    edge_drm_pump_deferred_internal(redraw_cursor, 1);
    result = 0;
out:
    duration_us = boottime_monotonic_us() - started_us;
    __atomic_add_fetch(
        &g_edge_drm_runtime_stats.present_duration_total_us,
        duration_us, __ATOMIC_RELAXED);
    edge_drm_stat_max(
        &g_edge_drm_runtime_stats.present_duration_max_us,
        duration_us);
    if (duration_us > EDGE_DRM_SCANOUT_DEFAULT_INTERVAL_US)
        __atomic_add_fetch(
            &g_edge_drm_runtime_stats.present_duration_over_16ms,
            1u, __ATOMIC_RELAXED);
    return result;
}

static void edge_drm_enqueue_flip_event_locked(
    edge_drm_client_t *client, uint64_t user_data,
    uint64_t microseconds) {
    edge_drm_event_vblank_t event;
    uint32_t tail;

    if (!client) return;
    memset(&event, 0, sizeof(event));
    event.type = EDGE_DRM_EVENT_FLIP_COMPLETE;
    event.length = sizeof(event);
    event.user_data = user_data;
    event.tv_sec = (uint32_t)(microseconds / 1000000u);
    event.tv_usec = (uint32_t)(microseconds % 1000000u);
    event.crtc_id = EDGE_DRM_CRTC_ID;
    event.sequence = ++g_edge_drm_flip_sequence;
    if (client->event_count == EDGE_DRM_EVENT_COUNT) {
        client->event_head =
            (client->event_head + 1u) % EDGE_DRM_EVENT_COUNT;
        client->event_count--;
    }
    tail = (client->event_head + client->event_count) %
        EDGE_DRM_EVENT_COUNT;
    client->events[tail] = event;
    client->event_count++;
    client->readiness_sequence++;
    __atomic_add_fetch(
        &g_edge_drm_runtime_stats.flip_events_delivered, 1u,
        __ATOMIC_RELAXED);
}

static void edge_drm_pump_flip_events(uint64_t now_us) {
    uint64_t next_due_us = 0u;

    edge_drm_lock();
    for (uint32_t index = 0; index < EDGE_DRM_CLIENT_COUNT; ++index) {
        edge_drm_client_t *client = &g_edge_drm_clients[index];

        if (!client->used || !client->flip_pending ||
            now_us < client->flip_due_us)
            continue;
        {
            uint64_t lateness_us = now_us - client->flip_due_us;

            __atomic_add_fetch(
                &g_edge_drm_runtime_stats.flip_lateness_total_us,
                lateness_us, __ATOMIC_RELAXED);
            edge_drm_stat_max(
                &g_edge_drm_runtime_stats.flip_lateness_max_us,
                lateness_us);
            if (lateness_us > EDGE_DRM_SCANOUT_DEFAULT_INTERVAL_US)
                __atomic_add_fetch(
                    &g_edge_drm_runtime_stats.flip_lateness_over_16ms,
                    1u, __ATOMIC_RELAXED);
        }
        edge_drm_enqueue_flip_event_locked(
            client, client->flip_user_data, now_us);
        client->flip_pending = 0u;
        client->flip_user_data = 0u;
        client->flip_due_us = 0u;
    }
    for (uint32_t index = 0; index < EDGE_DRM_CLIENT_COUNT; ++index) {
        const edge_drm_client_t *client = &g_edge_drm_clients[index];

        if (!client->used || !client->flip_pending ||
            !client->flip_due_us)
            continue;
        if (!next_due_us || client->flip_due_us < next_due_us)
            next_due_us = client->flip_due_us;
    }
    edge_drm_unlock();
    if (next_due_us) kernel_display_deadline_request(next_due_us);
}

static int edge_drm_queue_flip_event(uint64_t identity,
                                     uint64_t user_data,
                                     int asynchronous,
                                     uint64_t submitted_us) {
    edge_drm_client_t *client;
    uint64_t now_us = boottime_monotonic_us();
    int result = 0;

    __atomic_add_fetch(
        &g_edge_drm_runtime_stats.flip_events_requested, 1u,
        __ATOMIC_RELAXED);
    edge_drm_lock();
    client = edge_drm_client_locked(identity, 1);
    if (!client) {
        result = -EDGE_LINUX_ENOSPC;
    } else if (client->flip_pending) {
        result = -EDGE_LINUX_EBUSY;
        __atomic_add_fetch(
            &g_edge_drm_runtime_stats.flip_events_busy, 1u,
            __ATOMIC_RELAXED);
    } else if (asynchronous) {
        edge_drm_enqueue_flip_event_locked(client, user_data, now_us);
    } else {
        client->flip_pending = 1u;
        client->flip_user_data = user_data;
        /*
         * Page flips complete on a continuous display cadence. Scheduling a
         * complete interval after every submission serializes software
         * rendering time with vblank wait time and caps a fast compositor
         * below the advertised refresh rate. Keep one cadence across commits
         * so a frame submitted before the next boundary completes there.
         */
        client->flip_due_us = edge_drm_next_vblank_locked(submitted_us);
        kernel_display_deadline_request(client->flip_due_us);
    }
    edge_drm_unlock();
    return result;
}

static int64_t edge_drm_ioctl_version(
    const kernel_ioctl_request_t *request) {
    static const char fallback_name[] = "edgeos-kms";
    static const char date[] = "20260728";
    static const char fallback_description[] = "EdgeOS shared display KMS";
    static const char virtgpu_description[] = "EdgeOS VirtIO GPU KMS";
    edge_drm_version_t version;
    const char *name = edge_virtgpu_driver_name();
    const char *description;
    uint64_t description_length;
    uint64_t name_length;

    if (!name) name = fallback_name;
    description = edge_virtgpu_available() ?
        virtgpu_description : fallback_description;
    name_length = strlen(name);
    description_length = strlen(description);

    if (!request->argument ||
        edge_drm_copy_from(request, &version, request->argument,
                           sizeof(version)) < 0)
        return -EDGE_LINUX_EFAULT;
    if ((version.name_len && !version.name) ||
        (version.date_len && !version.date) ||
        (version.desc_len && !version.desc))
        return -EDGE_LINUX_EFAULT;
    if (edge_drm_copy_string(request, version.name, version.name_len,
                             name, name_length + 1u) < 0 ||
        edge_drm_copy_string(request, version.date, version.date_len,
                             date, sizeof(date)) < 0 ||
        edge_drm_copy_string(request, version.desc, version.desc_len,
                             description, description_length + 1u) < 0)
        return -EDGE_LINUX_EFAULT;
    version.version_major = 1;
    version.version_minor = 0;
    version.version_patchlevel = 0;
    version.name_len = name_length;
    version.date_len = sizeof(date) - 1u;
    version.desc_len = description_length;
    return edge_drm_copy_to(request, request->argument, &version,
                            sizeof(version)) < 0 ?
        -EDGE_LINUX_EFAULT : 0;
}

static int64_t edge_drm_ioctl_unique(
    const kernel_ioctl_request_t *request) {
    static const char unique_name[] = "platform:edgeos-display";
    edge_drm_unique_t unique;

    if (!request->argument ||
        edge_drm_copy_from(request, &unique, request->argument,
                           sizeof(unique)) < 0)
        return -EDGE_LINUX_EFAULT;
    if (unique.unique_len && !unique.unique) return -EDGE_LINUX_EFAULT;
    if (edge_drm_copy_string(request, unique.unique, unique.unique_len,
                             unique_name, sizeof(unique_name)) < 0)
        return -EDGE_LINUX_EFAULT;
    unique.unique_len = sizeof(unique_name) - 1u;
    return edge_drm_copy_to(request, request->argument, &unique,
                            sizeof(unique)) < 0 ?
        -EDGE_LINUX_EFAULT : 0;
}

static int64_t edge_drm_ioctl_get_cap(
    const kernel_ioctl_request_t *request) {
    edge_drm_get_cap_t capability;

    if (!request->argument ||
        edge_drm_copy_from(request, &capability, request->argument,
                           sizeof(capability)) < 0)
        return -EDGE_LINUX_EFAULT;
    switch (capability.capability) {
        case EDGE_DRM_CAP_DUMB_BUFFER:
        case EDGE_DRM_CAP_TIMESTAMP_MONOTONIC:
        case EDGE_DRM_CAP_CRTC_IN_VBLANK_EVENT:
            capability.value = 1u;
            break;
        case EDGE_DRM_CAP_DUMB_PREFERRED_DEPTH:
            capability.value = 24u;
            break;
        case EDGE_DRM_CAP_DUMB_PREFER_SHADOW:
            capability.value = display_backend_requires_present() ? 1u : 0u;
            break;
        case EDGE_DRM_CAP_PRIME:
            capability.value = EDGE_DRM_PRIME_CAP_IMPORT |
                EDGE_DRM_PRIME_CAP_EXPORT;
            break;
        case EDGE_DRM_CAP_CURSOR_WIDTH:
        case EDGE_DRM_CAP_CURSOR_HEIGHT:
            capability.value = 64u;
            break;
        case EDGE_DRM_CAP_ADDFB2_MODIFIERS:
        case EDGE_DRM_CAP_SYNCOBJ:
        case EDGE_DRM_CAP_SYNCOBJ_TIMELINE:
            capability.value = 0u;
            break;
        default:
            return -EDGE_LINUX_EINVAL;
    }
    return edge_drm_copy_to(request, request->argument, &capability,
                            sizeof(capability)) < 0 ?
        -EDGE_LINUX_EFAULT : 0;
}

static int64_t edge_drm_ioctl_set_client_cap(
    uint64_t identity, const kernel_ioctl_request_t *request) {
    edge_drm_set_client_cap_t capability;
    edge_drm_client_t *client;
    int64_t result = 0;

    if (!request->argument ||
        edge_drm_copy_from(request, &capability, request->argument,
                           sizeof(capability)) < 0)
        return -EDGE_LINUX_EFAULT;
    if (capability.value > 1u) return -EDGE_LINUX_EINVAL;
    edge_drm_lock();
    client = edge_drm_client_locked(identity, 1);
    if (!client) {
        result = -EDGE_LINUX_ENOSPC;
    } else if (capability.capability ==
               EDGE_DRM_CLIENT_CAP_UNIVERSAL_PLANES) {
        client->universal_planes = (uint8_t)capability.value;
    } else if (capability.capability ==
               EDGE_DRM_CLIENT_CAP_ASPECT_RATIO) {
        client->aspect_ratio = (uint8_t)capability.value;
    } else if (capability.capability ==
               EDGE_DRM_CLIENT_CAP_ATOMIC) {
        client->atomic = (uint8_t)capability.value;
        if (capability.value) client->universal_planes = 1u;
    } else if (capability.capability != EDGE_DRM_CLIENT_CAP_STEREO_3D &&
               capability.capability != EDGE_DRM_CLIENT_CAP_ATOMIC) {
        result = -EDGE_LINUX_EINVAL;
    }
    edge_drm_unlock();
    return result;
}

static int64_t edge_drm_ioctl_resources(
    const kernel_ioctl_request_t *request) {
    edge_drm_card_res_t resources;
    display_mode_t mode;
    uint32_t framebuffer_ids[EDGE_DRM_FRAMEBUFFER_COUNT];
    uint32_t framebuffer_count = 0;
    uint32_t count;
    int available;

    if (!request->argument ||
        edge_drm_copy_from(request, &resources, request->argument,
                           sizeof(resources)) < 0)
        return -EDGE_LINUX_EFAULT;
    available = edge_drm_mode_available(&mode, 0);
    edge_drm_lock();
    for (uint32_t index = 0; index < EDGE_DRM_FRAMEBUFFER_COUNT; ++index)
        if (g_edge_drm_framebuffers[index].used &&
            g_edge_drm_framebuffers[index].user_live)
            framebuffer_ids[framebuffer_count++] =
                g_edge_drm_framebuffers[index].id;
    edge_drm_unlock();

    count = edge_drm_min_u32(resources.count_fbs, framebuffer_count);
    if (count && (!resources.fb_id_ptr ||
        edge_drm_copy_to(request, resources.fb_id_ptr, framebuffer_ids,
                         (uint64_t)count * sizeof(uint32_t)) < 0))
        return -EDGE_LINUX_EFAULT;
    if (available && resources.count_crtcs && resources.crtc_id_ptr) {
        uint32_t id = EDGE_DRM_CRTC_ID;
        if (edge_drm_copy_to(request, resources.crtc_id_ptr, &id,
                             sizeof(id)) < 0)
            return -EDGE_LINUX_EFAULT;
    }
    if (available && resources.count_connectors &&
        resources.connector_id_ptr) {
        uint32_t id = EDGE_DRM_CONNECTOR_ID;
        if (edge_drm_copy_to(request, resources.connector_id_ptr, &id,
                             sizeof(id)) < 0)
            return -EDGE_LINUX_EFAULT;
    }
    if (available && resources.count_encoders && resources.encoder_id_ptr) {
        uint32_t id = EDGE_DRM_ENCODER_ID;
        if (edge_drm_copy_to(request, resources.encoder_id_ptr, &id,
                             sizeof(id)) < 0)
            return -EDGE_LINUX_EFAULT;
    }
    resources.count_fbs = framebuffer_count;
    resources.count_crtcs = available ? 1u : 0u;
    resources.count_connectors = available ? 1u : 0u;
    resources.count_encoders = available ? 1u : 0u;
    resources.min_width = available ? 64u : 0u;
    resources.min_height = available ? 64u : 0u;
    resources.max_width = available ?
        (mode.width > EDGE_DRM_MAX_WIDTH ? mode.width :
                                           EDGE_DRM_MAX_WIDTH) : 0u;
    resources.max_height = available ?
        (mode.height > EDGE_DRM_MAX_HEIGHT ? mode.height :
                                            EDGE_DRM_MAX_HEIGHT) : 0u;
    return edge_drm_copy_to(request, request->argument, &resources,
                            sizeof(resources)) < 0 ?
        -EDGE_LINUX_EFAULT : 0;
}

static int64_t edge_drm_ioctl_get_crtc(
    const kernel_ioctl_request_t *request) {
    edge_drm_crtc_t crtc;
    display_mode_t current;

    if (!request->argument ||
        edge_drm_copy_from(request, &crtc, request->argument,
                           sizeof(crtc)) < 0)
        return -EDGE_LINUX_EFAULT;
    if (crtc.crtc_id != EDGE_DRM_CRTC_ID)
        return -EDGE_LINUX_ENOENT;
    if (!edge_drm_mode_available(&current, 0))
        return -EDGE_LINUX_ENODEV;
    crtc.set_connectors_ptr = 0;
    crtc.count_connectors = 0;
    edge_drm_lock();
    crtc.fb_id = g_edge_drm_active_fb;
    crtc.x = g_edge_drm_crtc_x;
    crtc.y = g_edge_drm_crtc_y;
    crtc.mode_valid = g_edge_drm_crtc_active ? 1u : 0u;
    edge_drm_unlock();
    crtc.gamma_size = 0;
    edge_drm_fill_mode(&crtc.mode, &current, 1);
    return edge_drm_copy_to(request, request->argument, &crtc,
                            sizeof(crtc)) < 0 ?
        -EDGE_LINUX_EFAULT : 0;
}

static int edge_drm_validate_framebuffer_mode_locked(
    const edge_drm_framebuffer_t *framebuffer, uint32_t x, uint32_t y,
    uint32_t width, uint32_t height) {
    if (!framebuffer || !width || !height ||
        x > framebuffer->width || y > framebuffer->height ||
        width > framebuffer->width - x ||
        height > framebuffer->height - y)
        return -EDGE_LINUX_EINVAL;
    return 0;
}

static int64_t edge_drm_ioctl_set_crtc(
    uint64_t identity, const kernel_ioctl_request_t *request) {
    edge_drm_crtc_t crtc;
    edge_drm_cursor_state_t previous_cursor;
    edge_drm_framebuffer_t framebuffer;
    display_mode_t current;
    display_mode_t requested_mode;
    uint32_t previous_primary_fb;
    uint32_t connector = 0;
    int result;

    if (!request->argument ||
        edge_drm_copy_from(request, &crtc, request->argument,
                           sizeof(crtc)) < 0)
        return -EDGE_LINUX_EFAULT;
    if (crtc.crtc_id != EDGE_DRM_CRTC_ID)
        return -EDGE_LINUX_ENOENT;
    edge_drm_lock();
    result = edge_drm_require_master_locked(identity);
    edge_drm_unlock();
    if (result < 0) return result;
    if (!crtc.fb_id || !crtc.mode_valid) {
        edge_drm_lock();
        previous_cursor = g_edge_drm_cursor;
        previous_primary_fb = g_edge_drm_active_fb;
        memset(&g_edge_drm_cursor, 0, sizeof(g_edge_drm_cursor));
        edge_drm_mode_blob_unreference_locked(g_edge_drm_mode_blob_id);
        g_edge_drm_active_fb = 0;
        g_edge_drm_crtc_x = 0;
        g_edge_drm_crtc_y = 0;
        g_edge_drm_mode_blob_id = 0;
        g_edge_drm_crtc_active = 0;
        edge_drm_publish_scanout_state_locked();
        edge_drm_unlock();
        (void)edge_drm_cursor_restore(
            &previous_cursor, previous_primary_fb);
        fb_console_set_drm_owned(0);
        (void)edge_virtgpu_framebuffer_reset();
        return 0;
    }
    if (crtc.count_connectors != 1u || !crtc.set_connectors_ptr ||
        edge_drm_copy_from(request, &connector, crtc.set_connectors_ptr,
                           sizeof(connector)) < 0)
        return -EDGE_LINUX_EFAULT;
    if (connector != EDGE_DRM_CONNECTOR_ID)
        return -EDGE_LINUX_ENOENT;

    edge_drm_lock();
    {
        edge_drm_framebuffer_t *found =
            edge_drm_framebuffer_locked(crtc.fb_id, 0);
        if (!found) {
            edge_drm_unlock();
            return -EDGE_LINUX_ENOENT;
        }
        framebuffer = *found;
        result = edge_drm_validate_framebuffer_mode_locked(
            found, crtc.x, crtc.y,
            crtc.mode.hdisplay, crtc.mode.vdisplay);
    }
    edge_drm_unlock();
    if (result < 0) return result;
    if (!edge_drm_mode_available(&current, 0))
        return -EDGE_LINUX_ENODEV;
    edge_drm_display_mode_from_modeinfo(&crtc.mode, &requested_mode);
    if (requested_mode.width != current.width ||
        requested_mode.height != current.height ||
        requested_mode.refresh_millihz != current.refresh_millihz) {
        if (requested_mode.width > EDGE_DRM_MAX_WIDTH ||
            requested_mode.height > EDGE_DRM_MAX_HEIGHT ||
            display_backend_set_mode(&requested_mode) < 0)
            return -EDGE_LINUX_EINVAL;
        __atomic_store_n(&g_edge_drm_scanout_interval_us,
                         display_mode_frame_interval_us(&requested_mode),
                         __ATOMIC_RELEASE);
    }
    if (framebuffer.width < crtc.x + crtc.mode.hdisplay ||
        framebuffer.height < crtc.y + crtc.mode.vdisplay)
        return -EDGE_LINUX_EINVAL;
    edge_drm_lock();
    previous_cursor = g_edge_drm_cursor;
    previous_primary_fb = g_edge_drm_active_fb;
    edge_drm_unlock();
    (void)edge_drm_cursor_restore(
        &previous_cursor, previous_primary_fb);
    edge_drm_lock();
    edge_drm_mode_blob_unreference_locked(g_edge_drm_mode_blob_id);
    g_edge_drm_active_fb = crtc.fb_id;
    g_edge_drm_crtc_x = crtc.x;
    g_edge_drm_crtc_y = crtc.y;
    g_edge_drm_mode_blob_id = EDGE_DRM_CURRENT_MODE_BLOB_ID;
    g_edge_drm_crtc_active = 1u;
    edge_drm_publish_scanout_state_locked();
    edge_drm_unlock();
    fb_console_set_drm_owned(1);
    result = edge_drm_present_full(crtc.fb_id);
    if (result < 0) return result;
    return previous_cursor.fb_id ?
        edge_drm_cursor_draw(&previous_cursor) : 0;
}

static int64_t edge_drm_ioctl_encoder(
    const kernel_ioctl_request_t *request) {
    edge_drm_encoder_t encoder;

    if (!request->argument ||
        edge_drm_copy_from(request, &encoder, request->argument,
                           sizeof(encoder)) < 0)
        return -EDGE_LINUX_EFAULT;
    if (encoder.encoder_id != EDGE_DRM_ENCODER_ID)
        return -EDGE_LINUX_ENOENT;
    encoder.encoder_type = EDGE_DRM_MODE_ENCODER_VIRTUAL;
    encoder.crtc_id = EDGE_DRM_CRTC_ID;
    encoder.possible_crtcs = 1u;
    encoder.possible_clones = 0u;
    return edge_drm_copy_to(request, request->argument, &encoder,
                            sizeof(encoder)) < 0 ?
        -EDGE_LINUX_EFAULT : 0;
}

static int64_t edge_drm_ioctl_connector(
    uint64_t identity, const kernel_ioctl_request_t *request) {
    edge_drm_connector_t connector;
    edge_drm_modeinfo_t modes[EDGE_DRM_MODE_COUNT];
    uint32_t property_ids[4];
    uint64_t property_values[4];
    uint32_t property_count = 0;
    uint32_t mode_count;
    uint32_t count;
    uint8_t edid[DISPLAY_MODE_EDID_MAX_BYTES];
    display_mode_t edid_modes[DISPLAY_MODE_EDID_MAX_MODES];
    uint32_t edid_size;
    uint32_t width_mm = 0u;
    uint32_t height_mm = 0u;

    if (!request->argument ||
        edge_drm_copy_from(request, &connector, request->argument,
                           sizeof(connector)) < 0)
        return -EDGE_LINUX_EFAULT;
    if (connector.connector_id != EDGE_DRM_CONNECTOR_ID)
        return -EDGE_LINUX_ENOENT;
    mode_count = edge_drm_collect_modes(modes);
    if (!mode_count) return -EDGE_LINUX_ENODEV;
    edid_size = display_backend_get_edid(edid, sizeof(edid));
    if (edid_size > sizeof(edid))
        edid_size = sizeof(edid);
    if (edid_size)
        (void)display_edid_parse(edid, edid_size, edid_modes,
            DISPLAY_MODE_EDID_MAX_MODES, &width_mm, &height_mm);
    count = edge_drm_min_u32(connector.count_modes, mode_count);
    if (count && (!connector.modes_ptr ||
        edge_drm_copy_to(request, connector.modes_ptr, modes,
                         (uint64_t)count * sizeof(modes[0])) < 0))
        return -EDGE_LINUX_EFAULT;
    if (connector.count_encoders && connector.encoders_ptr) {
        uint32_t id = EDGE_DRM_ENCODER_ID;
        if (edge_drm_copy_to(request, connector.encoders_ptr, &id,
                             sizeof(id)) < 0)
            return -EDGE_LINUX_EFAULT;
    }
    edge_drm_lock();
    if (edge_drm_client_atomic_locked(identity)) {
        property_ids[property_count] = EDGE_DRM_PROP_CONNECTOR_CRTC_ID;
        property_values[property_count++] =
            g_edge_drm_crtc_active ? EDGE_DRM_CRTC_ID : 0u;
        property_ids[property_count] = EDGE_DRM_PROP_LINK_STATUS;
        property_values[property_count++] = 0u;
    }
    property_ids[property_count] = EDGE_DRM_PROP_NON_DESKTOP;
    property_values[property_count++] = 0u;
    if (edid_size) {
        property_ids[property_count] = EDGE_DRM_PROP_EDID;
        property_values[property_count++] = EDGE_DRM_EDID_BLOB_ID;
    }
    edge_drm_unlock();
    count = edge_drm_min_u32(connector.count_props, property_count);
    if (count && (!connector.props_ptr || !connector.prop_values_ptr ||
        edge_drm_copy_to(request, connector.props_ptr, property_ids,
                         (uint64_t)count * sizeof(property_ids[0])) < 0 ||
        edge_drm_copy_to(request, connector.prop_values_ptr, property_values,
                         (uint64_t)count * sizeof(property_values[0])) < 0))
        return -EDGE_LINUX_EFAULT;
    connector.count_modes = mode_count;
    connector.count_props = property_count;
    connector.count_encoders = 1u;
    connector.encoder_id = EDGE_DRM_ENCODER_ID;
    connector.connector_type = EDGE_DRM_MODE_CONNECTOR_VIRTUAL;
    connector.connector_type_id = 1u;
    connector.connection = EDGE_DRM_MODE_CONNECTED;
    connector.mm_width = width_mm ? width_mm :
        (modes[0].hdisplay * 254u + 480u) / 960u;
    connector.mm_height = height_mm ? height_mm :
        (modes[0].vdisplay * 254u + 480u) / 960u;
    connector.subpixel = EDGE_DRM_MODE_SUBPIXEL_UNKNOWN;
    connector.pad = 0;
    return edge_drm_copy_to(request, request->argument, &connector,
                            sizeof(connector)) < 0 ?
        -EDGE_LINUX_EFAULT : 0;
}

static void edge_drm_property_name_copy(char destination[32],
                                        const char *source) {
    uint32_t index = 0;

    memset(destination, 0, 32u);
    if (!source) return;
    while (source[index] && index + 1u < 32u) {
        destination[index] = source[index];
        ++index;
    }
}

static int64_t edge_drm_ioctl_get_property(
    const kernel_ioctl_request_t *request) {
    edge_drm_get_property_t property;
    edge_drm_property_spec_t spec;
    uint32_t count;

    if (!request->argument ||
        edge_drm_copy_from(request, &property, request->argument,
                           sizeof(property)) < 0)
        return -EDGE_LINUX_EFAULT;
    if (!edge_drm_property_spec(property.prop_id, &spec))
        return -EDGE_LINUX_ENOENT;
    count = edge_drm_min_u32(property.count_values, spec.value_count);
    if (count && (!property.values_ptr ||
        edge_drm_copy_to(request, property.values_ptr, spec.values,
                         (uint64_t)count * sizeof(spec.values[0])) < 0))
        return -EDGE_LINUX_EFAULT;
    count = edge_drm_min_u32(property.count_enum_blobs, spec.enum_count);
    if (count && (!property.enum_blob_ptr ||
        edge_drm_copy_to(request, property.enum_blob_ptr, spec.enums,
                         (uint64_t)count * sizeof(spec.enums[0])) < 0))
        return -EDGE_LINUX_EFAULT;
    property.flags = spec.flags;
    property.count_values = spec.value_count;
    property.count_enum_blobs = spec.enum_count;
    edge_drm_property_name_copy(property.name, spec.name);
    return edge_drm_copy_to(request, request->argument, &property,
                            sizeof(property)) < 0 ?
        -EDGE_LINUX_EFAULT : 0;
}

static int edge_drm_object_properties_locked(
    uint32_t object_id, uint32_t object_type,
    const display_mode_t *mode, uint32_t *ids, uint64_t *values,
    uint32_t *count_out) {
    edge_drm_framebuffer_t *framebuffer = 0;
    uint32_t count = 0;

    if (!ids || !values || !count_out) return -EDGE_LINUX_EINVAL;
    if (object_id == EDGE_DRM_CONNECTOR_ID &&
        object_type == EDGE_DRM_MODE_OBJECT_CONNECTOR) {
        ids[count] = EDGE_DRM_PROP_CONNECTOR_CRTC_ID;
        values[count++] = g_edge_drm_crtc_active ? EDGE_DRM_CRTC_ID : 0u;
        ids[count] = EDGE_DRM_PROP_LINK_STATUS;
        values[count++] = 0u;
        ids[count] = EDGE_DRM_PROP_NON_DESKTOP;
        values[count++] = 0u;
        if (display_backend_get_edid(0, 0u)) {
            ids[count] = EDGE_DRM_PROP_EDID;
            values[count++] = EDGE_DRM_EDID_BLOB_ID;
        }
    } else if (object_id == EDGE_DRM_CRTC_ID &&
               object_type == EDGE_DRM_MODE_OBJECT_CRTC) {
        ids[count] = EDGE_DRM_PROP_CRTC_MODE_ID;
        values[count++] = g_edge_drm_crtc_active ?
            (g_edge_drm_mode_blob_id ?
                g_edge_drm_mode_blob_id :
                EDGE_DRM_CURRENT_MODE_BLOB_ID) : 0u;
        ids[count] = EDGE_DRM_PROP_CRTC_ACTIVE;
        values[count++] = g_edge_drm_crtc_active ? 1u : 0u;
    } else if ((object_id == EDGE_DRM_PRIMARY_PLANE_ID ||
                object_id == EDGE_DRM_CURSOR_PLANE_ID) &&
               object_type == EDGE_DRM_MODE_OBJECT_PLANE) {
        uint32_t framebuffer_id = object_id == EDGE_DRM_PRIMARY_PLANE_ID ?
            g_edge_drm_active_fb : g_edge_drm_cursor.fb_id;
        uint32_t crtc_id = object_id == EDGE_DRM_PRIMARY_PLANE_ID ?
            (g_edge_drm_active_fb ? EDGE_DRM_CRTC_ID : 0u) :
            g_edge_drm_cursor.crtc_id;

        if (framebuffer_id)
            framebuffer = edge_drm_framebuffer_locked(framebuffer_id, 0);
        ids[count] = EDGE_DRM_PROP_PLANE_FB_ID;
        values[count++] = framebuffer_id;
        ids[count] = EDGE_DRM_PROP_PLANE_CRTC_ID;
        values[count++] = crtc_id;
        ids[count] = EDGE_DRM_PROP_PLANE_SRC_X;
        values[count++] = object_id == EDGE_DRM_PRIMARY_PLANE_ID ?
            (uint64_t)g_edge_drm_crtc_x << 16 : g_edge_drm_cursor.src_x;
        ids[count] = EDGE_DRM_PROP_PLANE_SRC_Y;
        values[count++] = object_id == EDGE_DRM_PRIMARY_PLANE_ID ?
            (uint64_t)g_edge_drm_crtc_y << 16 : g_edge_drm_cursor.src_y;
        ids[count] = EDGE_DRM_PROP_PLANE_SRC_W;
        values[count++] = object_id == EDGE_DRM_PRIMARY_PLANE_ID ?
            (framebuffer ? (uint64_t)mode->width << 16 : 0u) :
            g_edge_drm_cursor.src_w;
        ids[count] = EDGE_DRM_PROP_PLANE_SRC_H;
        values[count++] = object_id == EDGE_DRM_PRIMARY_PLANE_ID ?
            (framebuffer ? (uint64_t)mode->height << 16 : 0u) :
            g_edge_drm_cursor.src_h;
        ids[count] = EDGE_DRM_PROP_PLANE_CRTC_X;
        values[count++] = object_id == EDGE_DRM_PRIMARY_PLANE_ID ?
            0u : (uint64_t)(int64_t)g_edge_drm_cursor.crtc_x;
        ids[count] = EDGE_DRM_PROP_PLANE_CRTC_Y;
        values[count++] = object_id == EDGE_DRM_PRIMARY_PLANE_ID ?
            0u : (uint64_t)(int64_t)g_edge_drm_cursor.crtc_y;
        ids[count] = EDGE_DRM_PROP_PLANE_CRTC_W;
        values[count++] = object_id == EDGE_DRM_PRIMARY_PLANE_ID ?
            (framebuffer ? mode->width : 0u) : g_edge_drm_cursor.crtc_w;
        ids[count] = EDGE_DRM_PROP_PLANE_CRTC_H;
        values[count++] = object_id == EDGE_DRM_PRIMARY_PLANE_ID ?
            (framebuffer ? mode->height : 0u) : g_edge_drm_cursor.crtc_h;
        ids[count] = EDGE_DRM_PROP_PLANE_TYPE;
        values[count++] = object_id == EDGE_DRM_PRIMARY_PLANE_ID ? 1u : 2u;
        ids[count] = EDGE_DRM_PROP_PLANE_IN_FORMATS;
        values[count++] = EDGE_DRM_IN_FORMATS_BLOB_ID;
        if (object_id == EDGE_DRM_PRIMARY_PLANE_ID) {
            ids[count] = EDGE_DRM_PROP_PLANE_FB_DAMAGE_CLIPS;
            values[count++] = 0u;
        }
    } else {
        return -EDGE_LINUX_ENOENT;
    }
    *count_out = count;
    return 0;
}

static int64_t edge_drm_ioctl_object_properties(
    uint64_t identity, const kernel_ioctl_request_t *request) {
    edge_drm_obj_get_properties_t object;
    display_mode_t mode;
    uint32_t ids[16];
    uint64_t values[16];
    uint32_t count = 0;
    uint32_t copied;
    int atomic_client;
    int result;

    if (!request->argument ||
        edge_drm_copy_from(request, &object, request->argument,
                           sizeof(object)) < 0)
        return -EDGE_LINUX_EFAULT;
    if (!edge_drm_mode_available(&mode, 0))
        return -EDGE_LINUX_ENODEV;
    edge_drm_lock();
    atomic_client = edge_drm_client_atomic_locked(identity);
    result = edge_drm_object_properties_locked(
        object.obj_id, object.obj_type, &mode, ids, values, &count);
    if (result == 0 && !atomic_client) {
        uint32_t visible = 0;
        for (uint32_t index = 0; index < count; ++index) {
            if (!edge_drm_property_visible(ids[index], 0)) continue;
            ids[visible] = ids[index];
            values[visible++] = values[index];
        }
        count = visible;
    }
    edge_drm_unlock();
    if (result < 0) return result;
    copied = edge_drm_min_u32(object.count_props, count);
    if (copied && (!object.props_ptr || !object.prop_values_ptr ||
        edge_drm_copy_to(request, object.props_ptr, ids,
                         (uint64_t)copied * sizeof(ids[0])) < 0 ||
        edge_drm_copy_to(request, object.prop_values_ptr, values,
                         (uint64_t)copied * sizeof(values[0])) < 0))
        return -EDGE_LINUX_EFAULT;
    object.count_props = count;
    return edge_drm_copy_to(request, request->argument, &object,
                            sizeof(object)) < 0 ?
        -EDGE_LINUX_EFAULT : 0;
}

typedef struct {
    uint32_t version;
    uint32_t flags;
    uint32_t count_formats;
    uint32_t formats_offset;
    uint32_t count_modifiers;
    uint32_t modifiers_offset;
    uint32_t formats[2];
    struct {
        uint64_t formats;
        uint32_t offset;
        uint32_t pad;
        uint64_t modifier;
    } linear;
} edge_drm_format_blob_t;

_Static_assert(sizeof(edge_drm_format_blob_t) == 56,
               "Linux DRM format modifier blob layout mismatch");

static int edge_drm_blob_snapshot(uint32_t id, uint8_t *data,
                                  uint32_t *length) {
    display_mode_t mode;

    if (!data || !length) return -EDGE_LINUX_EINVAL;
    if (id == EDGE_DRM_CURRENT_MODE_BLOB_ID) {
        edge_drm_modeinfo_t current;
        if (!edge_drm_mode_available(&mode, 0))
            return -EDGE_LINUX_ENODEV;
        edge_drm_fill_mode(&current, &mode, 1);
        memcpy(data, &current, sizeof(current));
        *length = sizeof(current);
        return 0;
    }
    if (id == EDGE_DRM_IN_FORMATS_BLOB_ID) {
        edge_drm_format_blob_t formats;
        memset(&formats, 0, sizeof(formats));
        formats.version = 1u;
        formats.count_formats = 2u;
        formats.formats_offset = offsetof(edge_drm_format_blob_t, formats);
        formats.count_modifiers = 1u;
        formats.modifiers_offset =
            offsetof(edge_drm_format_blob_t, linear);
        formats.formats[0] = EDGE_DRM_FORMAT_XRGB8888;
        formats.formats[1] = EDGE_DRM_FORMAT_ARGB8888;
        formats.linear.formats = 3u;
        formats.linear.modifier = 0u;
        memcpy(data, &formats, sizeof(formats));
        *length = sizeof(formats);
        return 0;
    }
    if (id == EDGE_DRM_EDID_BLOB_ID) {
        uint32_t size = display_backend_get_edid(
            data, EDGE_DRM_BLOB_CAPACITY);
        if (!size)
            return -EDGE_LINUX_ENOENT;
        if (size > EDGE_DRM_BLOB_CAPACITY)
            size = EDGE_DRM_BLOB_CAPACITY;
        *length = size;
        return 0;
    }
    edge_drm_lock();
    {
        edge_drm_blob_t *blob = edge_drm_blob_locked(id);
        if (!blob) {
            edge_drm_unlock();
            return -EDGE_LINUX_ENOENT;
        }
        memcpy(data, blob->data, blob->length);
        *length = blob->length;
    }
    edge_drm_unlock();
    return 0;
}

static int64_t edge_drm_ioctl_get_blob(
    const kernel_ioctl_request_t *request) {
    edge_drm_get_blob_t command;
    uint8_t data[EDGE_DRM_BLOB_CAPACITY];
    uint32_t length;
    uint32_t copied;
    int result;

    if (!request->argument ||
        edge_drm_copy_from(request, &command, request->argument,
                           sizeof(command)) < 0)
        return -EDGE_LINUX_EFAULT;
    result = edge_drm_blob_snapshot(command.blob_id, data, &length);
    if (result < 0) return result;
    copied = edge_drm_min_u32(command.length, length);
    if (copied && (!command.data ||
        edge_drm_copy_to(request, command.data, data, copied) < 0))
        return -EDGE_LINUX_EFAULT;
    command.length = length;
    return edge_drm_copy_to(request, request->argument, &command,
                            sizeof(command)) < 0 ?
        -EDGE_LINUX_EFAULT : 0;
}

static int64_t edge_drm_ioctl_create_blob(
    uint64_t identity, const kernel_ioctl_request_t *request) {
    edge_drm_create_blob_t command;
    uint8_t data[EDGE_DRM_BLOB_CAPACITY];
    edge_drm_blob_t *blob = 0;

    if (!request->argument ||
        edge_drm_copy_from(request, &command, request->argument,
                           sizeof(command)) < 0)
        return -EDGE_LINUX_EFAULT;
    if (!command.length || command.length > sizeof(data) || !command.data)
        return -EDGE_LINUX_EINVAL;
    if (edge_drm_copy_from(request, data, command.data, command.length) < 0)
        return -EDGE_LINUX_EFAULT;
    edge_drm_lock();
    if (!edge_drm_client_atomic_locked(identity)) {
        edge_drm_unlock();
        return -EDGE_LINUX_EOPNOTSUPP;
    }
    for (uint32_t index = 0; index < EDGE_DRM_BLOB_COUNT; ++index)
        if (!g_edge_drm_blobs[index].used) {
            blob = &g_edge_drm_blobs[index];
            break;
        }
    if (!blob) {
        edge_drm_unlock();
        return -EDGE_LINUX_ENOSPC;
    }
    memset(blob, 0, sizeof(*blob));
    blob->used = 1u;
    blob->user_live = 1u;
    blob->owner = identity;
    blob->id = g_edge_drm_next_blob_id++;
    if (blob->id < EDGE_DRM_BLOB_ID_BASE)
        blob->id = g_edge_drm_next_blob_id = EDGE_DRM_BLOB_ID_BASE;
    blob->length = command.length;
    memcpy(blob->data, data, command.length);
    command.blob_id = blob->id;
    edge_drm_unlock();
    return edge_drm_copy_to(request, request->argument, &command,
                            sizeof(command)) < 0 ?
        -EDGE_LINUX_EFAULT : 0;
}

static int64_t edge_drm_ioctl_destroy_blob(
    uint64_t identity, const kernel_ioctl_request_t *request) {
    edge_drm_destroy_blob_t command;
    edge_drm_blob_t *blob;

    if (!request->argument ||
        edge_drm_copy_from(request, &command, request->argument,
                           sizeof(command)) < 0)
        return -EDGE_LINUX_EFAULT;
    edge_drm_lock();
    blob = edge_drm_blob_locked(command.blob_id);
    if (!blob || !blob->user_live || blob->owner != identity) {
        edge_drm_unlock();
        return -EDGE_LINUX_ENOENT;
    }
    blob->user_live = 0u;
    edge_drm_blob_maybe_release_locked(blob);
    edge_drm_unlock();
    return 0;
}

static int64_t edge_drm_ioctl_list_lessees(
    uint64_t identity, const kernel_ioctl_request_t *request) {
    edge_drm_mode_list_lessees_t list;

    (void)identity;

    if (!request->argument ||
        edge_drm_copy_from(request, &list, request->argument,
                           sizeof(list)) < 0)
        return -EDGE_LINUX_EFAULT;
    /* There are no DRM lessees until lease creation is implemented. */
    list.count_lessees = 0u;
    list.pad = 0u;
    return edge_drm_copy_to(request, request->argument, &list,
                            sizeof(list)) < 0 ?
        -EDGE_LINUX_EFAULT : 0;
}

static int64_t edge_drm_ioctl_set_property(
    uint64_t identity, const kernel_ioctl_request_t *request,
    int connector_layout) {
    edge_drm_obj_set_property_t object;
    edge_drm_connector_set_property_t connector;
    uint32_t object_id;
    uint32_t property_id;
    uint64_t value;
    int result;

    memset(&object, 0, sizeof(object));
    if (connector_layout) {
        if (!request->argument ||
            edge_drm_copy_from(request, &connector, request->argument,
                               sizeof(connector)) < 0)
            return -EDGE_LINUX_EFAULT;
        object_id = connector.connector_id;
        property_id = connector.prop_id;
        value = connector.value;
        if (object_id != EDGE_DRM_CONNECTOR_ID)
            return -EDGE_LINUX_ENOENT;
    } else {
        if (!request->argument ||
            edge_drm_copy_from(request, &object, request->argument,
                               sizeof(object)) < 0)
            return -EDGE_LINUX_EFAULT;
        object_id = object.obj_id;
        property_id = object.prop_id;
        value = object.value;
        if ((object_id == EDGE_DRM_CONNECTOR_ID &&
             object.obj_type != EDGE_DRM_MODE_OBJECT_CONNECTOR) ||
            (object_id == EDGE_DRM_CRTC_ID &&
             object.obj_type != EDGE_DRM_MODE_OBJECT_CRTC) ||
            ((object_id == EDGE_DRM_PRIMARY_PLANE_ID ||
              object_id == EDGE_DRM_CURSOR_PLANE_ID) &&
             object.obj_type != EDGE_DRM_MODE_OBJECT_PLANE))
            return -EDGE_LINUX_ENOENT;
    }
    edge_drm_lock();
    result = edge_drm_require_master_locked(identity);
    edge_drm_unlock();
    if (result < 0) return result;
    if (object_id == EDGE_DRM_CONNECTOR_ID &&
        property_id == EDGE_DRM_PROP_LINK_STATUS && value == 0u)
        return 0;
    return -EDGE_LINUX_EINVAL;
}

static int64_t edge_drm_ioctl_create_dumb(
    uint64_t identity, const kernel_ioctl_request_t *request) {
    edge_drm_create_dumb_t create;
    edge_drm_buffer_t *buffer = 0;
    uint32_t bytes_per_pixel;
    uint32_t pitch;
    uint32_t page_count;
    uint8_t *storage;
    uint64_t raw_pitch;
    uint64_t size;

    if (!request->argument ||
        edge_drm_copy_from(request, &create, request->argument,
                           sizeof(create)) < 0)
        return -EDGE_LINUX_EFAULT;
    if (!create.width || !create.height || !create.bpp ||
        create.bpp > 64u ||
        create.width > EDGE_DRM_MAX_BUFFER_DIMENSION ||
        create.height > EDGE_DRM_MAX_BUFFER_DIMENSION)
        return -EDGE_LINUX_EINVAL;
    bytes_per_pixel = (create.bpp + 7u) / 8u;
    raw_pitch = (uint64_t)create.width * bytes_per_pixel;
    if (!raw_pitch ||
        raw_pitch > UINT32_MAX - (EDGE_DRM_PITCH_ALIGN - 1u))
        return -EDGE_LINUX_EINVAL;
    pitch = edge_drm_align_up((uint32_t)raw_pitch,
                              EDGE_DRM_PITCH_ALIGN);
    size = (uint64_t)pitch * create.height;
    if (!size || size > UINT32_MAX - (EDGE_DRM_PAGE_SIZE - 1u))
        return -EDGE_LINUX_EINVAL;
    size = edge_drm_align_up((uint32_t)size, EDGE_DRM_PAGE_SIZE);
    if (size > EDGE_DRM_BUFFER_CAPACITY)
        return -EDGE_LINUX_ENOSPC;
    page_count = (uint32_t)(size / EDGE_DRM_PAGE_SIZE);
    storage = arch_vm_alloc_pages(page_count);
    if (!storage) return -EDGE_LINUX_ENOMEM;

    edge_drm_lock();
    if (!edge_drm_client_locked(identity, 1)) {
        edge_drm_unlock();
        for (uint32_t page = 0; page < page_count; ++page)
            arch_vm_free_page(
                storage + (uint64_t)page * EDGE_DRM_PAGE_SIZE);
        return -EDGE_LINUX_ENOSPC;
    }
    for (uint32_t index = 0; index < EDGE_DRM_BUFFER_COUNT; ++index)
        if (!g_edge_drm_buffers[index].used) {
            buffer = &g_edge_drm_buffers[index];
            break;
        }
    if (!buffer) {
        edge_drm_unlock();
        for (uint32_t page = 0; page < page_count; ++page)
            arch_vm_free_page(
                storage + (uint64_t)page * EDGE_DRM_PAGE_SIZE);
        return -EDGE_LINUX_ENOSPC;
    }
    memset(buffer, 0, sizeof(*buffer));
    buffer->used = 1;
    buffer->handle_open = 1;
    buffer->backing_index = UINT32_MAX;
    buffer->handle = g_edge_drm_next_handle++;
    if (!buffer->handle) buffer->handle = g_edge_drm_next_handle++;
    buffer->width = create.width;
    buffer->height = create.height;
    buffer->pitch = pitch;
    buffer->size = (uint32_t)size;
    buffer->page_count = page_count;
    buffer->owner = identity;
    buffer->map_offset = (uint64_t)buffer->handle << 32;
    buffer->storage = storage;
    memset(buffer->storage, 0, buffer->size);
    create.handle = buffer->handle;
    create.pitch = buffer->pitch;
    create.size = buffer->size;
    edge_drm_unlock();
    return edge_drm_copy_to(request, request->argument, &create,
                            sizeof(create)) < 0 ?
        -EDGE_LINUX_EFAULT : 0;
}

static int64_t edge_drm_ioctl_map_dumb(
    uint64_t identity, const kernel_ioctl_request_t *request) {
    edge_drm_map_dumb_t map;
    edge_drm_buffer_t *buffer;

    if (!request->argument ||
        edge_drm_copy_from(request, &map, request->argument,
                           sizeof(map)) < 0)
        return -EDGE_LINUX_EFAULT;
    edge_drm_lock();
    buffer = edge_drm_buffer_handle_locked(identity, map.handle, 0);
    if (buffer) {
        buffer->map_authorized = 1;
        map.offset = buffer->map_offset;
    }
    edge_drm_unlock();
    if (!buffer) return -EDGE_LINUX_ENOENT;
    return edge_drm_copy_to(request, request->argument, &map,
                            sizeof(map)) < 0 ?
        -EDGE_LINUX_EFAULT : 0;
}

static int64_t edge_drm_close_handle(uint64_t identity, uint32_t handle) {
    edge_drm_buffer_t *buffer;
    uint32_t index;

    edge_drm_lock();
    buffer = edge_drm_buffer_handle_locked(identity, handle, &index);
    if (!buffer) {
        edge_drm_unlock();
        return -EDGE_LINUX_ENOENT;
    }
    buffer->handle_open = 0;
    edge_drm_buffer_maybe_release_locked(index);
    edge_drm_unlock();
    return 0;
}

static edge_drm_buffer_t *edge_drm_prime_buffer_locked(
    int32_t object_id, uint32_t *index_out) {
    uint32_t index;

    if (object_id < (int32_t)EDGE_DRM_PRIME_OBJECT_BASE)
        return 0;
    index = (uint32_t)object_id - EDGE_DRM_PRIME_OBJECT_BASE;
    if (index >= EDGE_DRM_BUFFER_COUNT ||
        !g_edge_drm_buffers[index].used ||
        g_edge_drm_buffers[index].backing_index != UINT32_MAX)
        return 0;
    if (index_out) *index_out = index;
    return &g_edge_drm_buffers[index];
}

int edge_drm_prime_retain(int32_t object_id) {
    edge_drm_buffer_t *buffer;
    int result;

    if (object_id < (int32_t)EDGE_DRM_PRIME_OBJECT_BASE)
        return edge_virtgpu_prime_retain(object_id);
    edge_drm_lock();
    buffer = edge_drm_prime_buffer_locked(object_id, 0);
    if (!buffer) {
        result = -EDGE_LINUX_EBADF;
    } else if (buffer->prime_refs == UINT32_MAX) {
        result = -EDGE_LINUX_EOVERFLOW;
    } else {
        ++buffer->prime_refs;
        result = 0;
    }
    edge_drm_unlock();
    return result;
}

void edge_drm_prime_release(int32_t object_id) {
    edge_drm_buffer_t *buffer;
    uint32_t index;

    if (object_id < (int32_t)EDGE_DRM_PRIME_OBJECT_BASE) {
        edge_virtgpu_prime_release(object_id);
        return;
    }
    edge_drm_lock();
    buffer = edge_drm_prime_buffer_locked(object_id, &index);
    if (buffer && buffer->prime_refs) {
        --buffer->prime_refs;
        edge_drm_buffer_maybe_release_locked(index);
    }
    edge_drm_unlock();
}

static int64_t edge_drm_ioctl_prime_handle_to_fd(
    uint64_t identity, const kernel_ioctl_request_t *request) {
    edge_drm_prime_handle_t command;
    edge_drm_buffer_t *backing;
    edge_drm_buffer_t *buffer;
    uint32_t index;
    int32_t object_id;
    int descriptor;

    if (!request->argument ||
        edge_drm_copy_from(request, &command, request->argument,
                           sizeof(command)) < 0)
        return -EDGE_LINUX_EFAULT;
    if (command.flags & ~EDGE_DRM_PRIME_FLAGS)
        return -EDGE_LINUX_EINVAL;
    edge_drm_lock();
    buffer = edge_drm_buffer_handle_locked(identity, command.handle, &index);
    if (!buffer) {
        edge_drm_unlock();
        return -EDGE_LINUX_ENOENT;
    }
    backing = edge_drm_buffer_backing_locked(buffer, &index);
    if (!backing) {
        edge_drm_unlock();
        return -EDGE_LINUX_EIO;
    }
    if (backing->prime_refs == UINT32_MAX) {
        edge_drm_unlock();
        return -EDGE_LINUX_EOVERFLOW;
    }
    ++backing->prime_refs;
    object_id = (int32_t)(EDGE_DRM_PRIME_OBJECT_BASE + index);
    edge_drm_unlock();

    descriptor = kernel_anonymous_fd_install_descriptor(
        KERNEL_ANONYMOUS_FD_PRIME, object_id,
        command.flags & EDGE_DRM_PRIME_RDWR,
        command.flags & EDGE_DRM_PRIME_CLOEXEC);
    if (descriptor < 0) {
        edge_drm_prime_release(object_id);
        return descriptor;
    }
    command.fd = descriptor;
    if (edge_drm_copy_to(request, request->argument, &command,
                         sizeof(command)) < 0) {
        (void)kernel_fd_close(descriptor);
        return -EDGE_LINUX_EFAULT;
    }
    return 0;
}

static int64_t edge_drm_ioctl_prime_fd_to_handle(
    uint64_t identity, const kernel_ioctl_request_t *request) {
    edge_drm_prime_handle_t command;
    edge_drm_buffer_t *alias = 0;
    edge_drm_buffer_t *buffer;
    uint32_t backing_index;
    int32_t object_id;

    if (!request->argument ||
        edge_drm_copy_from(request, &command, request->argument,
                           sizeof(command)) < 0)
        return -EDGE_LINUX_EFAULT;
    object_id = kernel_anonymous_fd_descriptor_object_id(
        command.fd, KERNEL_ANONYMOUS_FD_PRIME);
    if (object_id < 0) return object_id;
    if (object_id < (int32_t)EDGE_DRM_PRIME_OBJECT_BASE)
        return edge_virtgpu_ioctl(identity, request);

    edge_drm_lock();
    buffer = edge_drm_prime_buffer_locked(object_id, &backing_index);
    if (!buffer) {
        edge_drm_unlock();
        return -EDGE_LINUX_EBADF;
    }
    for (uint32_t index = 0; index < EDGE_DRM_BUFFER_COUNT; ++index) {
        edge_drm_buffer_t *candidate = &g_edge_drm_buffers[index];
        uint32_t candidate_backing;

        if (!candidate->used || candidate->owner != identity ||
            !candidate->handle_open)
            continue;
        candidate_backing = candidate->backing_index == UINT32_MAX ?
            index : candidate->backing_index;
        if (candidate_backing == backing_index) {
            alias = candidate;
            break;
        }
    }
    if (!alias) {
        for (uint32_t index = 0; index < EDGE_DRM_BUFFER_COUNT; ++index)
            if (!g_edge_drm_buffers[index].used) {
                alias = &g_edge_drm_buffers[index];
                break;
            }
        if (!alias || buffer->alias_refs == UINT32_MAX) {
            edge_drm_unlock();
            return alias ? -EDGE_LINUX_EOVERFLOW : -EDGE_LINUX_ENOSPC;
        }
        memset(alias, 0, sizeof(*alias));
        alias->used = 1u;
        alias->handle_open = 1u;
        alias->backing_index = backing_index;
        alias->handle = g_edge_drm_next_handle++;
        if (!alias->handle)
            alias->handle = g_edge_drm_next_handle++;
        alias->width = buffer->width;
        alias->height = buffer->height;
        alias->pitch = buffer->pitch;
        alias->size = buffer->size;
        alias->page_count = buffer->page_count;
        alias->owner = identity;
        alias->map_offset = (uint64_t)alias->handle << 32;
        alias->storage = buffer->storage;
        ++buffer->alias_refs;
    }
    command.handle = alias->handle;
    edge_drm_unlock();
    return edge_drm_copy_to(request, request->argument, &command,
                            sizeof(command)) < 0 ?
        -EDGE_LINUX_EFAULT : 0;
}

static int64_t edge_drm_add_framebuffer(
    uint64_t identity, uint32_t handle, uint32_t width, uint32_t height,
    uint32_t pitch, uint32_t pixel_format, uint32_t depth, uint32_t bpp,
    uint32_t *framebuffer_id) {
    edge_drm_buffer_t *buffer;
    edge_drm_framebuffer_t *framebuffer = 0;
    edge_virtgpu_framebuffer_info_t virtgpu_info;
    uint32_t buffer_index;
    int virtgpu = 0;

    if (!framebuffer_id || !width || !height || bpp != 32u ||
        (pixel_format != EDGE_DRM_FORMAT_XRGB8888 &&
         pixel_format != EDGE_DRM_FORMAT_ARGB8888))
        return -EDGE_LINUX_EINVAL;
    edge_drm_lock();
    buffer = edge_drm_buffer_handle_locked(identity, handle, &buffer_index);
    if (buffer && (width > buffer->width || height > buffer->height ||
                   pitch != buffer->pitch ||
                   (uint64_t)pitch * height > buffer->size)) {
        edge_drm_unlock();
        return -EDGE_LINUX_EINVAL;
    }
    edge_drm_unlock();

    if (!buffer) {
        if (!edge_virtgpu_framebuffer_available() ||
            edge_virtgpu_framebuffer_acquire(
                identity, handle, &virtgpu_info) < 0)
            return -EDGE_LINUX_EINVAL;
        if (width > virtgpu_info.width ||
            height > virtgpu_info.height ||
            pitch != virtgpu_info.stride ||
            (uint64_t)pitch * height > virtgpu_info.size) {
            edge_virtgpu_framebuffer_release(identity, handle);
            return -EDGE_LINUX_EINVAL;
        }
        virtgpu = 1;
        buffer_index = UINT32_MAX;
    }

    edge_drm_lock();
    if (!virtgpu) {
        buffer = edge_drm_buffer_handle_locked(
            identity, handle, &buffer_index);
        if (!buffer || width > buffer->width ||
            height > buffer->height || pitch != buffer->pitch ||
            (uint64_t)pitch * height > buffer->size) {
            edge_drm_unlock();
            return -EDGE_LINUX_EINVAL;
        }
    }
    for (uint32_t index = 0; index < EDGE_DRM_FRAMEBUFFER_COUNT; ++index)
        if (!g_edge_drm_framebuffers[index].used) {
            framebuffer = &g_edge_drm_framebuffers[index];
            break;
        }
    if (!framebuffer) {
        edge_drm_unlock();
        if (virtgpu)
            edge_virtgpu_framebuffer_release(identity, handle);
        return -EDGE_LINUX_ENOSPC;
    }
    memset(framebuffer, 0, sizeof(*framebuffer));
    framebuffer->used = 1;
    framebuffer->virtgpu = virtgpu ? 1u : 0u;
    framebuffer->user_live = 1u;
    framebuffer->id = g_edge_drm_next_fb_id++;
    if (framebuffer->id < EDGE_DRM_FB_ID_BASE)
        framebuffer->id = g_edge_drm_next_fb_id = EDGE_DRM_FB_ID_BASE;
    framebuffer->buffer_index = buffer_index;
    framebuffer->virtgpu_handle = virtgpu ? handle : 0u;
    framebuffer->width = width;
    framebuffer->height = height;
    framebuffer->pitch = pitch;
    framebuffer->pixel_format = pixel_format;
    framebuffer->depth = depth;
    framebuffer->bpp = bpp;
    framebuffer->owner = identity;
    *framebuffer_id = framebuffer->id;
    edge_drm_unlock();
    return 0;
}

static int64_t edge_drm_ioctl_addfb(
    uint64_t identity, const kernel_ioctl_request_t *request) {
    edge_drm_fb_cmd_t command;
    int64_t result;

    if (!request->argument ||
        edge_drm_copy_from(request, &command, request->argument,
                           sizeof(command)) < 0)
        return -EDGE_LINUX_EFAULT;
    if (command.depth != 24u && command.depth != 32u)
        return -EDGE_LINUX_EINVAL;
    result = edge_drm_add_framebuffer(
        identity, command.handle, command.width, command.height,
        command.pitch, command.depth == 32u ?
            EDGE_DRM_FORMAT_ARGB8888 : EDGE_DRM_FORMAT_XRGB8888,
        command.depth, command.bpp, &command.fb_id);
    if (result < 0) return result;
    return edge_drm_copy_to(request, request->argument, &command,
                            sizeof(command)) < 0 ?
        -EDGE_LINUX_EFAULT : 0;
}

static int64_t edge_drm_ioctl_addfb2(
    uint64_t identity, const kernel_ioctl_request_t *request) {
    edge_drm_fb_cmd2_t command;
    int64_t result;

    if (!request->argument ||
        edge_drm_copy_from(request, &command, request->argument,
                           sizeof(command)) < 0)
        return -EDGE_LINUX_EFAULT;
    if (command.flags || command.handles[1] || command.handles[2] ||
        command.handles[3] || command.pitches[1] || command.pitches[2] ||
        command.pitches[3] || command.offsets[0] || command.offsets[1] ||
        command.offsets[2] || command.offsets[3] || command.modifier[0] ||
        command.modifier[1] || command.modifier[2] || command.modifier[3])
        return -EDGE_LINUX_EINVAL;
    result = edge_drm_add_framebuffer(
        identity, command.handles[0], command.width, command.height,
        command.pitches[0], command.pixel_format,
        command.pixel_format == EDGE_DRM_FORMAT_ARGB8888 ? 32u : 24u,
        32u, &command.fb_id);
    if (result < 0) return result;
    return edge_drm_copy_to(request, request->argument, &command,
                            sizeof(command)) < 0 ?
        -EDGE_LINUX_EFAULT : 0;
}

static int64_t edge_drm_ioctl_getfb(
    const kernel_ioctl_request_t *request) {
    edge_drm_fb_cmd_t command;
    edge_drm_framebuffer_t *framebuffer;
    edge_drm_buffer_t *buffer;

    if (!request->argument ||
        edge_drm_copy_from(request, &command, request->argument,
                           sizeof(command)) < 0)
        return -EDGE_LINUX_EFAULT;
    edge_drm_lock();
    framebuffer = edge_drm_framebuffer_locked(command.fb_id, 0);
    if (!framebuffer) {
        edge_drm_unlock();
        return -EDGE_LINUX_ENOENT;
    }
    command.width = framebuffer->width;
    command.height = framebuffer->height;
    command.pitch = framebuffer->pitch;
    command.bpp = framebuffer->bpp;
    command.depth = framebuffer->depth;
    if (framebuffer->virtgpu) {
        command.handle = framebuffer->virtgpu_handle;
    } else {
        if (framebuffer->buffer_index >= EDGE_DRM_BUFFER_COUNT) {
            edge_drm_unlock();
            return -EDGE_LINUX_ENOENT;
        }
        buffer = &g_edge_drm_buffers[framebuffer->buffer_index];
        command.handle = buffer->handle_open ? buffer->handle : 0u;
    }
    edge_drm_unlock();
    return edge_drm_copy_to(request, request->argument, &command,
                            sizeof(command)) < 0 ?
        -EDGE_LINUX_EFAULT : 0;
}

static int64_t edge_drm_ioctl_rmfb(
    uint64_t identity, const kernel_ioctl_request_t *request) {
    edge_drm_cursor_state_t previous_cursor;
    edge_drm_framebuffer_t *framebuffer;
    uint32_t framebuffer_id;
    uint32_t framebuffer_index;
    uint32_t buffer_index;
    uint32_t previous_primary_fb;
    uint32_t virtgpu_handle;
    int released_active = 0;
    int released_cursor = 0;
    int virtgpu;

    if (!request->argument ||
        edge_drm_copy_from(request, &framebuffer_id, request->argument,
                           sizeof(framebuffer_id)) < 0)
        return -EDGE_LINUX_EFAULT;
    edge_drm_lock();
    framebuffer = edge_drm_framebuffer_locked(
        framebuffer_id, &framebuffer_index);
    if (!framebuffer || framebuffer->owner != identity) {
        edge_drm_unlock();
        return -EDGE_LINUX_ENOENT;
    }
    buffer_index = framebuffer->buffer_index;
    virtgpu_handle = framebuffer->virtgpu_handle;
    virtgpu = framebuffer->virtgpu;
    previous_cursor = g_edge_drm_cursor;
    previous_primary_fb = g_edge_drm_active_fb;
    if (g_edge_drm_cursor.fb_id == framebuffer_id) {
        memset(&g_edge_drm_cursor, 0, sizeof(g_edge_drm_cursor));
        released_cursor = 1;
    }
    memset(&g_edge_drm_framebuffers[framebuffer_index], 0,
           sizeof(g_edge_drm_framebuffers[framebuffer_index]));
    if (g_edge_drm_active_fb == framebuffer_id) {
        g_edge_drm_active_fb = 0;
        g_edge_drm_crtc_active = 0;
        memset(&g_edge_drm_cursor, 0, sizeof(g_edge_drm_cursor));
        released_active = 1;
    }
    edge_drm_publish_scanout_state_locked();
    if (!virtgpu)
        edge_drm_buffer_maybe_release_locked(buffer_index);
    edge_drm_unlock();
    if (released_cursor && !released_active)
        (void)edge_drm_cursor_restore(
            &previous_cursor, previous_primary_fb);
    if (released_active) fb_console_set_drm_owned(0);
    if (virtgpu)
        edge_virtgpu_framebuffer_release(identity, virtgpu_handle);
    return 0;
}

static int64_t edge_drm_ioctl_closefb(
    uint64_t identity, const kernel_ioctl_request_t *request) {
    edge_drm_closefb_t command;
    edge_drm_framebuffer_t *framebuffer;
    uint64_t virtgpu_owners[EDGE_DRM_FRAMEBUFFER_COUNT];
    uint32_t virtgpu_handles[EDGE_DRM_FRAMEBUFFER_COUNT];
    uint32_t virtgpu_count;

    if (!request->argument ||
        edge_drm_copy_from(request, &command, request->argument,
                           sizeof(command)) < 0)
        return -EDGE_LINUX_EFAULT;
    if (command.pad) return -EDGE_LINUX_EINVAL;
    edge_drm_lock();
    framebuffer = edge_drm_framebuffer_locked(command.fb_id, 0);
    if (!framebuffer || !framebuffer->user_live ||
        framebuffer->owner != identity) {
        edge_drm_unlock();
        return -EDGE_LINUX_ENOENT;
    }
    framebuffer->user_live = 0u;
    virtgpu_count = edge_drm_detached_framebuffers_release_locked(
        virtgpu_owners, virtgpu_handles, EDGE_DRM_FRAMEBUFFER_COUNT);
    edge_drm_unlock();
    for (uint32_t index = 0; index < virtgpu_count; ++index)
        edge_virtgpu_framebuffer_release(
            virtgpu_owners[index], virtgpu_handles[index]);
    return 0;
}

static int64_t edge_drm_ioctl_page_flip(
    uint64_t identity, const kernel_ioctl_request_t *request) {
    edge_drm_cursor_state_t cursor;
    edge_drm_page_flip_t flip;
    uint64_t submitted_us;
    int result;

    if (!request->argument ||
        edge_drm_copy_from(request, &flip, request->argument,
                           sizeof(flip)) < 0)
        return -EDGE_LINUX_EFAULT;
    if (flip.crtc_id != EDGE_DRM_CRTC_ID ||
        flip.reserved ||
        (flip.flags & ~(EDGE_DRM_MODE_PAGE_FLIP_EVENT |
                        EDGE_DRM_MODE_PAGE_FLIP_ASYNC)))
        return -EDGE_LINUX_EINVAL;
    submitted_us = boottime_monotonic_us();
    edge_drm_lock();
    result = edge_drm_require_master_locked(identity);
    if (result == 0 &&
        !edge_drm_framebuffer_locked(flip.fb_id, 0))
        result = -EDGE_LINUX_ENOENT;
    cursor = g_edge_drm_cursor;
    edge_drm_unlock();
    if (result < 0) return result;
    edge_drm_lock();
    g_edge_drm_active_fb = flip.fb_id;
    edge_drm_publish_scanout_state_locked();
    edge_drm_unlock();
    result = edge_drm_present_flip(flip.fb_id, 0u, cursor.fb_id != 0u);
    if (result < 0) return result;
    if (flip.flags & EDGE_DRM_MODE_PAGE_FLIP_EVENT) {
        result = edge_drm_queue_flip_event(
            identity, flip.user_data,
            (flip.flags & EDGE_DRM_MODE_PAGE_FLIP_ASYNC) != 0,
            submitted_us);
        if (result < 0) return result;
    }
    return 0;
}

static int64_t edge_drm_ioctl_dirtyfb(
    const kernel_ioctl_request_t *request) {
    edge_drm_dirty_fb_t dirty;
    edge_drm_clip_rect_t clip;
    uint32_t active;

    if (!request->argument ||
        edge_drm_copy_from(request, &dirty, request->argument,
                           sizeof(dirty)) < 0)
        return -EDGE_LINUX_EFAULT;
    if (dirty.flags || dirty.color || dirty.num_clips > 256u ||
        (dirty.num_clips && !dirty.clips_ptr))
        return -EDGE_LINUX_EINVAL;
    edge_drm_lock();
    active = g_edge_drm_active_fb;
    edge_drm_unlock();
    if (dirty.fb_id != active) return 0;
    if (!dirty.num_clips)
        return edge_drm_present_full(dirty.fb_id);
    for (uint32_t index = 0; index < dirty.num_clips; ++index) {
        if (edge_drm_copy_from(
                request, &clip,
                dirty.clips_ptr + (uint64_t)index * sizeof(clip),
                sizeof(clip)) < 0)
            return -EDGE_LINUX_EFAULT;
        if (clip.x2 <= clip.x1 || clip.y2 <= clip.y1) continue;
        if (edge_drm_present_rect(
                dirty.fb_id, clip.x1, clip.y1,
                (uint32_t)clip.x2 - clip.x1,
                (uint32_t)clip.y2 - clip.y1) < 0)
            return -EDGE_LINUX_EINVAL;
    }
    return 0;
}

static int64_t edge_drm_ioctl_plane_resources(
    const kernel_ioctl_request_t *request) {
    static const uint32_t plane_ids[] = {
        EDGE_DRM_PRIMARY_PLANE_ID, EDGE_DRM_CURSOR_PLANE_ID,
    };
    edge_drm_plane_res_t resources;
    uint32_t count;

    if (!request->argument ||
        edge_drm_copy_from(request, &resources, request->argument,
                           sizeof(resources)) < 0)
        return -EDGE_LINUX_EFAULT;
    count = edge_drm_min_u32(
        resources.count_planes,
        sizeof(plane_ids) / sizeof(plane_ids[0]));
    if (count && resources.plane_id_ptr) {
        if (edge_drm_copy_to(request, resources.plane_id_ptr, plane_ids,
                             (uint64_t)count * sizeof(plane_ids[0])) < 0)
            return -EDGE_LINUX_EFAULT;
    }
    resources.count_planes = sizeof(plane_ids) / sizeof(plane_ids[0]);
    resources.pad = 0;
    return edge_drm_copy_to(request, request->argument, &resources,
                            sizeof(resources)) < 0 ?
        -EDGE_LINUX_EFAULT : 0;
}

static int64_t edge_drm_ioctl_get_plane(
    const kernel_ioctl_request_t *request) {
    static const uint32_t primary_formats[] = {
        EDGE_DRM_FORMAT_XRGB8888, EDGE_DRM_FORMAT_ARGB8888,
    };
    static const uint32_t cursor_formats[] = {
        EDGE_DRM_FORMAT_ARGB8888,
    };
    const uint32_t *formats;
    uint32_t format_count;
    edge_drm_plane_t plane;
    uint32_t count;

    if (!request->argument ||
        edge_drm_copy_from(request, &plane, request->argument,
                           sizeof(plane)) < 0)
        return -EDGE_LINUX_EFAULT;
    if (plane.plane_id != EDGE_DRM_PRIMARY_PLANE_ID &&
        plane.plane_id != EDGE_DRM_CURSOR_PLANE_ID)
        return -EDGE_LINUX_ENOENT;
    if (plane.plane_id == EDGE_DRM_CURSOR_PLANE_ID) {
        formats = cursor_formats;
        format_count = sizeof(cursor_formats) / sizeof(cursor_formats[0]);
    } else {
        formats = primary_formats;
        format_count = sizeof(primary_formats) / sizeof(primary_formats[0]);
    }
    count = edge_drm_min_u32(
        plane.count_format_types, format_count);
    if (count && (!plane.format_type_ptr ||
        edge_drm_copy_to(request, plane.format_type_ptr, formats,
                         (uint64_t)count * sizeof(formats[0])) < 0))
        return -EDGE_LINUX_EFAULT;
    edge_drm_lock();
    if (plane.plane_id == EDGE_DRM_CURSOR_PLANE_ID) {
        plane.crtc_id = g_edge_drm_cursor.crtc_id;
        plane.fb_id = g_edge_drm_cursor.fb_id;
    } else {
        plane.crtc_id = g_edge_drm_active_fb ? EDGE_DRM_CRTC_ID : 0u;
        plane.fb_id = g_edge_drm_active_fb;
    }
    edge_drm_unlock();
    plane.possible_crtcs = 1u;
    plane.gamma_size = 0;
    plane.count_format_types = format_count;
    return edge_drm_copy_to(request, request->argument, &plane,
                            sizeof(plane)) < 0 ?
        -EDGE_LINUX_EFAULT : 0;
}

static int64_t edge_drm_ioctl_set_plane(
    uint64_t identity, const kernel_ioctl_request_t *request) {
    edge_drm_set_plane_t plane;
    edge_drm_cursor_state_t previous_cursor;
    edge_drm_cursor_state_t next_cursor;
    uint32_t primary_fb_id;
    int result;

    if (!request->argument ||
        edge_drm_copy_from(request, &plane, request->argument,
                           sizeof(plane)) < 0)
        return -EDGE_LINUX_EFAULT;
    if (plane.plane_id != EDGE_DRM_PRIMARY_PLANE_ID &&
        plane.plane_id != EDGE_DRM_CURSOR_PLANE_ID)
        return -EDGE_LINUX_ENOENT;
    edge_drm_lock();
    result = edge_drm_require_master_locked(identity);
    edge_drm_unlock();
    if (result < 0) return result;
    if (plane.plane_id == EDGE_DRM_CURSOR_PLANE_ID) {
        edge_drm_lock();
        previous_cursor = g_edge_drm_cursor;
        primary_fb_id = g_edge_drm_active_fb;
        edge_drm_unlock();
        if (!plane.crtc_id && !plane.fb_id) {
            edge_drm_cursor_state_t disabled_cursor = {0};

            (void)edge_drm_cursor_transition(
                &previous_cursor, &disabled_cursor, primary_fb_id);
            edge_drm_lock();
            memset(&g_edge_drm_cursor, 0, sizeof(g_edge_drm_cursor));
            edge_drm_unlock();
            return 0;
        }
        if (plane.crtc_id != EDGE_DRM_CRTC_ID || !plane.fb_id ||
            plane.flags || (plane.src_x & 0xffffu) ||
            (plane.src_y & 0xffffu) || (plane.src_w & 0xffffu) ||
            (plane.src_h & 0xffffu) || !plane.crtc_w || !plane.crtc_h ||
            (plane.src_w >> 16) != plane.crtc_w ||
            (plane.src_h >> 16) != plane.crtc_h ||
            plane.crtc_w > EDGE_DRM_CURSOR_MAX_WIDTH ||
            plane.crtc_h > EDGE_DRM_CURSOR_MAX_HEIGHT)
            return -EDGE_LINUX_EINVAL;
        edge_drm_lock();
        {
            edge_drm_framebuffer_t *framebuffer =
                edge_drm_framebuffer_locked(plane.fb_id, 0);
            if (!framebuffer || framebuffer->virtgpu ||
                framebuffer->pixel_format != EDGE_DRM_FORMAT_ARGB8888 ||
                (plane.src_x >> 16) > framebuffer->width ||
                (plane.src_y >> 16) > framebuffer->height ||
                plane.crtc_w >
                    framebuffer->width - (plane.src_x >> 16) ||
                plane.crtc_h >
                    framebuffer->height - (plane.src_y >> 16)) {
                edge_drm_unlock();
                return -EDGE_LINUX_EINVAL;
            }
        }
        edge_drm_unlock();
        memset(&next_cursor, 0, sizeof(next_cursor));
        next_cursor.fb_id = plane.fb_id;
        next_cursor.crtc_id = plane.crtc_id;
        next_cursor.src_x = plane.src_x;
        next_cursor.src_y = plane.src_y;
        next_cursor.src_w = plane.src_w;
        next_cursor.src_h = plane.src_h;
        next_cursor.crtc_x = plane.crtc_x;
        next_cursor.crtc_y = plane.crtc_y;
        next_cursor.crtc_w = plane.crtc_w;
        next_cursor.crtc_h = plane.crtc_h;
        edge_drm_lock();
        g_edge_drm_cursor = next_cursor;
        edge_drm_unlock();
        return edge_drm_cursor_transition(
            &previous_cursor, &next_cursor, primary_fb_id);
    }
    if (!plane.crtc_id && !plane.fb_id) {
        edge_drm_lock();
        previous_cursor = g_edge_drm_cursor;
        primary_fb_id = g_edge_drm_active_fb;
        memset(&g_edge_drm_cursor, 0, sizeof(g_edge_drm_cursor));
        g_edge_drm_active_fb = 0;
        g_edge_drm_crtc_x = 0;
        g_edge_drm_crtc_y = 0;
        g_edge_drm_crtc_active = 0;
        edge_drm_publish_scanout_state_locked();
        edge_drm_unlock();
        (void)edge_drm_cursor_restore(
            &previous_cursor, primary_fb_id);
        fb_console_set_drm_owned(0);
        return 0;
    }
    if (plane.crtc_id != EDGE_DRM_CRTC_ID || !plane.fb_id ||
        plane.flags || plane.crtc_x != 0 || plane.crtc_y != 0 ||
        plane.src_x != 0 || plane.src_y != 0 ||
        (plane.src_w >> 16) != plane.crtc_w ||
        (plane.src_h >> 16) != plane.crtc_h ||
        plane.crtc_w != fb.width || plane.crtc_h != fb.height)
        return -EDGE_LINUX_EINVAL;
    edge_drm_lock();
    if (!edge_drm_framebuffer_locked(plane.fb_id, 0)) {
        edge_drm_unlock();
        return -EDGE_LINUX_ENOENT;
    }
    previous_cursor = g_edge_drm_cursor;
    primary_fb_id = g_edge_drm_active_fb;
    edge_drm_unlock();
    (void)edge_drm_cursor_restore(
        &previous_cursor, primary_fb_id);
    edge_drm_lock();
    g_edge_drm_active_fb = plane.fb_id;
    g_edge_drm_crtc_x = 0;
    g_edge_drm_crtc_y = 0;
    edge_drm_publish_scanout_state_locked();
    edge_drm_unlock();
    result = edge_drm_present_full(plane.fb_id);
    if (result < 0) return result;
    return previous_cursor.fb_id ?
        edge_drm_cursor_draw(&previous_cursor) : 0;
}

static void edge_drm_atomic_state_locked(
    edge_drm_atomic_state_t *state, const display_mode_t *mode) {
    memset(state, 0, sizeof(*state));
    state->connector_crtc_id =
        g_edge_drm_crtc_active ? EDGE_DRM_CRTC_ID : 0u;
    state->crtc_active = g_edge_drm_crtc_active ? 1u : 0u;
    state->mode_blob_id = g_edge_drm_crtc_active ?
        (g_edge_drm_mode_blob_id ?
            g_edge_drm_mode_blob_id :
            EDGE_DRM_CURRENT_MODE_BLOB_ID) : 0u;
    state->plane_fb_id = g_edge_drm_active_fb;
    state->plane_crtc_id =
        g_edge_drm_active_fb ? EDGE_DRM_CRTC_ID : 0u;
    if (g_edge_drm_active_fb && mode) {
        state->src_x = g_edge_drm_crtc_x << 16;
        state->src_y = g_edge_drm_crtc_y << 16;
        state->src_w = mode->width << 16;
        state->src_h = mode->height << 16;
        state->crtc_w = mode->width;
        state->crtc_h = mode->height;
    }
    /* Damage clips describe one atomic commit and are never carried forward. */
    state->damage_blob_id = 0u;
    state->cursor_fb_id = g_edge_drm_cursor.fb_id;
    state->cursor_crtc_id = g_edge_drm_cursor.crtc_id;
    state->cursor_src_x = g_edge_drm_cursor.src_x;
    state->cursor_src_y = g_edge_drm_cursor.src_y;
    state->cursor_src_w = g_edge_drm_cursor.src_w;
    state->cursor_src_h = g_edge_drm_cursor.src_h;
    state->cursor_crtc_x = g_edge_drm_cursor.crtc_x;
    state->cursor_crtc_y = g_edge_drm_cursor.crtc_y;
    state->cursor_crtc_w = g_edge_drm_cursor.crtc_w;
    state->cursor_crtc_h = g_edge_drm_cursor.crtc_h;
}

static void edge_drm_atomic_cursor_state(
    const edge_drm_atomic_state_t *state,
    edge_drm_cursor_state_t *cursor) {
    if (!state || !cursor) return;
    memset(cursor, 0, sizeof(*cursor));
    cursor->fb_id = state->cursor_fb_id;
    cursor->crtc_id = state->cursor_crtc_id;
    cursor->src_x = state->cursor_src_x;
    cursor->src_y = state->cursor_src_y;
    cursor->src_w = state->cursor_src_w;
    cursor->src_h = state->cursor_src_h;
    cursor->crtc_x = state->cursor_crtc_x;
    cursor->crtc_y = state->cursor_crtc_y;
    cursor->crtc_w = state->cursor_crtc_w;
    cursor->crtc_h = state->cursor_crtc_h;
}

static int edge_drm_cursor_state_equal(
    const edge_drm_cursor_state_t *left,
    const edge_drm_cursor_state_t *right) {
    if (!left || !right) return 0;
    return left->fb_id == right->fb_id &&
           left->crtc_id == right->crtc_id &&
           left->src_x == right->src_x &&
           left->src_y == right->src_y &&
           left->src_w == right->src_w &&
           left->src_h == right->src_h &&
           left->crtc_x == right->crtc_x &&
           left->crtc_y == right->crtc_y &&
           left->crtc_w == right->crtc_w &&
           left->crtc_h == right->crtc_h;
}

static int edge_drm_atomic_set_property(
    edge_drm_atomic_state_t *state, uint32_t object_id,
    uint32_t property_id, uint64_t value) {
    if (!state) return -EDGE_LINUX_EINVAL;
    if (object_id == EDGE_DRM_CONNECTOR_ID) {
        if (property_id == EDGE_DRM_PROP_CONNECTOR_CRTC_ID) {
            if (value > UINT32_MAX) return -EDGE_LINUX_ERANGE;
            state->connector_crtc_id = (uint32_t)value;
            return 0;
        }
        if ((property_id == EDGE_DRM_PROP_LINK_STATUS ||
             property_id == EDGE_DRM_PROP_NON_DESKTOP) &&
            value == 0u)
            return 0;
        return -EDGE_LINUX_EINVAL;
    }
    if (object_id == EDGE_DRM_CRTC_ID) {
        if (property_id == EDGE_DRM_PROP_CRTC_MODE_ID) {
            if (value > UINT32_MAX) return -EDGE_LINUX_ERANGE;
            state->mode_blob_id = (uint32_t)value;
            return 0;
        }
        if (property_id == EDGE_DRM_PROP_CRTC_ACTIVE && value <= 1u) {
            state->crtc_active = (uint32_t)value;
            return 0;
        }
        return -EDGE_LINUX_EINVAL;
    }
    if (object_id != EDGE_DRM_PRIMARY_PLANE_ID &&
        object_id != EDGE_DRM_CURSOR_PLANE_ID)
        return -EDGE_LINUX_ENOENT;
    if (value > UINT32_MAX &&
        property_id != EDGE_DRM_PROP_PLANE_CRTC_X &&
        property_id != EDGE_DRM_PROP_PLANE_CRTC_Y)
        return -EDGE_LINUX_ERANGE;
    if (object_id == EDGE_DRM_CURSOR_PLANE_ID) {
        switch (property_id) {
            case EDGE_DRM_PROP_PLANE_FB_ID:
                state->cursor_fb_id = (uint32_t)value;
                break;
            case EDGE_DRM_PROP_PLANE_CRTC_ID:
                state->cursor_crtc_id = (uint32_t)value;
                break;
            case EDGE_DRM_PROP_PLANE_SRC_X:
                state->cursor_src_x = (uint32_t)value;
                break;
            case EDGE_DRM_PROP_PLANE_SRC_Y:
                state->cursor_src_y = (uint32_t)value;
                break;
            case EDGE_DRM_PROP_PLANE_SRC_W:
                state->cursor_src_w = (uint32_t)value;
                break;
            case EDGE_DRM_PROP_PLANE_SRC_H:
                state->cursor_src_h = (uint32_t)value;
                break;
            case EDGE_DRM_PROP_PLANE_CRTC_X:
                state->cursor_crtc_x = (int32_t)value;
                break;
            case EDGE_DRM_PROP_PLANE_CRTC_Y:
                state->cursor_crtc_y = (int32_t)value;
                break;
            case EDGE_DRM_PROP_PLANE_CRTC_W:
                state->cursor_crtc_w = (uint32_t)value;
                break;
            case EDGE_DRM_PROP_PLANE_CRTC_H:
                state->cursor_crtc_h = (uint32_t)value;
                break;
            case EDGE_DRM_PROP_PLANE_TYPE:
                return value == 2u ? 0 : -EDGE_LINUX_EINVAL;
            case EDGE_DRM_PROP_PLANE_IN_FORMATS:
                return value == EDGE_DRM_IN_FORMATS_BLOB_ID ?
                    0 : -EDGE_LINUX_EINVAL;
            case EDGE_DRM_PROP_PLANE_FB_DAMAGE_CLIPS:
                return -EDGE_LINUX_EINVAL;
            default:
                return -EDGE_LINUX_EINVAL;
        }
        return 0;
    }
    switch (property_id) {
        case EDGE_DRM_PROP_PLANE_FB_ID:
            state->plane_fb_id = (uint32_t)value;
            break;
        case EDGE_DRM_PROP_PLANE_CRTC_ID:
            state->plane_crtc_id = (uint32_t)value;
            break;
        case EDGE_DRM_PROP_PLANE_SRC_X:
            state->src_x = (uint32_t)value;
            break;
        case EDGE_DRM_PROP_PLANE_SRC_Y:
            state->src_y = (uint32_t)value;
            break;
        case EDGE_DRM_PROP_PLANE_SRC_W:
            state->src_w = (uint32_t)value;
            break;
        case EDGE_DRM_PROP_PLANE_SRC_H:
            state->src_h = (uint32_t)value;
            break;
        case EDGE_DRM_PROP_PLANE_CRTC_X:
            state->crtc_x = (int32_t)value;
            break;
        case EDGE_DRM_PROP_PLANE_CRTC_Y:
            state->crtc_y = (int32_t)value;
            break;
        case EDGE_DRM_PROP_PLANE_CRTC_W:
            state->crtc_w = (uint32_t)value;
            break;
        case EDGE_DRM_PROP_PLANE_CRTC_H:
            state->crtc_h = (uint32_t)value;
            break;
        case EDGE_DRM_PROP_PLANE_TYPE:
            return value == 1u ? 0 : -EDGE_LINUX_EINVAL;
        case EDGE_DRM_PROP_PLANE_IN_FORMATS:
            return value == EDGE_DRM_IN_FORMATS_BLOB_ID ?
                0 : -EDGE_LINUX_EINVAL;
        case EDGE_DRM_PROP_PLANE_FB_DAMAGE_CLIPS:
            state->damage_blob_id = (uint32_t)value;
            break;
        default:
            return -EDGE_LINUX_EINVAL;
    }
    return 0;
}

static int edge_drm_mode_supported(const edge_drm_modeinfo_t *requested) {
    edge_drm_modeinfo_t modes[EDGE_DRM_MODE_COUNT];
    uint32_t count;

    if (!requested || !requested->hdisplay || !requested->vdisplay)
        return 0;
    count = edge_drm_collect_modes(modes);
    for (uint32_t index = 0; index < count; ++index)
        if (modes[index].hdisplay == requested->hdisplay &&
            modes[index].vdisplay == requested->vdisplay &&
            (!requested->vrefresh ||
             modes[index].vrefresh == requested->vrefresh) &&
            ((modes[index].flags ^ requested->flags) & (1u << 4)) == 0)
            return 1;
    return 0;
}

static int edge_drm_mode_blob(uint32_t id,
                              edge_drm_modeinfo_t *mode) {
    uint8_t data[EDGE_DRM_BLOB_CAPACITY];
    uint32_t length = 0;
    int result;

    if (!id || !mode) return -EDGE_LINUX_EINVAL;
    result = edge_drm_blob_snapshot(id, data, &length);
    if (result < 0) return result;
    if (length != sizeof(*mode)) return -EDGE_LINUX_EINVAL;
    memcpy(mode, data, sizeof(*mode));
    return edge_drm_mode_supported(mode) ? 0 : -EDGE_LINUX_EINVAL;
}

static int edge_drm_atomic_validate(
    const edge_drm_atomic_state_t *previous,
    const edge_drm_atomic_state_t *state, uint32_t flags,
    edge_drm_modeinfo_t *mode, edge_drm_framebuffer_t *framebuffer) {
    edge_drm_framebuffer_t cursor_framebuffer;
    int modeset;

    if (!previous || !state || !mode || !framebuffer)
        return -EDGE_LINUX_EINVAL;
    memset(mode, 0, sizeof(*mode));
    memset(framebuffer, 0, sizeof(*framebuffer));
    memset(&cursor_framebuffer, 0, sizeof(cursor_framebuffer));
    modeset =
        previous->connector_crtc_id != state->connector_crtc_id ||
        previous->crtc_active != state->crtc_active ||
        previous->mode_blob_id != state->mode_blob_id;
    if (modeset && !(flags & EDGE_DRM_MODE_ATOMIC_ALLOW_MODESET))
        return -EDGE_LINUX_EINVAL;
    if (!state->crtc_active) {
        if (state->connector_crtc_id || state->mode_blob_id ||
            state->plane_fb_id || state->plane_crtc_id ||
            state->cursor_fb_id || state->cursor_crtc_id)
            return -EDGE_LINUX_EINVAL;
        return 0;
    }
    if (state->connector_crtc_id != EDGE_DRM_CRTC_ID ||
        !state->mode_blob_id)
        return -EDGE_LINUX_EINVAL;
    if (edge_drm_mode_blob(state->mode_blob_id, mode) < 0)
        return -EDGE_LINUX_EINVAL;
    if (!state->plane_fb_id) {
        if (state->plane_crtc_id || state->cursor_fb_id ||
            state->cursor_crtc_id)
            return -EDGE_LINUX_EINVAL;
        return 0;
    }
    if (state->plane_crtc_id != EDGE_DRM_CRTC_ID ||
        (state->src_x & 0xffffu) || (state->src_y & 0xffffu) ||
        (state->src_w & 0xffffu) || (state->src_h & 0xffffu) ||
        state->crtc_x != 0 || state->crtc_y != 0 ||
        !state->crtc_w || !state->crtc_h ||
        (state->src_w >> 16) != state->crtc_w ||
        (state->src_h >> 16) != state->crtc_h ||
        state->crtc_w != mode->hdisplay ||
        state->crtc_h != mode->vdisplay)
        return -EDGE_LINUX_EINVAL;
    edge_drm_lock();
    {
        edge_drm_framebuffer_t *found =
            edge_drm_framebuffer_locked(state->plane_fb_id, 0);
        if (found) *framebuffer = *found;
    }
    edge_drm_unlock();
    if (!framebuffer->used ||
        (state->src_x >> 16) > framebuffer->width ||
        (state->src_y >> 16) > framebuffer->height ||
        state->crtc_w > framebuffer->width - (state->src_x >> 16) ||
        state->crtc_h > framebuffer->height - (state->src_y >> 16))
        return -EDGE_LINUX_EINVAL;
    if (state->damage_blob_id) {
        uint8_t damage[EDGE_DRM_BLOB_CAPACITY];
        uint32_t damage_length = 0;

        if (edge_drm_blob_snapshot(state->damage_blob_id, damage,
                                   &damage_length) < 0 ||
            !damage_length ||
            damage_length % sizeof(edge_drm_mode_rect_t))
            return -EDGE_LINUX_EINVAL;
    }
    if (!state->cursor_fb_id)
        return state->cursor_crtc_id ? -EDGE_LINUX_EINVAL : 0;
    if (state->cursor_crtc_id != EDGE_DRM_CRTC_ID ||
        (state->cursor_src_x & 0xffffu) ||
        (state->cursor_src_y & 0xffffu) ||
        (state->cursor_src_w & 0xffffu) ||
        (state->cursor_src_h & 0xffffu) ||
        !state->cursor_crtc_w || !state->cursor_crtc_h ||
        (state->cursor_src_w >> 16) != state->cursor_crtc_w ||
        (state->cursor_src_h >> 16) != state->cursor_crtc_h ||
        state->cursor_crtc_w > EDGE_DRM_CURSOR_MAX_WIDTH ||
        state->cursor_crtc_h > EDGE_DRM_CURSOR_MAX_HEIGHT)
        return -EDGE_LINUX_EINVAL;
    edge_drm_lock();
    {
        edge_drm_framebuffer_t *found =
            edge_drm_framebuffer_locked(state->cursor_fb_id, 0);
        if (found) cursor_framebuffer = *found;
    }
    edge_drm_unlock();
    if (!cursor_framebuffer.used || cursor_framebuffer.virtgpu ||
        cursor_framebuffer.pixel_format != EDGE_DRM_FORMAT_ARGB8888 ||
        (state->cursor_src_x >> 16) > cursor_framebuffer.width ||
        (state->cursor_src_y >> 16) > cursor_framebuffer.height ||
        state->cursor_crtc_w > cursor_framebuffer.width -
            (state->cursor_src_x >> 16) ||
        state->cursor_crtc_h > cursor_framebuffer.height -
            (state->cursor_src_y >> 16))
        return -EDGE_LINUX_EINVAL;
    return 0;
}

static void edge_drm_mode_blob_reference_locked(uint32_t id) {
    edge_drm_blob_t *blob = edge_drm_blob_locked(id);
    if (blob && blob->reference_count != UINT16_MAX)
        blob->reference_count++;
}

static void edge_drm_mode_blob_unreference_locked(uint32_t id) {
    edge_drm_blob_t *blob = edge_drm_blob_locked(id);
    if (!blob || !blob->reference_count) return;
    blob->reference_count--;
    edge_drm_blob_maybe_release_locked(blob);
}

static int64_t edge_drm_ioctl_atomic(
    uint64_t identity, const kernel_ioctl_request_t *request) {
    edge_drm_atomic_t command;
    edge_drm_atomic_state_t previous;
    edge_drm_atomic_state_t state;
    display_mode_t current;
    edge_drm_modeinfo_t requested_mode;
    edge_drm_framebuffer_t framebuffer;
    edge_drm_cursor_state_t previous_cursor;
    edge_drm_cursor_state_t next_cursor;
    uint32_t object_ids[EDGE_DRM_ATOMIC_OBJECT_COUNT];
    uint32_t property_counts[EDGE_DRM_ATOMIC_OBJECT_COUNT];
    uint32_t property_ids[EDGE_DRM_ATOMIC_PROPERTY_COUNT];
    uint64_t property_values[EDGE_DRM_ATOMIC_PROPERTY_COUNT];
    uint32_t property_total = 0;
    uint32_t property_cursor = 0;
    uint64_t submitted_us;
    int cursor_changed;
    int cursor_only;
    int primary_changed;
    int primary_plane_touched = 0;
    int mode_blob_referenced = 0;
    int result;

    submitted_us = boottime_monotonic_us();
    if (!request->argument ||
        edge_drm_copy_from(request, &command, request->argument,
                           sizeof(command)) < 0)
        return -EDGE_LINUX_EFAULT;
    if (command.reserved ||
        (command.flags & ~EDGE_DRM_MODE_ATOMIC_FLAGS) ||
        (command.flags & EDGE_DRM_MODE_PAGE_FLIP_ASYNC) ||
        ((command.flags & EDGE_DRM_MODE_ATOMIC_TEST_ONLY) &&
         (command.flags & EDGE_DRM_MODE_PAGE_FLIP_EVENT)) ||
        command.count_objs > EDGE_DRM_ATOMIC_OBJECT_COUNT ||
        (command.count_objs &&
         (!command.objs_ptr || !command.count_props_ptr)))
        return -EDGE_LINUX_EINVAL;
    if (!edge_drm_mode_available(&current, 0))
        return -EDGE_LINUX_ENODEV;
    if (command.count_objs &&
        (edge_drm_copy_from(request, object_ids, command.objs_ptr,
                            (uint64_t)command.count_objs *
                                sizeof(object_ids[0])) < 0 ||
         edge_drm_copy_from(request, property_counts,
                            command.count_props_ptr,
                            (uint64_t)command.count_objs *
                                sizeof(property_counts[0])) < 0))
        return -EDGE_LINUX_EFAULT;
    for (uint32_t index = 0; index < command.count_objs; ++index) {
        if (property_counts[index] >
            EDGE_DRM_ATOMIC_PROPERTY_COUNT - property_total)
            return -EDGE_LINUX_E2BIG;
        property_total += property_counts[index];
    }
    if (property_total && (!command.props_ptr ||
        !command.prop_values_ptr ||
        edge_drm_copy_from(request, property_ids, command.props_ptr,
                           (uint64_t)property_total *
                               sizeof(property_ids[0])) < 0 ||
        edge_drm_copy_from(request, property_values,
                           command.prop_values_ptr,
                           (uint64_t)property_total *
                               sizeof(property_values[0])) < 0))
        return -EDGE_LINUX_EFAULT;

    edge_drm_atomic_lock();
    edge_drm_lock();
    if (!edge_drm_client_atomic_locked(identity)) {
        edge_drm_unlock();
        result = -EDGE_LINUX_EOPNOTSUPP;
        goto out;
    }
    result = edge_drm_require_master_locked(identity);
    edge_drm_atomic_state_locked(&previous, &current);
    edge_drm_unlock();
    if (result < 0) goto out;
    state = previous;
    for (uint32_t object = 0; object < command.count_objs; ++object) {
        if (object_ids[object] == EDGE_DRM_PRIMARY_PLANE_ID &&
            property_counts[object])
            primary_plane_touched = 1;
        for (uint32_t property = 0;
             property < property_counts[object]; ++property) {
            result = edge_drm_atomic_set_property(
                &state, object_ids[object],
                property_ids[property_cursor],
                property_values[property_cursor]);
            if (result < 0) goto out;
            property_cursor++;
        }
    }
    result = edge_drm_atomic_validate(
        &previous, &state, command.flags, &requested_mode, &framebuffer);
    if (result < 0) goto out;
    if (command.flags & EDGE_DRM_MODE_ATOMIC_TEST_ONLY) goto out;
    edge_drm_atomic_cursor_state(&previous, &previous_cursor);
    edge_drm_atomic_cursor_state(&state, &next_cursor);
    cursor_changed = !edge_drm_cursor_state_equal(
        &previous_cursor, &next_cursor);
    primary_changed =
        previous.plane_fb_id != state.plane_fb_id ||
        previous.plane_crtc_id != state.plane_crtc_id ||
        previous.src_x != state.src_x || previous.src_y != state.src_y ||
        previous.src_w != state.src_w || previous.src_h != state.src_h ||
        previous.crtc_x != state.crtc_x ||
        previous.crtc_y != state.crtc_y ||
        previous.crtc_w != state.crtc_w ||
        previous.crtc_h != state.crtc_h ||
        previous.crtc_active != state.crtc_active ||
        previous.mode_blob_id != state.mode_blob_id;
    cursor_only = cursor_changed && !primary_changed &&
        !state.damage_blob_id;
    __atomic_add_fetch(
        &g_edge_drm_runtime_stats.atomic_commits, 1u,
        __ATOMIC_RELAXED);
    if (cursor_only)
        __atomic_add_fetch(
            &g_edge_drm_runtime_stats.atomic_cursor_only_commits,
            1u, __ATOMIC_RELAXED);
    if (state.mode_blob_id != previous.mode_blob_id &&
        state.mode_blob_id >= EDGE_DRM_BLOB_ID_BASE) {
        edge_drm_lock();
        if (!edge_drm_blob_locked(state.mode_blob_id)) {
            edge_drm_unlock();
            result = -EDGE_LINUX_ENOENT;
            goto out;
        }
        edge_drm_mode_blob_reference_locked(state.mode_blob_id);
        mode_blob_referenced = 1;
        edge_drm_unlock();
    }

    if (state.crtc_active) {
        display_mode_t requested;
        edge_drm_display_mode_from_modeinfo(&requested_mode, &requested);
        if ((requested.width != current.width ||
             requested.height != current.height ||
             requested.refresh_millihz != current.refresh_millihz) &&
            display_backend_set_mode(&requested) < 0) {
            result = -EDGE_LINUX_EINVAL;
            goto out;
        }
        __atomic_store_n(&g_edge_drm_scanout_interval_us,
                         display_mode_frame_interval_us(&requested),
                         __ATOMIC_RELEASE);
    }

    if (cursor_changed && !cursor_only)
        (void)edge_drm_cursor_restore(
            &previous_cursor, previous.plane_fb_id);
    edge_drm_lock();
    if (state.mode_blob_id != previous.mode_blob_id) {
        if (!mode_blob_referenced)
            edge_drm_mode_blob_reference_locked(state.mode_blob_id);
        mode_blob_referenced = 0;
        edge_drm_mode_blob_unreference_locked(previous.mode_blob_id);
    }
    g_edge_drm_crtc_active = (uint8_t)state.crtc_active;
    g_edge_drm_mode_blob_id = state.mode_blob_id;
    g_edge_drm_active_fb = state.plane_fb_id;
    g_edge_drm_crtc_x = state.src_x >> 16;
    g_edge_drm_crtc_y = state.src_y >> 16;
    g_edge_drm_cursor = next_cursor;
    edge_drm_publish_scanout_state_locked();
    edge_drm_unlock();
    fb_console_set_drm_owned(
        state.crtc_active && state.plane_fb_id);
    if (state.plane_fb_id &&
        (primary_changed || state.damage_blob_id ||
         (!cursor_only && primary_plane_touched &&
          display_backend_requires_present()))) {
        __atomic_add_fetch(
            &g_edge_drm_runtime_stats.atomic_primary_commits,
            1u, __ATOMIC_RELAXED);
        /*
         * Physical scanout observes stores to an unchanged framebuffer
         * without another modeset. Explicit-present backends do not: a
         * software compositor may render into its current buffer and submit
         * the primary plane again with the same FB_ID and no damage blob.
         * Treat that primary-plane commit as a presentation request. Cursor-
         * only commits remain independent and avoid a full-screen transfer.
         */
        result = edge_drm_present_flip(
            state.plane_fb_id, state.damage_blob_id, !cursor_changed);
        if (result < 0) goto out;
    }
    if (cursor_only) {
        result = edge_drm_cursor_transition(
            &previous_cursor, &next_cursor, previous.plane_fb_id);
        if (result < 0) goto out;
    } else if (cursor_changed && next_cursor.fb_id) {
        result = edge_drm_cursor_draw(&next_cursor);
        if (result < 0) goto out;
    }
    if (command.flags & EDGE_DRM_MODE_PAGE_FLIP_EVENT) {
        result = edge_drm_queue_flip_event(
            identity, command.user_data,
            (command.flags & EDGE_DRM_MODE_PAGE_FLIP_ASYNC) != 0,
            submitted_us);
        if (result < 0) goto out;
    }
    result = 0;
out:
    if (mode_blob_referenced) {
        edge_drm_lock();
        edge_drm_mode_blob_unreference_locked(state.mode_blob_id);
        edge_drm_unlock();
    }
    edge_drm_atomic_unlock();
    return result;
}

int edge_drm_path_is_card(const char *path) {
    return path && strcmp(path, EDGE_DRM_CARD_PATH) == 0;
}

int edge_drm_path_is_render(const char *path) {
    return path && edge_virtgpu_available() &&
        strcmp(path, EDGE_VIRTGPU_RENDER_PATH) == 0;
}

int edge_drm_path_is_device(const char *path) {
    return edge_drm_path_is_card(path) || edge_drm_path_is_render(path);
}

int64_t edge_drm_ioctl(uint64_t identity,
                       const kernel_ioctl_request_t *request) {
    uint32_t value;
    int64_t result;

    if (!identity || !request) return -EDGE_LINUX_EBADF;
    switch (request->command) {
        case EDGE_DRM_IOCTL_VERSION:
            if (edge_virtgpu_available())
                return edge_virtgpu_ioctl(identity, request);
            return edge_drm_ioctl_version(request);
        case EDGE_DRM_IOCTL_GET_UNIQUE:
            return edge_drm_ioctl_unique(request);
        case EDGE_DRM_IOCTL_GET_MAGIC:
            edge_drm_lock();
            {
                edge_drm_client_t *client =
                    edge_drm_client_locked(identity, 1);
                value = client ? client->magic : 0u;
            }
            edge_drm_unlock();
            if (!value) return -EDGE_LINUX_ENOSPC;
            return !request->argument ||
                edge_drm_copy_to(request, request->argument, &value,
                                 sizeof(value)) < 0 ?
                -EDGE_LINUX_EFAULT : 0;
        case EDGE_DRM_IOCTL_AUTH_MAGIC:
            if (!request->argument ||
                edge_drm_copy_from(request, &value, request->argument,
                                   sizeof(value)) < 0)
                return -EDGE_LINUX_EFAULT;
            edge_drm_lock();
            for (uint32_t index = 0; index < EDGE_DRM_CLIENT_COUNT; ++index)
                if (g_edge_drm_clients[index].used &&
                    g_edge_drm_clients[index].magic == value) {
                    edge_drm_unlock();
                    return 0;
                }
            edge_drm_unlock();
            return -EDGE_LINUX_EINVAL;
        case EDGE_DRM_IOCTL_GET_CAP:
            return edge_drm_ioctl_get_cap(request);
        case EDGE_DRM_IOCTL_SET_CLIENT_CAP:
            return edge_drm_ioctl_set_client_cap(identity, request);
        case EDGE_DRM_IOCTL_PRIME_HANDLE_TO_FD:
            result = edge_drm_ioctl_prime_handle_to_fd(identity, request);
            if (result == -EDGE_LINUX_ENOENT && edge_virtgpu_available())
                return edge_virtgpu_ioctl(identity, request);
            return result;
        case EDGE_DRM_IOCTL_PRIME_FD_TO_HANDLE:
            return edge_drm_ioctl_prime_fd_to_handle(identity, request);
        case EDGE_DRM_IOCTL_SET_MASTER:
            edge_drm_lock();
            if (!g_edge_drm_master || g_edge_drm_master == identity) {
                g_edge_drm_master = identity;
                edge_drm_unlock();
                return 0;
            }
            edge_drm_unlock();
            return -EDGE_LINUX_EBUSY;
        case EDGE_DRM_IOCTL_DROP_MASTER:
            edge_drm_lock();
            if (g_edge_drm_master == identity) g_edge_drm_master = 0;
            edge_drm_unlock();
            return 0;
        case EDGE_DRM_IOCTL_GEM_CLOSE: {
            edge_drm_gem_close_t close;
            if (!request->argument ||
                edge_drm_copy_from(request, &close, request->argument,
                                   sizeof(close)) < 0)
                return -EDGE_LINUX_EFAULT;
            result = edge_drm_close_handle(identity, close.handle);
            if (result == -EDGE_LINUX_ENOENT &&
                edge_virtgpu_available())
                return edge_virtgpu_ioctl(identity, request);
            return result;
        }
        case EDGE_DRM_IOCTL_MODE_GETRESOURCES:
            return edge_drm_ioctl_resources(request);
        case EDGE_DRM_IOCTL_MODE_GETCRTC:
            return edge_drm_ioctl_get_crtc(request);
        case EDGE_DRM_IOCTL_MODE_SETCRTC:
            return edge_drm_ioctl_set_crtc(identity, request);
        case EDGE_DRM_IOCTL_MODE_GETENCODER:
            return edge_drm_ioctl_encoder(request);
        case EDGE_DRM_IOCTL_MODE_GETCONNECTOR:
            return edge_drm_ioctl_connector(identity, request);
        case EDGE_DRM_IOCTL_MODE_GETPROPERTY:
            return edge_drm_ioctl_get_property(request);
        case EDGE_DRM_IOCTL_MODE_SETPROPERTY:
            return edge_drm_ioctl_set_property(identity, request, 1);
        case EDGE_DRM_IOCTL_MODE_GETPROPBLOB:
            return edge_drm_ioctl_get_blob(request);
        case EDGE_DRM_IOCTL_MODE_GETFB:
            return edge_drm_ioctl_getfb(request);
        case EDGE_DRM_IOCTL_MODE_ADDFB:
            return edge_drm_ioctl_addfb(identity, request);
        case EDGE_DRM_IOCTL_MODE_RMFB:
            return edge_drm_ioctl_rmfb(identity, request);
        case EDGE_DRM_IOCTL_MODE_PAGE_FLIP:
            return edge_drm_ioctl_page_flip(identity, request);
        case EDGE_DRM_IOCTL_MODE_DIRTYFB:
            return edge_drm_ioctl_dirtyfb(request);
        case EDGE_DRM_IOCTL_MODE_CREATE_DUMB:
            return edge_drm_ioctl_create_dumb(identity, request);
        case EDGE_DRM_IOCTL_MODE_MAP_DUMB:
            return edge_drm_ioctl_map_dumb(identity, request);
        case EDGE_DRM_IOCTL_MODE_DESTROY_DUMB: {
            edge_drm_destroy_dumb_t destroy;
            if (!request->argument ||
                edge_drm_copy_from(request, &destroy, request->argument,
                                   sizeof(destroy)) < 0)
                return -EDGE_LINUX_EFAULT;
            return edge_drm_close_handle(identity, destroy.handle);
        }
        case EDGE_DRM_IOCTL_MODE_GETPLANERESOURCES:
            return edge_drm_ioctl_plane_resources(request);
        case EDGE_DRM_IOCTL_MODE_GETPLANE:
            return edge_drm_ioctl_get_plane(request);
        case EDGE_DRM_IOCTL_MODE_SETPLANE:
            return edge_drm_ioctl_set_plane(identity, request);
        case EDGE_DRM_IOCTL_MODE_ADDFB2:
            return edge_drm_ioctl_addfb2(identity, request);
        case EDGE_DRM_IOCTL_MODE_OBJ_GETPROPERTIES:
            return edge_drm_ioctl_object_properties(identity, request);
        case EDGE_DRM_IOCTL_MODE_OBJ_SETPROPERTY:
            return edge_drm_ioctl_set_property(identity, request, 0);
        case EDGE_DRM_IOCTL_MODE_ATOMIC:
            return edge_drm_ioctl_atomic(identity, request);
        case EDGE_DRM_IOCTL_MODE_CREATEPROPBLOB:
            return edge_drm_ioctl_create_blob(identity, request);
        case EDGE_DRM_IOCTL_MODE_DESTROYPROPBLOB:
            return edge_drm_ioctl_destroy_blob(identity, request);
        case EDGE_DRM_IOCTL_MODE_LIST_LESSEES:
            return edge_drm_ioctl_list_lessees(identity, request);
        case EDGE_DRM_IOCTL_MODE_CLOSEFB:
            return edge_drm_ioctl_closefb(identity, request);
        default:
            if (edge_virtgpu_available())
                return edge_virtgpu_ioctl(identity, request);
            return -EDGE_LINUX_ENOTTY;
    }
}

int64_t edge_drm_ioctl_path(
    uint64_t identity, const char *path,
    const kernel_ioctl_request_t *request) {
    if (edge_drm_path_is_render(path))
        return edge_virtgpu_ioctl(identity, request);
    if (edge_drm_path_is_card(path))
        return edge_drm_ioctl(identity, request);
    return -EDGE_LINUX_ENODEV;
}

int64_t edge_drm_read(uint64_t identity, void *destination,
                      uint64_t length) {
    edge_drm_client_t *client;
    uint64_t copied = 0;

    if (!identity || (!destination && length))
        return -EDGE_LINUX_EFAULT;
    if (length < sizeof(edge_drm_event_vblank_t))
        return -EDGE_LINUX_EINVAL;
    edge_drm_lock();
    client = edge_drm_client_locked(identity, 0);
    while (client && client->event_count &&
           copied + sizeof(edge_drm_event_vblank_t) <= length) {
        memcpy((uint8_t *)destination + copied,
               &client->events[client->event_head],
               sizeof(edge_drm_event_vblank_t));
        client->event_head =
            (client->event_head + 1u) % EDGE_DRM_EVENT_COUNT;
        client->event_count--;
        copied += sizeof(edge_drm_event_vblank_t);
    }
    edge_drm_unlock();
    return copied ? (int64_t)copied : -EDGE_LINUX_EAGAIN;
}

int edge_drm_poll_readable(uint64_t identity) {
    edge_drm_client_t *client;
    int readable;

    /*
     * A compositor can update an unchanged dumb framebuffer and then enter
     * poll without another modeset. Physical scanout observes those stores
     * continuously; an explicit-present backend must therefore keep the
     * ordinary scanout cadence active while the compositor sleeps.
     *
     * Readiness evaluation may run several times around one epoll sleep and
     * again at every bounded rescan. It must never poll the device or scan the
     * framebuffer here:
     * at 1080p even a cadence check that occasionally becomes due moves the
     * complete hash/copy job onto a compositor's latency-critical epoll path.
     * Completion interrupts, timer activity, and input schedule the shared
     * display worker. Readiness only advances due flip events, which is bounded
     * by the client table and is necessary for the event fd to become readable
     * on time.
     */
    edge_drm_pump_flip_events(boottime_monotonic_us());
    edge_drm_lock();
    client = edge_drm_client_locked(identity, 0);
    readable = client && client->event_count;
    edge_drm_unlock();
    return readable;
}

uint64_t edge_drm_readiness_sequence(uint64_t identity) {
    edge_drm_client_t *client;
    uint64_t sequence;

    edge_drm_lock();
    client = edge_drm_client_locked(identity, 0);
    sequence = client ? client->readiness_sequence : 0;
    edge_drm_unlock();
    return sequence;
}

void edge_drm_get_runtime_stats(edge_drm_runtime_stats_t *stats) {
    if (!stats) return;
    memcpy(stats, &g_edge_drm_runtime_stats, sizeof(*stats));
}

void edge_drm_release_client(uint64_t identity) {
    edge_drm_client_t *client;
    edge_drm_cursor_state_t previous_cursor;
    uint32_t virtgpu_handles[EDGE_DRM_FRAMEBUFFER_COUNT];
    uint32_t virtgpu_count = 0;
    uint32_t previous_primary_fb;
    int released_active = 0;
    int released_cursor = 0;

    if (!identity) return;
    edge_drm_lock();
    previous_cursor = g_edge_drm_cursor;
    previous_primary_fb = g_edge_drm_active_fb;
    for (uint32_t index = 0; index < EDGE_DRM_FRAMEBUFFER_COUNT; ++index) {
        edge_drm_framebuffer_t *framebuffer =
            &g_edge_drm_framebuffers[index];
        uint32_t buffer_index;
        if (!framebuffer->used || framebuffer->owner != identity) continue;
        buffer_index = framebuffer->buffer_index;
        if (framebuffer->virtgpu &&
            virtgpu_count < EDGE_DRM_FRAMEBUFFER_COUNT)
            virtgpu_handles[virtgpu_count++] =
                framebuffer->virtgpu_handle;
        if (g_edge_drm_active_fb == framebuffer->id) {
            g_edge_drm_active_fb = 0;
            g_edge_drm_crtc_active = 0;
            memset(&g_edge_drm_cursor, 0, sizeof(g_edge_drm_cursor));
            released_active = 1;
        }
        if (g_edge_drm_cursor.fb_id == framebuffer->id) {
            memset(&g_edge_drm_cursor, 0, sizeof(g_edge_drm_cursor));
            released_cursor = 1;
        }
        memset(framebuffer, 0, sizeof(*framebuffer));
        if (buffer_index < EDGE_DRM_BUFFER_COUNT)
            edge_drm_buffer_maybe_release_locked(buffer_index);
    }
    edge_drm_publish_scanout_state_locked();
    for (uint32_t index = 0; index < EDGE_DRM_BUFFER_COUNT; ++index) {
        edge_drm_buffer_t *buffer = &g_edge_drm_buffers[index];
        if (!buffer->used || buffer->owner != identity) continue;
        buffer->handle_open = 0;
        edge_drm_buffer_maybe_release_locked(index);
    }
    for (uint32_t index = 0; index < EDGE_DRM_BLOB_COUNT; ++index) {
        edge_drm_blob_t *blob = &g_edge_drm_blobs[index];
        if (!blob->used || blob->owner != identity) continue;
        blob->user_live = 0u;
        edge_drm_blob_maybe_release_locked(blob);
    }
    client = edge_drm_client_locked(identity, 0);
    if (client) memset(client, 0, sizeof(*client));
    if (g_edge_drm_master == identity) g_edge_drm_master = 0;
    edge_drm_unlock();
    if (released_cursor && !released_active)
        (void)edge_drm_cursor_restore(
            &previous_cursor, previous_primary_fb);
    if (released_active) fb_console_set_drm_owned(0);
    for (uint32_t index = 0; index < virtgpu_count; ++index)
        edge_virtgpu_framebuffer_release(
            identity, virtgpu_handles[index]);
    edge_virtgpu_release_client(identity);
}

int edge_drm_mmap_prepare(uint64_t identity, uint64_t offset,
                          uint64_t length, uint32_t *page_count) {
    int result = -EDGE_LINUX_EINVAL;

    if (!identity || !length || !page_count ||
        (offset & (EDGE_DRM_PAGE_SIZE - 1u)) ||
        (length & (EDGE_DRM_PAGE_SIZE - 1u)))
        return -EDGE_LINUX_EINVAL;
    edge_drm_lock();
    for (uint32_t index = 0; index < EDGE_DRM_BUFFER_COUNT; ++index) {
        edge_drm_buffer_t *buffer = &g_edge_drm_buffers[index];
        if (!buffer->used || buffer->owner != identity ||
            !buffer->map_authorized || buffer->map_offset != offset)
            continue;
        if (length > buffer->size) break;
        *page_count = (uint32_t)(length / EDGE_DRM_PAGE_SIZE);
        buffer->mapped = 1u;
        result = 0;
        break;
    }
    edge_drm_unlock();
    if (result < 0 && edge_virtgpu_available())
        return edge_virtgpu_mmap_prepare(
            identity, offset, length, page_count);
    return result;
}

int edge_drm_mmap_page(uint64_t identity, uint64_t offset,
                       uint32_t page_index, void **kernel_address) {
    int result = -EDGE_LINUX_EINVAL;

    if (!identity || !kernel_address) return -EDGE_LINUX_EINVAL;
    edge_drm_lock();
    for (uint32_t index = 0; index < EDGE_DRM_BUFFER_COUNT; ++index) {
        edge_drm_buffer_t *buffer = &g_edge_drm_buffers[index];
        uint64_t page_offset = (uint64_t)page_index * EDGE_DRM_PAGE_SIZE;
        if (!buffer->used || buffer->owner != identity ||
            !buffer->map_authorized || buffer->map_offset != offset)
            continue;
        if (page_offset >= buffer->size) break;
        *kernel_address = buffer->storage + page_offset;
        result = 0;
        break;
    }
    edge_drm_unlock();
    if (result < 0 && edge_virtgpu_available())
        return edge_virtgpu_mmap_page(
            identity, offset, page_index, kernel_address);
    return result;
}

int edge_drm_mmap_write_tracking_required(uint64_t identity,
                                          uint64_t offset) {
    (void)identity;
    (void)offset;

    /*
     * Desktop compositors normally render into large, rotating dumb buffers.
     * Re-protecting every dirty page after each scanout makes the next frame
     * take one write-notify fault per 4 KiB page. At 1920x1080 that can exceed
     * two thousand faults for a single software-rendered frame and stalls the
     * compositor's input loop. The direct-display path already compares the
     * mapped buffer at display cadence and page flips explicitly wake that
     * scan, so use the fault-free tile comparison path for DRM mappings.
     *
     * Explicit-present backends retain their transfer-based damage handling;
     * fbdev has a separate write-notify policy and is unaffected here.
     */
    return 0;
}

int edge_drm_mmap_enable_write_tracking(uint64_t identity,
                                        uint64_t offset) {
    int result = -EDGE_LINUX_EINVAL;

    if (!identity) return result;
    edge_drm_lock();
    for (uint32_t index = 0; index < EDGE_DRM_BUFFER_COUNT; ++index) {
        edge_drm_buffer_t *buffer = &g_edge_drm_buffers[index];
        if (!buffer->used || buffer->owner != identity ||
            !buffer->map_authorized || buffer->map_offset != offset)
            continue;
        if (!buffer->write_tracking) {
            buffer->write_tracking = 1u;
            memset(buffer->dirty_pages, 0,
                   sizeof(buffer->dirty_pages));
            memset(buffer->scanout_page_hash_valid, 0,
                   sizeof(buffer->scanout_page_hash_valid));
        }
        result = 0;
        break;
    }
    edge_drm_unlock();
    return result;
}

int edge_drm_note_mmap_dirty_physical(uint64_t physical_address,
                                      uint64_t length) {
    uint64_t physical_end;
    int found = 0;

    if (!length || physical_address > UINT64_MAX - length) return 0;
    physical_end = physical_address + length;
    edge_drm_lock();
    for (uint32_t index = 0; index < EDGE_DRM_BUFFER_COUNT; ++index) {
        edge_drm_buffer_t *buffer = &g_edge_drm_buffers[index];
        uint64_t buffer_start;
        uint64_t buffer_end;
        uint64_t overlap_start;
        uint64_t overlap_end;
        uint32_t first_page;
        uint32_t last_page;

        if (!buffer->used || !buffer->write_tracking ||
            !buffer->storage || !buffer->size)
            continue;
        buffer_start = (uint64_t)(uintptr_t)buffer->storage;
        buffer_end = buffer_start + buffer->size;
        if (physical_end <= buffer_start ||
            physical_address >= buffer_end)
            continue;
        overlap_start = physical_address > buffer_start ?
            physical_address : buffer_start;
        overlap_end = physical_end < buffer_end ?
            physical_end : buffer_end;
        first_page =
            (uint32_t)((overlap_start - buffer_start) /
                       EDGE_DRM_PAGE_SIZE);
        last_page =
            (uint32_t)((overlap_end - 1u - buffer_start) /
                       EDGE_DRM_PAGE_SIZE);
        if (last_page >= buffer->page_count)
            last_page = buffer->page_count - 1u;
        for (uint32_t page = first_page; page <= last_page; ++page)
            buffer->dirty_pages[page >> 5] |=
                1u << (page & 31u);
        found = 1;
    }
    edge_drm_unlock();
    if (found) edge_drm_scanout_activity();
    return found;
}
