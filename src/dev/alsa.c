/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Copyright (c) EdgeOS Contributors.
 *
 * Original EdgeOS implementation of the Linux ALSA control and PCM playback
 * ABI.  The externally visible structure layouts and ioctl numbers follow
 * Linux UAPI definitions; the implementation is independent EdgeOS code that
 * routes playback to the active kernel audio backend.
 */

#include "dev/alsa.h"
#include "sys/boottime.h"
#if defined(CONFIG_AUDIO_AC97) || defined(CONFIG_AUDIO_HDA) || defined(CONFIG_USB_AUDIO) || defined(CONFIG_BSD_DRIVER_BRIDGE)
#include "drivers/audio.h"
#endif
#include "string.h"
#include "stdio.h"

#define ENOSYS 38
#define EINVAL 22
#define ENOENT 2
#define ENODEV 19
#define EAGAIN 11

#define ALSA_IOC_NRBITS   8u
#define ALSA_IOC_TYPEBITS 8u
#define ALSA_IOC_NRSHIFT  0u
#define ALSA_IOC_TYPESHIFT (ALSA_IOC_NRSHIFT + ALSA_IOC_NRBITS)
#define ALSA_IOC_TYPE(cmd) (((cmd) >> ALSA_IOC_TYPESHIFT) & ((1u << ALSA_IOC_TYPEBITS) - 1u))
#define ALSA_IOC_NR(cmd)   (((cmd) >> ALSA_IOC_NRSHIFT) & ((1u << ALSA_IOC_NRBITS) - 1u))

#define SNDRV_PROTOCOL_VERSION(major, minor, subminor) \
    (((major) << 16) | ((minor) << 8) | (subminor))
#define SNDRV_PCM_VERSION SNDRV_PROTOCOL_VERSION(2, 0, 17)
#define SNDRV_CTL_VERSION SNDRV_PROTOCOL_VERSION(2, 0, 9)
#define SNDRV_TIMER_VERSION SNDRV_PROTOCOL_VERSION(2, 0, 8)

#define SNDRV_PCM_STREAM_PLAYBACK 0
#define SNDRV_PCM_STREAM_CAPTURE  1
#define SNDRV_PCM_CLASS_GENERIC   0
#define SNDRV_PCM_SUBCLASS_GENERIC_MIX 0
#define SNDRV_PCM_STATE_OPEN      0
#define SNDRV_PCM_STATE_SETUP     2
#define SNDRV_PCM_STATE_PREPARED  3
#define SNDRV_PCM_STATE_RUNNING   4
#define SNDRV_PCM_STATE_XRUN      5

#define SNDRV_PCM_INFO_INTERLEAVED       0x00000100u
#define SNDRV_PCM_INFO_BLOCK_TRANSFER    0x00010000u
#define SNDRV_PCM_INFO_BATCH             0x00040000u

#define SNDRV_PCM_ACCESS_RW_INTERLEAVED  3u
#define SNDRV_PCM_FORMAT_S16_LE          2u
#define SNDRV_PCM_SUBFORMAT_STD          0u

#define SNDRV_PCM_HW_PARAM_ACCESS        0
#define SNDRV_PCM_HW_PARAM_FORMAT        1
#define SNDRV_PCM_HW_PARAM_SUBFORMAT     2
#define SNDRV_PCM_HW_PARAM_SAMPLE_BITS   8
#define SNDRV_PCM_HW_PARAM_FRAME_BITS    9
#define SNDRV_PCM_HW_PARAM_CHANNELS      10
#define SNDRV_PCM_HW_PARAM_RATE          11
#define SNDRV_PCM_HW_PARAM_PERIOD_TIME   12
#define SNDRV_PCM_HW_PARAM_PERIOD_SIZE   13
#define SNDRV_PCM_HW_PARAM_PERIOD_BYTES  14
#define SNDRV_PCM_HW_PARAM_PERIODS       15
#define SNDRV_PCM_HW_PARAM_BUFFER_TIME   16
#define SNDRV_PCM_HW_PARAM_BUFFER_SIZE   17
#define SNDRV_PCM_HW_PARAM_BUFFER_BYTES  18
#define SNDRV_PCM_HW_PARAM_TICK_TIME     19

#define SNDRV_TIMER_CLASS_NONE   (-1)
#define SNDRV_TIMER_CLASS_GLOBAL 1
#define SNDRV_TIMER_CLASS_PCM    3
#define SNDRV_TIMER_SCLASS_NONE  0
#define SNDRV_TIMER_GLOBAL_SYSTEM 0
#define SNDRV_TIMER_EVENT_TICK   1

#define SNDRV_CTL_ELEM_IFACE_MIXER 2
#define SNDRV_CTL_ELEM_TYPE_BOOLEAN 1
#define SNDRV_CTL_ELEM_TYPE_INTEGER 2
#define SNDRV_CTL_ELEM_ACCESS_READ  0x01u
#define SNDRV_CTL_ELEM_ACCESS_WRITE 0x02u
#define SNDRV_CTL_ELEM_ACCESS_READWRITE \
    (SNDRV_CTL_ELEM_ACCESS_READ | SNDRV_CTL_ELEM_ACCESS_WRITE)

#define EDGE_ALSA_CTL_MASTER_SWITCH 1u
#define EDGE_ALSA_CTL_MASTER_VOLUME 2u
#define EDGE_ALSA_CTL_COUNT 2u

struct snd_mask_compat {
    uint32_t bits[8];
};

struct snd_interval_compat {
    uint32_t min;
    uint32_t max;
    uint32_t flags;
};

struct snd_pcm_info_compat {
    uint32_t device;
    uint32_t subdevice;
    int32_t stream;
    int32_t card;
    uint8_t id[64];
    uint8_t name[80];
    uint8_t subname[32];
    int32_t dev_class;
    int32_t dev_subclass;
    uint32_t subdevices_count;
    uint32_t subdevices_avail;
    uint8_t pad1[16];
    uint8_t reserved[64];
};

struct snd_pcm_hw_params_compat {
    uint32_t flags;
    struct snd_mask_compat masks[3];
    struct snd_mask_compat mres[5];
    struct snd_interval_compat intervals[12];
    struct snd_interval_compat ires[9];
    uint32_t rmask;
    uint32_t cmask;
    uint32_t info;
    uint32_t msbits;
    uint32_t rate_num;
    uint32_t rate_den;
    edge_snd_pcm_uframes_t fifo_size;
    uint8_t sync[16];
    uint8_t reserved[48];
};

struct snd_pcm_sw_params_compat {
    int32_t tstamp_mode;
    uint32_t period_step;
    uint32_t sleep_min;
    edge_snd_pcm_uframes_t avail_min;
    edge_snd_pcm_uframes_t xfer_align;
    edge_snd_pcm_uframes_t start_threshold;
    edge_snd_pcm_uframes_t stop_threshold;
    edge_snd_pcm_uframes_t silence_threshold;
    edge_snd_pcm_uframes_t silence_size;
    edge_snd_pcm_uframes_t boundary;
    uint32_t proto;
    uint32_t tstamp_type;
    uint8_t reserved[56];
};

struct edge_timespec_compat {
    int64_t tv_sec;
    int64_t tv_nsec;
};

struct snd_pcm_status_compat {
    int32_t state;
    int32_t pad1;
    struct edge_timespec_compat trigger_tstamp;
    struct edge_timespec_compat tstamp;
    edge_snd_pcm_uframes_t appl_ptr;
    edge_snd_pcm_uframes_t hw_ptr;
    edge_snd_pcm_sframes_t delay;
    edge_snd_pcm_uframes_t avail;
    edge_snd_pcm_uframes_t avail_max;
    edge_snd_pcm_uframes_t overrange;
    int32_t suspended_state;
    uint32_t audio_tstamp_data;
    struct edge_timespec_compat audio_tstamp;
    struct edge_timespec_compat driver_tstamp;
    uint32_t audio_tstamp_accuracy;
    uint8_t reserved[20];
};

struct snd_pcm_mmap_status_compat {
    int32_t state;
    int32_t pad1;
    edge_snd_pcm_uframes_t hw_ptr;
    struct edge_timespec_compat tstamp;
    int32_t suspended_state;
    struct edge_timespec_compat audio_tstamp;
};

struct snd_pcm_mmap_control_compat {
    edge_snd_pcm_uframes_t appl_ptr;
    edge_snd_pcm_uframes_t avail_min;
};

struct snd_pcm_sync_ptr_compat {
    uint32_t flags;
    union {
        struct snd_pcm_mmap_status_compat status;
        uint8_t reserved[64];
    } s;
    union {
        struct snd_pcm_mmap_control_compat control;
        uint8_t reserved[64];
    } c;
};

struct snd_pcm_channel_info_compat {
    uint32_t channel;
    int64_t offset;
    uint32_t first;
    uint32_t step;
};

struct snd_ctl_card_info_compat {
    int32_t card;
    int32_t pad;
    uint8_t id[16];
    uint8_t driver[16];
    uint8_t name[32];
    uint8_t longname[80];
    uint8_t reserved_[16];
    uint8_t mixername[80];
    uint8_t components[128];
};

struct snd_ctl_elem_info_compat {
    struct edge_snd_ctl_elem_id id;
    int32_t type;
    uint32_t access;
    uint32_t count;
    int32_t owner;
    uint8_t value[128];
    uint8_t reserved[64];
};

struct snd_ctl_elem_value_compat {
    struct edge_snd_ctl_elem_id id;
    uint32_t indirect;
    uint32_t pad;
    uint8_t value[1024];
    uint8_t reserved[128];
};

struct snd_timer_id_compat {
    int32_t dev_class;
    int32_t dev_sclass;
    int32_t card;
    int32_t device;
    int32_t subdevice;
};

struct snd_timer_ginfo_compat {
    struct snd_timer_id_compat tid;
    uint32_t flags;
    int32_t card;
    uint8_t id[64];
    uint8_t name[80];
    uint64_t reserved0;
    uint64_t resolution;
    uint64_t resolution_min;
    uint64_t resolution_max;
    uint32_t clients;
    uint8_t reserved[32];
};

struct snd_timer_gparams_compat {
    struct snd_timer_id_compat tid;
    uint64_t period_num;
    uint64_t period_den;
    uint8_t reserved[32];
};

struct snd_timer_gstatus_compat {
    struct snd_timer_id_compat tid;
    uint64_t resolution;
    uint64_t resolution_num;
    uint64_t resolution_den;
    uint8_t reserved[32];
};

struct snd_timer_select_compat {
    struct snd_timer_id_compat id;
    uint8_t reserved[32];
};

struct snd_timer_info_compat {
    uint32_t flags;
    int32_t card;
    uint8_t id[64];
    uint8_t name[80];
    uint64_t reserved0;
    uint64_t resolution;
    uint8_t reserved[64];
};

struct snd_timer_params_compat {
    uint32_t flags;
    uint32_t ticks;
    uint32_t queue_size;
    uint32_t reserved0;
    uint32_t filter;
    uint8_t reserved[60];
};

struct snd_timer_status_compat {
    struct edge_timespec_compat tstamp;
    uint32_t resolution;
    uint32_t lost;
    uint32_t overrun;
    uint32_t queue;
    uint8_t reserved[64];
};

struct snd_timer_read_compat {
    uint32_t resolution;
    uint32_t ticks;
};

struct snd_timer_tread_compat {
    int32_t event;
    int32_t pad1;
    struct edge_timespec_compat tstamp;
    uint32_t val;
    uint32_t pad2;
};

struct alsa_pcm_runtime {
    uint64_t frames;
    int setup;
    int prepared;
    int running;
    int xrun;
    edge_snd_pcm_uframes_t avail_min;
    edge_snd_pcm_uframes_t boundary;
};

static struct alsa_pcm_runtime g_pcm_runtime[2] = {
    {
        .avail_min = 1024,
        .boundary = 0x40000000ul,
    },
    {
        .avail_min = 1024,
        .boundary = 0x40000000ul,
    },
};

static uint32_t g_alsa_open_descriptions[EDGE_ALSA_NODE_TIMER + 1u];

static struct {
    int selected;
    int running;
    int tread;
    uint32_t ticks_per_event;
    uint32_t queue_size;
    uint64_t resolution_ns;
    uint64_t last_us;
    struct snd_timer_id_compat id;
} g_alsa_timer = {
    .selected = 0,
    .running = 0,
    .tread = 0,
    .ticks_per_event = 1,
    .queue_size = 32,
    .resolution_ns = 1000000ull,
    .last_us = 0,
    .id = { SNDRV_TIMER_CLASS_GLOBAL, SNDRV_TIMER_SCLASS_NONE, -1, SNDRV_TIMER_GLOBAL_SYSTEM, 0 },
};

static void alsa_pcm_runtime_reset(struct alsa_pcm_runtime *runtime) {
    if (!runtime) return;
    memset(runtime, 0, sizeof(*runtime));
    runtime->avail_min = 1024;
    runtime->boundary = 0x40000000ul;
}

static void alsa_fill_timespec(struct edge_timespec_compat *ts) {
    uint64_t us = boottime_monotonic_us();
    ts->tv_sec = (int64_t)(us / 1000000ull);
    ts->tv_nsec = (int64_t)((us % 1000000ull) * 1000ull);
}

static uint64_t alsa_timer_period_us(void) {
    uint64_t ns = g_alsa_timer.resolution_ns * (uint64_t)(g_alsa_timer.ticks_per_event ? g_alsa_timer.ticks_per_event : 1u);
    uint64_t us = ns / 1000ull;
    return us ? us : 1ull;
}

int alsa_ioctl_type(uint32_t cmd) {
    return (int)ALSA_IOC_TYPE(cmd);
}

int alsa_ioctl_nr(uint32_t cmd) {
    return (int)ALSA_IOC_NR(cmd);
}

int alsa_playback_available(void) {
#if defined(CONFIG_AUDIO_AC97) || defined(CONFIG_AUDIO_HDA) || defined(CONFIG_USB_AUDIO) || defined(CONFIG_BSD_DRIVER_BRIDGE)
    return audio_available();
#else
    return 0;
#endif
}

int alsa_available(void) {
#if defined(CONFIG_AUDIO_AC97) || defined(CONFIG_AUDIO_HDA) || defined(CONFIG_USB_AUDIO) || defined(CONFIG_BSD_DRIVER_BRIDGE)
    return alsa_playback_available() || audio_capture_available();
#else
    return 0;
#endif
}

int alsa_capture_available(void) {
#if defined(CONFIG_AUDIO_AC97) || defined(CONFIG_AUDIO_HDA) || defined(CONFIG_USB_AUDIO) || defined(CONFIG_BSD_DRIVER_BRIDGE)
    return audio_capture_available();
#else
    return 0;
#endif
}

static const char *alsa_audio_identity(void) {
#if defined(CONFIG_AUDIO_AC97) || defined(CONFIG_AUDIO_HDA) || defined(CONFIG_USB_AUDIO) || defined(CONFIG_BSD_DRIVER_BRIDGE)
    return audio_available() ? audio_identity() : audio_capture_identity();
#else
    return "no audio";
#endif
}

const char *alsa_card_id(void) {
    return "EdgeOS";
}

const char *alsa_card_name(void) {
    return "EdgeOS PCM";
}

const char *alsa_card_longname(void) {
    return alsa_audio_identity();
}

static int alsa_audio_write_pcm(const char *buf, uint32_t len) {
#if defined(CONFIG_AUDIO_AC97) || defined(CONFIG_AUDIO_HDA) || defined(CONFIG_USB_AUDIO) || defined(CONFIG_BSD_DRIVER_BRIDGE)
    return audio_write_pcm(buf, len);
#else
    (void)buf;
    (void)len;
    return -ENODEV;
#endif
}

static int alsa_audio_read_pcm(char *buf, uint32_t len) {
#if defined(CONFIG_AUDIO_AC97) || defined(CONFIG_AUDIO_HDA) || defined(CONFIG_USB_AUDIO) || defined(CONFIG_BSD_DRIVER_BRIDGE)
    return audio_read_pcm(buf, len);
#else
    (void)buf;
    (void)len;
    return -ENODEV;
#endif
}

static int alsa_audio_stream_control(int stream, int command) {
#if defined(CONFIG_AUDIO_AC97) || defined(CONFIG_AUDIO_HDA) || defined(CONFIG_USB_AUDIO) || defined(CONFIG_BSD_DRIVER_BRIDGE)
    return audio_stream_control(
        stream == SNDRV_PCM_STREAM_CAPTURE ?
            AUDIO_STREAM_CAPTURE : AUDIO_STREAM_PLAYBACK,
        (uint8_t)command);
#else
    (void)stream;
    (void)command;
    return -ENODEV;
#endif
}

static void alsa_default_geometry(struct audio_pcm_geometry *geometry) {
    if (!geometry) return;
    memset(geometry, 0, sizeof(*geometry));
    geometry->rate = EDGE_ALSA_PCM_RATE;
    geometry->channels = EDGE_ALSA_PCM_CHANNELS;
    geometry->sample_bits = EDGE_ALSA_PCM_BITS;
    geometry->frame_bytes = EDGE_ALSA_PCM_FRAME_BYTES;
    geometry->period_bytes = 1024u * EDGE_ALSA_PCM_FRAME_BYTES;
    geometry->buffer_bytes = 65536u * EDGE_ALSA_PCM_FRAME_BYTES;
}

static void alsa_pcm_geometry(int stream,
                              struct audio_pcm_geometry *geometry) {
    int valid = 0;

    if (!geometry) return;
#if defined(CONFIG_AUDIO_AC97) || defined(CONFIG_AUDIO_HDA) || defined(CONFIG_USB_AUDIO) || defined(CONFIG_BSD_DRIVER_BRIDGE)
    if (audio_get_pcm_geometry(
            stream == SNDRV_PCM_STREAM_CAPTURE ?
                AUDIO_STREAM_CAPTURE : AUDIO_STREAM_PLAYBACK,
            geometry) == 0 &&
        geometry->rate && geometry->channels &&
        geometry->sample_bits && geometry->frame_bytes &&
        geometry->period_bytes && geometry->buffer_bytes &&
        geometry->queued_bytes <= geometry->buffer_bytes)
        valid = 1;
#else
    (void)stream;
#endif
    if (!valid) alsa_default_geometry(geometry);
}

static uint32_t alsa_geometry_frames(uint32_t bytes,
                                     uint32_t frame_bytes) {
    return frame_bytes ? bytes / frame_bytes : 0u;
}

int alsa_path_kind(const char *path) {
    if (!path) return EDGE_ALSA_NODE_NONE;
    if (strcmp(path, "/dev/snd") == 0) return EDGE_ALSA_NODE_SND_DIR;
    if (strcmp(path, EDGE_ALSA_PATH_CONTROL) == 0) return EDGE_ALSA_NODE_CONTROL;
    if (strcmp(path, EDGE_ALSA_PATH_PCM_PLAYBACK) == 0) return EDGE_ALSA_NODE_PCM_PLAYBACK;
    if (strcmp(path, EDGE_ALSA_PATH_PCM_CAPTURE) == 0) return EDGE_ALSA_NODE_PCM_CAPTURE;
    if (strcmp(path, EDGE_ALSA_PATH_TIMER) == 0) return EDGE_ALSA_NODE_TIMER;
    return EDGE_ALSA_NODE_NONE;
}

void alsa_open(const char *path) {
    int kind = alsa_path_kind(path);

    if (kind < EDGE_ALSA_NODE_CONTROL || kind > EDGE_ALSA_NODE_TIMER)
        return;
    if (g_alsa_open_descriptions[kind] != UINT32_MAX)
        g_alsa_open_descriptions[kind]++;
}

void alsa_close(const char *path) {
    int kind = alsa_path_kind(path);
    int stream;

    if (kind < EDGE_ALSA_NODE_CONTROL || kind > EDGE_ALSA_NODE_TIMER)
        return;
    if (!g_alsa_open_descriptions[kind])
        return;
    g_alsa_open_descriptions[kind]--;
    if (g_alsa_open_descriptions[kind])
        return;

    if (kind == EDGE_ALSA_NODE_PCM_PLAYBACK ||
        kind == EDGE_ALSA_NODE_PCM_CAPTURE) {
        stream = kind == EDGE_ALSA_NODE_PCM_CAPTURE ?
            SNDRV_PCM_STREAM_CAPTURE : SNDRV_PCM_STREAM_PLAYBACK;
        (void)alsa_audio_stream_control(
            stream, AUDIO_STREAM_COMMAND_RESET);
        alsa_pcm_runtime_reset(&g_pcm_runtime[stream]);
    } else if (kind == EDGE_ALSA_NODE_TIMER) {
        g_alsa_timer.selected = 0;
        g_alsa_timer.running = 0;
        g_alsa_timer.tread = 0;
        g_alsa_timer.ticks_per_event = 1;
        g_alsa_timer.queue_size = 32;
        g_alsa_timer.resolution_ns = 1000000ull;
        g_alsa_timer.last_us = 0;
        memset(&g_alsa_timer.id, 0, sizeof(g_alsa_timer.id));
        g_alsa_timer.id.dev_class = SNDRV_TIMER_CLASS_GLOBAL;
        g_alsa_timer.id.dev_sclass = SNDRV_TIMER_SCLASS_NONE;
        g_alsa_timer.id.card = -1;
        g_alsa_timer.id.device = SNDRV_TIMER_GLOBAL_SYSTEM;
    }
}

uint32_t alsa_dev_minor_from_kind(int kind) {
    switch (kind) {
        case EDGE_ALSA_NODE_CONTROL: return 0;
        case EDGE_ALSA_NODE_PCM_PLAYBACK: return 16;
        case EDGE_ALSA_NODE_PCM_CAPTURE: return 24;
        case EDGE_ALSA_NODE_TIMER: return 33;
        default: return 0;
    }
}

uint32_t alsa_inode_from_kind(int kind) {
    switch (kind) {
        case EDGE_ALSA_NODE_SND_DIR: return 0xD0FFA000u;
        case EDGE_ALSA_NODE_CONTROL: return 0xD0FFA001u;
        case EDGE_ALSA_NODE_PCM_PLAYBACK: return 0xD0FFA010u;
        case EDGE_ALSA_NODE_PCM_CAPTURE: return 0xD0FFA018u;
        case EDGE_ALSA_NODE_TIMER: return 0xD0FFA021u;
        default: return 0;
    }
}

static void alsa_copy_string(uint8_t *dst, uint32_t dst_len, const char *src) {
    uint32_t i = 0;
    if (!dst || !dst_len) return;
    if (!src) src = "";
    while (i + 1 < dst_len && src[i]) {
        dst[i] = (uint8_t)src[i];
        ++i;
    }
    dst[i] = 0;
}

static void alsa_append(char *dst, uint32_t dst_len, const char *src) {
    uint32_t off;
    if (!dst || !dst_len || !src) return;
    off = (uint32_t)strlen(dst);
    while (off + 1 < dst_len && *src) dst[off++] = *src++;
    dst[off] = 0;
}

static void alsa_append_u32(char *dst, uint32_t dst_len, uint32_t value) {
    char digits[11];
    uint32_t count = 0;

    do {
        digits[count++] = (char)('0' + value % 10u);
        value /= 10u;
    } while (value && count < sizeof(digits));
    while (count) {
        char character[2] = { digits[--count], 0 };
        alsa_append(dst, dst_len, character);
    }
}

static void alsa_fill_card_info(struct snd_ctl_card_info_compat *info) {
    memset(info, 0, sizeof(*info));
    info->card = 0;
    alsa_copy_string(info->id, sizeof(info->id), alsa_card_id());
    alsa_copy_string(info->driver, sizeof(info->driver), "EdgeOS");
    alsa_copy_string(info->name, sizeof(info->name), alsa_card_name());
    alsa_copy_string(info->longname, sizeof(info->longname), alsa_card_longname());
    alsa_copy_string(info->mixername, sizeof(info->mixername), "EdgeOS Mixer");
    alsa_copy_string(info->components, sizeof(info->components), alsa_audio_identity());
}

static int alsa_ctl_id_matches(const struct edge_snd_ctl_elem_id *id, uint32_t numid,
                               const char *name) {
    if (!id) return 0;
    if (id->numid != 0) return id->numid == numid;
    return id->iface == SNDRV_CTL_ELEM_IFACE_MIXER &&
           id->device == 0 && id->subdevice == 0 &&
           id->index == 0 && strcmp((const char *)id->name, name) == 0;
}

static int alsa_ctl_id_to_numid(const struct edge_snd_ctl_elem_id *id) {
    if (alsa_ctl_id_matches(id, EDGE_ALSA_CTL_MASTER_SWITCH, "Master Playback Switch")) {
        return EDGE_ALSA_CTL_MASTER_SWITCH;
    }
    if (alsa_ctl_id_matches(id, EDGE_ALSA_CTL_MASTER_VOLUME, "Master Playback Volume")) {
        return EDGE_ALSA_CTL_MASTER_VOLUME;
    }
    return 0;
}

int alsa_ctl_elem_id_for_index(uint32_t index, struct edge_snd_ctl_elem_id *out) {
    if (!out || index >= EDGE_ALSA_CTL_COUNT) return -ENOENT;
    memset(out, 0, sizeof(*out));
    out->numid = index + 1u;
    out->iface = SNDRV_CTL_ELEM_IFACE_MIXER;
    if (out->numid == EDGE_ALSA_CTL_MASTER_SWITCH) {
        alsa_copy_string(out->name, sizeof(out->name), "Master Playback Switch");
    } else {
        alsa_copy_string(out->name, sizeof(out->name), "Master Playback Volume");
    }
    return 0;
}

static int alsa_fill_ctl_elem_info(struct snd_ctl_elem_info_compat *info) {
    int numid;
    struct edge_snd_ctl_elem_id id;
    if (!info) return -EINVAL;
    numid = alsa_ctl_id_to_numid(&info->id);
    if (!numid) return -ENOENT;
    if (alsa_ctl_elem_id_for_index((uint32_t)numid - 1u, &id) < 0) return -ENOENT;
    memset(info, 0, sizeof(*info));
    info->id = id;
    info->access = SNDRV_CTL_ELEM_ACCESS_READWRITE;
    if ((uint32_t)numid == EDGE_ALSA_CTL_MASTER_SWITCH) {
        info->type = SNDRV_CTL_ELEM_TYPE_BOOLEAN;
        info->count = 1;
        ((int64_t *)info->value)[0] = 0;
        ((int64_t *)info->value)[1] = 1;
        ((int64_t *)info->value)[2] = 0;
    } else {
        info->type = SNDRV_CTL_ELEM_TYPE_INTEGER;
        info->count = 2;
        ((int64_t *)info->value)[0] = 0;
        ((int64_t *)info->value)[1] = 100;
        ((int64_t *)info->value)[2] = 1;
    }
    return 0;
}

static int alsa_read_ctl_elem(struct snd_ctl_elem_value_compat *val) {
    uint8_t muted = 0;
    uint8_t left = 100;
    uint8_t right = 100;
    int numid;
    if (!val) return -EINVAL;
    numid = alsa_ctl_id_to_numid(&val->id);
    if (!numid) return -ENOENT;
    audio_get_playback_control(&muted, &left, &right);
    memset(val->value, 0, sizeof(val->value));
    if ((uint32_t)numid == EDGE_ALSA_CTL_MASTER_SWITCH) {
        ((int64_t *)val->value)[0] = muted ? 0 : 1;
    } else {
        ((int64_t *)val->value)[0] = left;
        ((int64_t *)val->value)[1] = right;
    }
    return 0;
}

static int alsa_write_ctl_elem(struct snd_ctl_elem_value_compat *val) {
    uint8_t muted = 0;
    uint8_t left = 100;
    uint8_t right = 100;
    int numid;
    if (!val) return -EINVAL;
    numid = alsa_ctl_id_to_numid(&val->id);
    if (!numid) return -ENOENT;
    audio_get_playback_control(&muted, &left, &right);
    if ((uint32_t)numid == EDGE_ALSA_CTL_MASTER_SWITCH) {
        muted = ((int64_t *)val->value)[0] ? 0u : 1u;
    } else {
        int64_t l = ((int64_t *)val->value)[0];
        int64_t r = ((int64_t *)val->value)[1];
        if (l < 0) l = 0;
        if (r < 0) r = 0;
        if (l > 100) l = 100;
        if (r > 100) r = 100;
        left = (uint8_t)l;
        right = (uint8_t)r;
    }
    audio_set_playback_control(muted, left, right);
    return alsa_read_ctl_elem(val);
}

static void alsa_fill_pcm_info(struct snd_pcm_info_compat *info, int control) {
    uint32_t device = info ? info->device : 0;
    uint32_t subdevice = info ? info->subdevice : 0;
    int32_t stream = info ? info->stream : SNDRV_PCM_STREAM_PLAYBACK;
    memset(info, 0, sizeof(*info));
    info->device = device;
    info->subdevice = subdevice;
    info->stream = stream;
    info->card = 0;
    alsa_copy_string(info->id, sizeof(info->id), "edgeos-pcm0");
    alsa_copy_string(info->name, sizeof(info->name), alsa_audio_identity());
    alsa_copy_string(info->subname, sizeof(info->subname), "subdevice #0");
    info->dev_class = SNDRV_PCM_CLASS_GENERIC;
    info->dev_subclass = SNDRV_PCM_SUBCLASS_GENERIC_MIX;
    info->subdevices_count = 1;
    if (stream == SNDRV_PCM_STREAM_CAPTURE) {
        info->subdevices_avail = alsa_capture_available() ? 1u : 0u;
    } else {
        info->subdevices_avail = alsa_playback_available() ? 1u : 0u;
    }
    if (control && info->subdevices_avail == 0)
        info->subdevices_count = 0;
}

static void alsa_mask_single(struct snd_mask_compat *m, uint32_t bit) {
    memset(m, 0, sizeof(*m));
    if (bit < 256u) m->bits[bit >> 5] = 1u << (bit & 31u);
}

static void alsa_interval_set(struct snd_interval_compat *iv, uint32_t min, uint32_t max) {
    iv->min = min;
    iv->max = max;
    iv->flags = (min == max) ? 4u : 0u; /* integer */
}

static void alsa_fill_hw_params(struct snd_pcm_hw_params_compat *p,
                                int stream) {
    struct audio_pcm_geometry geometry;
    uint32_t period_frames;
    uint32_t buffer_frames;
    uint32_t periods;
    uint32_t period_time;
    uint32_t buffer_time;

    alsa_pcm_geometry(stream, &geometry);
    period_frames = alsa_geometry_frames(
        geometry.period_bytes, geometry.frame_bytes);
    buffer_frames = alsa_geometry_frames(
        geometry.buffer_bytes, geometry.frame_bytes);
    if (!period_frames) period_frames = 1u;
    if (!buffer_frames) buffer_frames = period_frames;
    periods = geometry.period_bytes ?
        geometry.buffer_bytes / geometry.period_bytes : 1u;
    if (!periods) periods = 1u;
    period_time = geometry.rate ?
        (uint32_t)(((uint64_t)period_frames * 1000000u) /
                   geometry.rate) : 0u;
    buffer_time = geometry.rate ?
        (uint32_t)(((uint64_t)buffer_frames * 1000000u) /
                   geometry.rate) : 0u;
    memset(p, 0, sizeof(*p));
    alsa_mask_single(&p->masks[SNDRV_PCM_HW_PARAM_ACCESS], SNDRV_PCM_ACCESS_RW_INTERLEAVED);
    alsa_mask_single(&p->masks[SNDRV_PCM_HW_PARAM_FORMAT], SNDRV_PCM_FORMAT_S16_LE);
    alsa_mask_single(&p->masks[SNDRV_PCM_HW_PARAM_SUBFORMAT], SNDRV_PCM_SUBFORMAT_STD);
    alsa_interval_set(&p->intervals[SNDRV_PCM_HW_PARAM_SAMPLE_BITS - 8],
                      geometry.sample_bits, geometry.sample_bits);
    alsa_interval_set(&p->intervals[SNDRV_PCM_HW_PARAM_FRAME_BITS - 8],
                      geometry.frame_bytes * 8u,
                      geometry.frame_bytes * 8u);
    alsa_interval_set(&p->intervals[SNDRV_PCM_HW_PARAM_CHANNELS - 8],
                      geometry.channels, geometry.channels);
    alsa_interval_set(&p->intervals[SNDRV_PCM_HW_PARAM_RATE - 8],
                      geometry.rate, geometry.rate);
    alsa_interval_set(&p->intervals[SNDRV_PCM_HW_PARAM_PERIOD_TIME - 8],
                      period_time, period_time);
    alsa_interval_set(&p->intervals[SNDRV_PCM_HW_PARAM_PERIOD_SIZE - 8],
                      period_frames, period_frames);
    alsa_interval_set(&p->intervals[SNDRV_PCM_HW_PARAM_PERIOD_BYTES - 8],
                      geometry.period_bytes, geometry.period_bytes);
    alsa_interval_set(&p->intervals[SNDRV_PCM_HW_PARAM_PERIODS - 8],
                      periods, periods);
    alsa_interval_set(&p->intervals[SNDRV_PCM_HW_PARAM_BUFFER_TIME - 8],
                      buffer_time, buffer_time);
    alsa_interval_set(&p->intervals[SNDRV_PCM_HW_PARAM_BUFFER_SIZE - 8],
                      buffer_frames, buffer_frames);
    alsa_interval_set(&p->intervals[SNDRV_PCM_HW_PARAM_BUFFER_BYTES - 8],
                      geometry.buffer_bytes, geometry.buffer_bytes);
    alsa_interval_set(&p->intervals[SNDRV_PCM_HW_PARAM_TICK_TIME - 8], 0, 0);
    p->cmask = 0xffffffffu;
    /*
     * PulseAudio and PipeWire trust SNDRV_PCM_INFO_MMAP/MMAP_VALID and will
     * select mmap mode when it is advertised.  EdgeOS currently exposes a
     * writei-style stream backed by the active kernel audio backend; there is
     * no Linux-compatible shared PCM ring buffer yet.  Keep the capabilities
     * truthful so userspace falls back to snd_pcm_writei instead of mmaping a
     * device that cannot maintain appl_ptr/hw_ptr coherently.
     */
    p->info = SNDRV_PCM_INFO_INTERLEAVED | SNDRV_PCM_INFO_BLOCK_TRANSFER |
              SNDRV_PCM_INFO_BATCH;
    p->msbits = geometry.sample_bits;
    p->rate_num = geometry.rate;
    p->rate_den = 1;
}

static void alsa_fill_sw_params(struct snd_pcm_sw_params_compat *p,
                                const struct alsa_pcm_runtime *runtime,
                                int stream) {
    struct audio_pcm_geometry geometry;

    alsa_pcm_geometry(stream, &geometry);
    memset(p, 0, sizeof(*p));
    p->period_step = 1;
    p->avail_min = runtime->avail_min;
    p->start_threshold = 1;
    p->stop_threshold = alsa_geometry_frames(
        geometry.buffer_bytes, geometry.frame_bytes);
    p->boundary = runtime->boundary;
    p->proto = SNDRV_PCM_VERSION;
}

static void alsa_fill_status(struct snd_pcm_status_compat *st,
                             const struct alsa_pcm_runtime *runtime,
                             int stream) {
    struct audio_pcm_geometry geometry;
    uint32_t queued_frames;
    uint32_t buffer_frames;

    alsa_pcm_geometry(stream, &geometry);
    queued_frames = alsa_geometry_frames(
        geometry.queued_bytes, geometry.frame_bytes);
    buffer_frames = alsa_geometry_frames(
        geometry.buffer_bytes, geometry.frame_bytes);
    memset(st, 0, sizeof(*st));
    st->state = runtime->xrun ? SNDRV_PCM_STATE_XRUN :
                (runtime->running ? SNDRV_PCM_STATE_RUNNING :
                (runtime->prepared ? SNDRV_PCM_STATE_PREPARED :
                (runtime->setup ? SNDRV_PCM_STATE_SETUP : SNDRV_PCM_STATE_OPEN)));
    alsa_fill_timespec(&st->tstamp);
    st->driver_tstamp = st->tstamp;
    st->appl_ptr = runtime->frames;
    st->hw_ptr = stream == SNDRV_PCM_STREAM_PLAYBACK &&
                 runtime->frames >= queued_frames ?
                     runtime->frames - queued_frames : runtime->frames;
    st->delay = stream == SNDRV_PCM_STREAM_PLAYBACK ?
        (edge_snd_pcm_sframes_t)queued_frames : 0;
    st->avail = stream == SNDRV_PCM_STREAM_CAPTURE ?
        queued_frames : buffer_frames - queued_frames;
    st->avail_max = buffer_frames;
}

static void alsa_fill_mmap_status(struct snd_pcm_mmap_status_compat *st,
                                  const struct alsa_pcm_runtime *runtime,
                                  int stream) {
    struct audio_pcm_geometry geometry;
    uint32_t queued_frames;

    alsa_pcm_geometry(stream, &geometry);
    queued_frames = alsa_geometry_frames(
        geometry.queued_bytes, geometry.frame_bytes);
    memset(st, 0, sizeof(*st));
    st->state = runtime->xrun ? SNDRV_PCM_STATE_XRUN :
                (runtime->running ? SNDRV_PCM_STATE_RUNNING :
                (runtime->prepared ? SNDRV_PCM_STATE_PREPARED :
                (runtime->setup ? SNDRV_PCM_STATE_SETUP : SNDRV_PCM_STATE_OPEN)));
    st->hw_ptr = stream == SNDRV_PCM_STREAM_PLAYBACK &&
                 runtime->frames >= queued_frames ?
                     runtime->frames - queued_frames : runtime->frames;
    alsa_fill_timespec(&st->tstamp);
    st->audio_tstamp = st->tstamp;
}

static void alsa_apply_sw_params(const struct snd_pcm_sw_params_compat *p,
                                  struct alsa_pcm_runtime *runtime) {
    if (!p) return;
    if (p->avail_min) runtime->avail_min = p->avail_min;
    if (p->boundary) runtime->boundary = p->boundary;
}

static void alsa_fill_channel_info(struct snd_pcm_channel_info_compat *ci) {
    uint32_t ch = ci ? ci->channel : 0;
    memset(ci, 0, sizeof(*ci));
    if (ch >= EDGE_ALSA_PCM_CHANNELS) {
        ci->channel = ch;
        return;
    }
    ci->channel = ch;
    /*
     * EdgeOS exposes only RW_INTERLEAVED PCM today.  ALSA still permits
     * userspace to ask channel geometry during capability probing; report the
     * real interleaved sample layout while keeping mmap capability disabled.
     */
    ci->offset = 0;
    ci->first = ch * EDGE_ALSA_PCM_BITS;
    ci->step = EDGE_ALSA_PCM_FRAME_BYTES * 8u;
}

static int alsa_timer_id_supported(const struct snd_timer_id_compat *id) {
    if (!id) return 0;
    if (id->dev_class == SNDRV_TIMER_CLASS_GLOBAL &&
        id->dev_sclass == SNDRV_TIMER_SCLASS_NONE &&
        id->card == -1 &&
        id->device == SNDRV_TIMER_GLOBAL_SYSTEM) return 1;
    if (id->dev_class == SNDRV_TIMER_CLASS_PCM &&
        id->card == 0 && id->device == 0 && id->subdevice == 0) return 1;
    return 0;
}

static void alsa_timer_fill_id_strings(uint8_t *id, uint32_t id_len,
                                       uint8_t *name, uint32_t name_len,
                                       const struct snd_timer_id_compat *tid) {
    if (tid && tid->dev_class == SNDRV_TIMER_CLASS_PCM) {
        alsa_copy_string(id, id_len, "PCM playback");
        alsa_copy_string(name, name_len, "EdgeOS PCM playback timer");
    } else {
        alsa_copy_string(id, id_len, "system");
        alsa_copy_string(name, name_len, "EdgeOS system timer");
    }
}

static uint32_t alsa_timer_pending_ticks(void) {
    uint64_t now_us;
    uint64_t delta;
    uint64_t period;
    if (!g_alsa_timer.running) return 0;
    now_us = boottime_monotonic_us();
    if (g_alsa_timer.last_us == 0 || now_us <= g_alsa_timer.last_us) return 0;
    delta = now_us - g_alsa_timer.last_us;
    period = alsa_timer_period_us();
    if (delta < period) return 0;
    delta /= period;
    if (delta > 0xffffffffull) delta = 0xffffffffull;
    return (uint32_t)delta;
}

static void alsa_timer_consume_ticks(uint32_t ticks) {
    uint64_t advance;
    if (!ticks) return;
    advance = alsa_timer_period_us() * (uint64_t)ticks;
    g_alsa_timer.last_us += advance;
    if (g_alsa_timer.last_us > boottime_monotonic_us()) g_alsa_timer.last_us = boottime_monotonic_us();
}

static void alsa_timer_fill_ginfo(struct snd_timer_ginfo_compat *gi) {
    struct snd_timer_id_compat tid = gi->tid;
    memset(gi, 0, sizeof(*gi));
    gi->tid = tid;
    gi->card = tid.dev_class == SNDRV_TIMER_CLASS_PCM ? 0 : -1;
    alsa_timer_fill_id_strings(gi->id, sizeof(gi->id), gi->name, sizeof(gi->name), &tid);
    gi->resolution = g_alsa_timer.resolution_ns;
    gi->resolution_min = g_alsa_timer.resolution_ns;
    gi->resolution_max = g_alsa_timer.resolution_ns;
    gi->clients = g_alsa_timer.selected ? 1u : 0u;
}

static void alsa_timer_fill_info(struct snd_timer_info_compat *info) {
    memset(info, 0, sizeof(*info));
    info->card = g_alsa_timer.id.dev_class == SNDRV_TIMER_CLASS_PCM ? 0 : -1;
    alsa_timer_fill_id_strings(info->id, sizeof(info->id), info->name, sizeof(info->name), &g_alsa_timer.id);
    info->resolution = g_alsa_timer.resolution_ns;
}

static void alsa_timer_fill_status(struct snd_timer_status_compat *st) {
    memset(st, 0, sizeof(*st));
    alsa_fill_timespec(&st->tstamp);
    st->resolution = (uint32_t)g_alsa_timer.resolution_ns;
    st->queue = alsa_timer_pending_ticks() ? 1u : 0u;
}

static const char *alsa_pcm_state_name(const struct alsa_pcm_runtime *runtime) {
    if (runtime->xrun) return "XRUN";
    if (runtime->running) return "RUNNING";
    if (runtime->prepared) return "PREPARED";
    if (runtime->setup) return "SETUP";
    return "OPEN";
}

int alsa_read(const char *path, char *out, uint32_t max) {
    uint32_t ticks;
    if (alsa_path_kind(path) == EDGE_ALSA_NODE_PCM_CAPTURE) {
        struct alsa_pcm_runtime *runtime =
            &g_pcm_runtime[SNDRV_PCM_STREAM_CAPTURE];
        int rc;
        if (!alsa_capture_available()) return -ENODEV;
        if (!out && max) return -EINVAL;
        rc = alsa_audio_read_pcm(out, max);
        if (rc > 0) {
            runtime->setup = 1;
            runtime->prepared = 1;
            runtime->running = 1;
            runtime->xrun = 0;
            runtime->frames += (uint32_t)rc / EDGE_ALSA_PCM_FRAME_BYTES;
        }
        return rc;
    }
    if (alsa_path_kind(path) == EDGE_ALSA_NODE_TIMER) {
        if (!out) return -EINVAL;
        if (!g_alsa_timer.running) return -EAGAIN;
        ticks = alsa_timer_pending_ticks();
        if (!ticks) return -EAGAIN;
        alsa_timer_consume_ticks(ticks);
        if (g_alsa_timer.tread) {
            struct snd_timer_tread_compat ev;
            if (max < sizeof(ev)) return -EINVAL;
            memset(&ev, 0, sizeof(ev));
            ev.event = SNDRV_TIMER_EVENT_TICK;
            alsa_fill_timespec(&ev.tstamp);
            ev.val = ticks;
            memcpy(out, &ev, sizeof(ev));
            return (int)sizeof(ev);
        } else {
            struct snd_timer_read_compat ev;
            if (max < sizeof(ev)) return -EINVAL;
            ev.resolution = (uint32_t)g_alsa_timer.resolution_ns;
            ev.ticks = ticks;
            memcpy(out, &ev, sizeof(ev));
            return (int)sizeof(ev);
        }
    }
    return -ENOSYS;
}

int alsa_poll_read_ready(const char *path) {
    int kind = alsa_path_kind(path);
    if (kind == EDGE_ALSA_NODE_PCM_CAPTURE) {
#if defined(CONFIG_AUDIO_AC97) || defined(CONFIG_AUDIO_HDA) || defined(CONFIG_USB_AUDIO) || defined(CONFIG_BSD_DRIVER_BRIDGE)
        return audio_capture_ready();
#else
        return 0;
#endif
    }
    if (kind == EDGE_ALSA_NODE_TIMER) return alsa_timer_pending_ticks() != 0;
    return 0;
}

int alsa_poll_write_ready(const char *path) {
    int kind = alsa_path_kind(path);
    if (kind == EDGE_ALSA_NODE_PCM_CAPTURE) return 0;
    if (kind == EDGE_ALSA_NODE_PCM_PLAYBACK) {
#if defined(CONFIG_AUDIO_AC97) || defined(CONFIG_AUDIO_HDA) || defined(CONFIG_USB_AUDIO) || defined(CONFIG_BSD_DRIVER_BRIDGE)
        return audio_playback_ready();
#else
        return 0;
#endif
    }
    return kind == EDGE_ALSA_NODE_CONTROL || kind == EDGE_ALSA_NODE_TIMER;
}

int alsa_write(const char *path, const char *buf, uint32_t len) {
    struct alsa_pcm_runtime *runtime =
        &g_pcm_runtime[SNDRV_PCM_STREAM_PLAYBACK];
    if (!alsa_available()) return -ENODEV;
    if (alsa_path_kind(path) != EDGE_ALSA_NODE_PCM_PLAYBACK) return -EINVAL;
    if (len == 0) return 0;
    int rc = alsa_audio_write_pcm(buf, len);
    if (rc > 0) {
        runtime->setup = 1;
        runtime->prepared = 1;
        runtime->running = 1;
        runtime->xrun = 0;
        runtime->frames += (uint32_t)rc / EDGE_ALSA_PCM_FRAME_BYTES;
    }
    return rc;
}

static int alsa_ctl_ioctl(uint32_t nr, void *arg) {
    if (!arg) return -EINVAL;
    switch (nr) {
        case 0x00:
            *(int *)arg = SNDRV_CTL_VERSION;
            return 0;
        case 0x01:
            alsa_fill_card_info((struct snd_ctl_card_info_compat *)arg);
            return 0;
        case 0x10: {
            struct edge_snd_ctl_elem_list *list = (struct edge_snd_ctl_elem_list *)arg;
            /*
             * Expose only controls that change real audio state.  The ids
             * themselves are copied to list->pids by the syscall layer because
             * that pointer is a Linux userspace address, not a kernel pointer.
             */
            list->count = EDGE_ALSA_CTL_COUNT;
            list->used = 0;
            if (list->offset < EDGE_ALSA_CTL_COUNT) {
                uint32_t avail = EDGE_ALSA_CTL_COUNT - list->offset;
                list->used = list->space < avail ? list->space : avail;
            }
            return 0;
        }
        case 0x11:
            return alsa_fill_ctl_elem_info((struct snd_ctl_elem_info_compat *)arg);
        case 0x12:
            return alsa_read_ctl_elem((struct snd_ctl_elem_value_compat *)arg);
        case 0x13:
            return alsa_write_ctl_elem((struct snd_ctl_elem_value_compat *)arg);
        case 0x14:
        case 0x15:
            return -ENOENT;
        case 0x16:
            *(int *)arg = 0;
            return 0;
        case 0x20:
        case 0x30:
        case 0x40: {
            int *dev = (int *)arg;
            if (*dev < 0) {
                *dev = (nr == 0x30) ? 0 : -1;
                return 0;
            }
            *dev = -1;
            return 0;
        }
        case 0x31: {
            struct snd_pcm_info_compat *info = (struct snd_pcm_info_compat *)arg;
            if (info->device != 0 || info->subdevice != 0 ||
                (info->stream == SNDRV_PCM_STREAM_PLAYBACK ?
                 !alsa_playback_available() :
                 (info->stream == SNDRV_PCM_STREAM_CAPTURE ?
                  !alsa_capture_available() : 1))) return -ENODEV;
            alsa_fill_pcm_info(info, 1);
            return 0;
        }
        case 0x32:
        case 0x42:
            return 0;
        case 0xd0:
            return 0;
        case 0xd1:
            *(int *)arg = 0;
            return 0;
        default:
            return -ENOSYS;
    }
}

static int alsa_pcm_ioctl(int kind, uint32_t nr, void *arg) {
    int stream = kind == EDGE_ALSA_NODE_PCM_CAPTURE ?
        SNDRV_PCM_STREAM_CAPTURE : SNDRV_PCM_STREAM_PLAYBACK;
    struct alsa_pcm_runtime *runtime = &g_pcm_runtime[stream];
    if (!alsa_available()) return -ENODEV;
    if (stream == SNDRV_PCM_STREAM_CAPTURE && !alsa_capture_available())
        return -ENODEV;
    if (stream == SNDRV_PCM_STREAM_PLAYBACK && !alsa_playback_available())
        return -ENODEV;
    switch (nr) {
        case 0x00:
        case 0x04:
            if (!arg) return -EINVAL;
            *(int *)arg = SNDRV_PCM_VERSION;
            return 0;
        case 0x01:
            if (!arg) return -EINVAL;
            ((struct snd_pcm_info_compat *)arg)->stream = stream;
            alsa_fill_pcm_info((struct snd_pcm_info_compat *)arg, 0);
            return 0;
        case 0x02:
        case 0x03:
            return 0;
        case 0x10:
        case 0x11:
            if (!arg) return -EINVAL;
            alsa_fill_hw_params(
                (struct snd_pcm_hw_params_compat *)arg, stream);
            runtime->setup = 1;
            runtime->prepared = 0;
            runtime->running = 0;
            runtime->xrun = 0;
            return 0;
        case 0x12:
            (void)alsa_audio_stream_control(
                stream, AUDIO_STREAM_COMMAND_RESET);
            runtime->setup = 0;
            runtime->prepared = 0;
            runtime->running = 0;
            runtime->xrun = 0;
            return 0;
        case 0x13:
            if (!arg) return -EINVAL;
            alsa_apply_sw_params((const struct snd_pcm_sw_params_compat *)arg,
                                 runtime);
            alsa_fill_sw_params((struct snd_pcm_sw_params_compat *)arg,
                                runtime, stream);
            return 0;
        case 0x20:
        case 0x24:
            if (!arg) return -EINVAL;
            alsa_fill_status(
                (struct snd_pcm_status_compat *)arg, runtime, stream);
            return 0;
        case 0x21:
            if (!arg) return -EINVAL;
            *(edge_snd_pcm_sframes_t *)arg = 0;
            return 0;
        case 0x22:
            return 0;
        case 0x23: {
            struct snd_pcm_sync_ptr_compat *sp = (struct snd_pcm_sync_ptr_compat *)arg;
            if (!arg) return -EINVAL;
            /*
             * SYNC_PTR is how ALSA-lib keeps mmap and direct-write clients in
             * sync.  We do not expose mmap, but PulseAudio/PipeWire still use
             * this ioctl while selecting a plugin path.  Return coherent
             * pointers for the writei stream instead of pretending the ioctl
             * does not exist.
             */
            sp->c.control.appl_ptr = runtime->frames;
            sp->c.control.avail_min = runtime->avail_min;
            alsa_fill_mmap_status(&sp->s.status, runtime, stream);
            return 0;
        }
        case 0x40:
            if (alsa_audio_stream_control(
                    stream, AUDIO_STREAM_COMMAND_RESET) < 0)
                return -ENODEV;
            runtime->setup = 1;
            runtime->prepared = 1;
            runtime->running = 0;
            runtime->xrun = 0;
            return 0;
        case 0x41:
            if (alsa_audio_stream_control(
                    stream, AUDIO_STREAM_COMMAND_RESET) < 0)
                return -ENODEV;
            runtime->frames = 0;
            runtime->running = 0;
            runtime->xrun = 0;
            return 0;
        case 0x42:
            if (alsa_audio_stream_control(
                    stream, AUDIO_STREAM_COMMAND_START) < 0)
                return -ENODEV;
            runtime->setup = 1;
            runtime->running = 1;
            runtime->prepared = 1;
            runtime->xrun = 0;
            return 0;
        case 0x43:
            if (alsa_audio_stream_control(
                    stream, AUDIO_STREAM_COMMAND_RESET) < 0)
                return -ENODEV;
            runtime->running = 0;
            runtime->prepared = 0;
            runtime->setup = 1;
            return 0;
        case 0x44:
            {
                int result = alsa_audio_stream_control(
                    stream, AUDIO_STREAM_COMMAND_DRAIN);
                if (result < 0) return result;
            }
            runtime->running = 0;
            return 0;
        case 0x45:
            if (arg && *(int *)arg) {
                if (alsa_audio_stream_control(
                        stream, AUDIO_STREAM_COMMAND_STOP) < 0)
                    return -ENODEV;
                runtime->running = 0;
            } else if (runtime->prepared) {
                if (alsa_audio_stream_control(
                        stream, AUDIO_STREAM_COMMAND_START) < 0)
                    return -ENODEV;
                runtime->running = 1;
            }
            return 0;
        case 0x46:
        case 0x47:
            return 0;
        case 0x48:
            runtime->xrun = 1;
            runtime->running = 0;
            return 0;
        case 0x49:
            if (arg) runtime->frames += *(edge_snd_pcm_uframes_t *)arg;
            return 0;
        case 0x50:
            /*
             * The syscall layer handles WRITEI_FRAMES because snd_xferi.buf is
             * a userspace pointer that must be copied in chunks before routing
             * to alsa_write().  Reaching this generic ioctl path means the
             * caller did not provide that Linux userspace context.
             */
            return -EINVAL;
        case 0x51:
            /*
             * The syscall layer handles READI_FRAMES because snd_xferi.buf is
             * a userspace pointer that must be copied out after capture.
             */
            return -EINVAL;
        case 0x52:
        case 0x53:
            return -EINVAL;
        case 0x60:
        case 0x61:
            return 0;
        case 0x32:
            if (!arg) return -EINVAL;
            if (((struct snd_pcm_channel_info_compat *)arg)->channel >= EDGE_ALSA_PCM_CHANNELS) return -EINVAL;
            alsa_fill_channel_info((struct snd_pcm_channel_info_compat *)arg);
            return 0;
        default:
            return -ENOSYS;
    }
}

static int alsa_timer_ioctl(uint32_t nr, void *arg) {
    switch (nr) {
        case 0x00:
            if (!arg) return -EINVAL;
            *(int *)arg = SNDRV_TIMER_VERSION;
            return 0;
        case 0x01: {
            struct snd_timer_id_compat *id = (struct snd_timer_id_compat *)arg;
            if (!arg) return -EINVAL;
            if (id->dev_class < 0) {
                id->dev_class = SNDRV_TIMER_CLASS_GLOBAL;
                id->dev_sclass = SNDRV_TIMER_SCLASS_NONE;
                id->card = -1;
                id->device = SNDRV_TIMER_GLOBAL_SYSTEM;
                id->subdevice = 0;
                return 0;
            }
            id->dev_class = SNDRV_TIMER_CLASS_NONE;
            id->dev_sclass = SNDRV_TIMER_SCLASS_NONE;
            id->card = -1;
            id->device = -1;
            id->subdevice = -1;
            return 0;
        }
        case 0x02:
        case 0xa4:
            if (!arg) return -EINVAL;
            g_alsa_timer.tread = (*(int *)arg != 0);
            return 0;
        case 0x03: {
            struct snd_timer_ginfo_compat *gi = (struct snd_timer_ginfo_compat *)arg;
            if (!arg) return -EINVAL;
            if (!alsa_timer_id_supported(&gi->tid)) return -ENODEV;
            alsa_timer_fill_ginfo(gi);
            return 0;
        }
        case 0x04: {
            struct snd_timer_gparams_compat *gp = (struct snd_timer_gparams_compat *)arg;
            if (!arg) return -EINVAL;
            if (!alsa_timer_id_supported(&gp->tid)) return -ENODEV;
            return 0;
        }
        case 0x05: {
            struct snd_timer_gstatus_compat *gs = (struct snd_timer_gstatus_compat *)arg;
            struct snd_timer_id_compat tid;
            if (!arg) return -EINVAL;
            if (!alsa_timer_id_supported(&gs->tid)) return -ENODEV;
            tid = gs->tid;
            memset(gs, 0, sizeof(*gs));
            gs->tid = tid;
            gs->resolution = g_alsa_timer.resolution_ns;
            gs->resolution_num = 1;
            gs->resolution_den =
                1000000000ull / g_alsa_timer.resolution_ns;
            return 0;
        }
        case 0x10: {
            struct snd_timer_select_compat *sel = (struct snd_timer_select_compat *)arg;
            if (!arg) return -EINVAL;
            if (!alsa_timer_id_supported(&sel->id)) return -ENODEV;
            g_alsa_timer.id = sel->id;
            g_alsa_timer.selected = 1;
            g_alsa_timer.running = 0;
            g_alsa_timer.last_us = 0;
            return 0;
        }
        case 0x11:
            if (!arg) return -EINVAL;
            if (!g_alsa_timer.selected) {
                g_alsa_timer.id.dev_class = SNDRV_TIMER_CLASS_GLOBAL;
                g_alsa_timer.id.dev_sclass = SNDRV_TIMER_SCLASS_NONE;
                g_alsa_timer.id.card = -1;
                g_alsa_timer.id.device = SNDRV_TIMER_GLOBAL_SYSTEM;
                g_alsa_timer.id.subdevice = 0;
                g_alsa_timer.selected = 1;
            }
            alsa_timer_fill_info((struct snd_timer_info_compat *)arg);
            return 0;
        case 0x12: {
            struct snd_timer_params_compat *p = (struct snd_timer_params_compat *)arg;
            if (!arg) return -EINVAL;
            if (p->ticks) g_alsa_timer.ticks_per_event = p->ticks;
            if (p->queue_size >= 32 && p->queue_size <= 1024) g_alsa_timer.queue_size = p->queue_size;
            p->ticks = g_alsa_timer.ticks_per_event;
            p->queue_size = g_alsa_timer.queue_size;
            return 0;
        }
        case 0x14:
            if (!arg) return -EINVAL;
            alsa_timer_fill_status((struct snd_timer_status_compat *)arg);
            return 0;
        case 0xa0:
        case 0xa2:
            if (!g_alsa_timer.selected) {
                g_alsa_timer.id.dev_class = SNDRV_TIMER_CLASS_GLOBAL;
                g_alsa_timer.id.dev_sclass = SNDRV_TIMER_SCLASS_NONE;
                g_alsa_timer.id.card = -1;
                g_alsa_timer.id.device = SNDRV_TIMER_GLOBAL_SYSTEM;
                g_alsa_timer.id.subdevice = 0;
                g_alsa_timer.selected = 1;
            }
            g_alsa_timer.running = 1;
            g_alsa_timer.last_us = boottime_monotonic_us();
            return 0;
        case 0xa1:
        case 0xa3:
            g_alsa_timer.running = 0;
            return 0;
        case 0xa5:
        case 0xa6:
            return -ENOSYS;
        default:
            return -ENOSYS;
    }
}

int alsa_ioctl_kernel(const char *path, uint32_t cmd, void *arg) {
    int kind = alsa_path_kind(path);
    int type = alsa_ioctl_type(cmd);
    int nr = alsa_ioctl_nr(cmd);
    if (kind == EDGE_ALSA_NODE_CONTROL && type == 'U') return alsa_ctl_ioctl((uint32_t)nr, arg);
    if ((kind == EDGE_ALSA_NODE_PCM_PLAYBACK ||
         kind == EDGE_ALSA_NODE_PCM_CAPTURE) && type == 'A')
        return alsa_pcm_ioctl(kind, (uint32_t)nr, arg);
    if (kind == EDGE_ALSA_NODE_TIMER && type == 'T') return alsa_timer_ioctl((uint32_t)nr, arg);
    return -EINVAL;
}

uint32_t alsa_ioctl_arg_size(uint32_t cmd) {
    int type = alsa_ioctl_type(cmd);
    int nr = alsa_ioctl_nr(cmd);
    if (type == 'U') {
        switch (nr) {
            case 0x00: return sizeof(int);
            case 0x01: return sizeof(struct snd_ctl_card_info_compat);
            case 0x10:
                return sizeof(struct edge_snd_ctl_elem_list);
            case 0x11:
                return sizeof(struct snd_ctl_elem_info_compat);
            case 0x12:
            case 0x13:
                return sizeof(struct snd_ctl_elem_value_compat);
            case 0x14:
            case 0x15:
                return sizeof(struct edge_snd_ctl_elem_id);
            case 0x16:
            case 0x32:
            case 0x42:
                return sizeof(int);
            case 0x20:
            case 0x30:
            case 0x40:
            case 0xd0:
            case 0xd1:
                return sizeof(int);
            case 0x31:
                return sizeof(struct snd_pcm_info_compat);
            default:
                return 0;
        }
    }
    if (type == 'A') {
        switch (nr) {
            case 0x00:
            case 0x02:
            case 0x03:
            case 0x04:
                return sizeof(int);
            case 0x01:
                return sizeof(struct snd_pcm_info_compat);
            case 0x10:
            case 0x11:
                return sizeof(struct snd_pcm_hw_params_compat);
            case 0x13:
                return sizeof(struct snd_pcm_sw_params_compat);
            case 0x20:
            case 0x24:
                return sizeof(struct snd_pcm_status_compat);
            case 0x21:
            case 0x46:
            case 0x49:
                return sizeof(edge_snd_pcm_sframes_t);
            case 0x23:
                return sizeof(struct snd_pcm_sync_ptr_compat);
            case 0x32:
                return sizeof(struct snd_pcm_channel_info_compat);
            case 0x45:
            case 0x60:
                return sizeof(int);
            case 0x50:
            case 0x51:
                return sizeof(struct edge_snd_xferi);
            case 0x52:
            case 0x53:
                return sizeof(struct edge_snd_xfern);
            default:
                return 0;
        }
    }
    if (type == 'T') {
        switch (nr) {
            case 0x00:
            case 0x02:
            case 0xa4:
                return sizeof(int);
            case 0x01:
                return sizeof(struct snd_timer_id_compat);
            case 0x03:
                return sizeof(struct snd_timer_ginfo_compat);
            case 0x04:
                return sizeof(struct snd_timer_gparams_compat);
            case 0x05:
                return sizeof(struct snd_timer_gstatus_compat);
            case 0x10:
                return sizeof(struct snd_timer_select_compat);
            case 0x11:
                return sizeof(struct snd_timer_info_compat);
            case 0x12:
                return sizeof(struct snd_timer_params_compat);
            case 0x14:
                return sizeof(struct snd_timer_status_compat);
            default:
                return 0;
        }
    }
    return 0;
}

static void alsa_proc_append_status(
        char *buffer, uint32_t capacity,
        const struct alsa_pcm_runtime *runtime, int stream) {
    struct audio_pcm_geometry geometry;
    uint32_t buffer_frames;
    uint32_t queued_frames;
    uint32_t available_frames;

    alsa_pcm_geometry(stream, &geometry);
    buffer_frames = alsa_geometry_frames(
        geometry.buffer_bytes, geometry.frame_bytes);
    queued_frames = alsa_geometry_frames(
        geometry.queued_bytes, geometry.frame_bytes);
    available_frames = stream == SNDRV_PCM_STREAM_CAPTURE ?
        queued_frames : buffer_frames - queued_frames;
    strcpy(buffer, "state: ");
    alsa_append(buffer, capacity, alsa_pcm_state_name(runtime));
    alsa_append(buffer, capacity, "\n"
                "owner_pid   : -1\n"
                "trigger_time: 0.000000000\n"
                "tstamp      : 0.000000000\n"
                "delay       : ");
    alsa_append_u32(buffer, capacity,
        stream == SNDRV_PCM_STREAM_PLAYBACK ? queued_frames : 0u);
    alsa_append(buffer, capacity, "\n"
                "avail       : ");
    alsa_append_u32(buffer, capacity, available_frames);
    alsa_append(buffer, capacity, "\n"
                "avail_max   : ");
    alsa_append_u32(buffer, capacity, buffer_frames);
    alsa_append(buffer, capacity, "\n");
}

static void alsa_proc_append_hw_params(
        char *buffer, uint32_t capacity, int stream) {
    struct audio_pcm_geometry geometry;

    alsa_pcm_geometry(stream, &geometry);
    strcpy(buffer, "access: RW_INTERLEAVED\n"
                   "format: S16_LE\n"
                   "subformat: STD\n"
                   "channels: ");
    alsa_append_u32(buffer, capacity, geometry.channels);
    alsa_append(buffer, capacity, "\n"
                "rate: ");
    alsa_append_u32(buffer, capacity, geometry.rate);
    alsa_append(buffer, capacity, " (");
    alsa_append_u32(buffer, capacity, geometry.rate);
    alsa_append(buffer, capacity, "/1)\n"
                "period_size: ");
    alsa_append_u32(buffer, capacity,
        alsa_geometry_frames(
            geometry.period_bytes, geometry.frame_bytes));
    alsa_append(buffer, capacity, "\n"
                "buffer_size: ");
    alsa_append_u32(buffer, capacity,
        alsa_geometry_frames(
            geometry.buffer_bytes, geometry.frame_bytes));
    alsa_append(buffer, capacity, "\n");
}

int alsa_proc_read(const char *name, char *out, uint32_t max) {
    const char *text = "";
    char tmp[256];
    if (!name || !out) return -EINVAL;
    if (!alsa_available()) return -ENODEV;
    if (strcmp(name, "cards") == 0) {
        strcpy(tmp, " 0 [EdgeOS         ]: EdgeOS - EdgeOS PCM\n"
                    "                      ");
        alsa_append(tmp, sizeof(tmp), alsa_audio_identity());
        alsa_append(tmp, sizeof(tmp), "\n");
        text = tmp;
    } else if (strcmp(name, "devices") == 0) {
        text = "  0: [ 0]   : control\n"
               " 16: [ 0- 0]: digital audio playback\n"
               " 33:        : timer\n";
    } else if (strcmp(name, "pcm") == 0) {
        strcpy(tmp, "00-00: ");
        alsa_append(tmp, sizeof(tmp), alsa_audio_identity());
        alsa_append(tmp, sizeof(tmp), " : playback 1\n");
        text = tmp;
    } else if (strcmp(name, "version") == 0) {
        text = "Advanced Linux Sound Architecture Driver Version 2.0.17.\n";
    } else if (strcmp(name, "timers") == 0) {
        text = "G0: system timer : 1000000.000us (1000000 ticks)\n"
               "P0-0-0: PCM playback 0-0-0 : 1000000.000us (1000000 ticks)\n";
    } else if (strcmp(name, "card0_id") == 0) {
        strcpy(tmp, alsa_card_id());
        alsa_append(tmp, sizeof(tmp), "\n");
        text = tmp;
    } else if (strcmp(name, "pcm0p_info") == 0) {
        strcpy(tmp, "card: 0\n"
                    "device: 0\n"
                    "subdevice: 0\n"
                    "stream: PLAYBACK\n"
                    "id: edgeos-pcm0\n"
                    "name: ");
        alsa_append(tmp, sizeof(tmp), alsa_audio_identity());
        alsa_append(tmp, sizeof(tmp), "\n"
                    "subname: subdevice #0\n"
                    "class: 0\n"
                    "subclass: 0\n"
                    "subdevices_count: 1\n"
                    "subdevices_avail: 1\n");
        text = tmp;
    } else if (strcmp(name, "pcm0p_sub0_info") == 0) {
        strcpy(tmp, "card: 0\n"
                    "device: 0\n"
                    "subdevice: 0\n"
                    "stream: PLAYBACK\n"
                    "id: edgeos-pcm0\n"
                    "name: ");
        alsa_append(tmp, sizeof(tmp), alsa_audio_identity());
        alsa_append(tmp, sizeof(tmp), "\n");
        text = tmp;
    } else if (strcmp(name, "pcm0p_sub0_status") == 0) {
        alsa_proc_append_status(
            tmp, sizeof(tmp),
            &g_pcm_runtime[SNDRV_PCM_STREAM_PLAYBACK],
            SNDRV_PCM_STREAM_PLAYBACK);
        text = tmp;
    } else if (strcmp(name, "pcm0p_sub0_hw_params") == 0) {
        alsa_proc_append_hw_params(
            tmp, sizeof(tmp), SNDRV_PCM_STREAM_PLAYBACK);
        text = tmp;
    } else if (strcmp(name, "pcm0c_info") == 0 ||
               strcmp(name, "pcm0c_sub0_info") == 0) {
        if (!alsa_capture_available()) return -ENODEV;
        strcpy(tmp, "card: 0\n"
                    "device: 0\n"
                    "subdevice: 0\n"
                    "stream: CAPTURE\n"
                    "id: edgeos-pcm0\n"
                    "name: ");
#if defined(CONFIG_AUDIO_AC97) || defined(CONFIG_AUDIO_HDA) || defined(CONFIG_USB_AUDIO) || defined(CONFIG_BSD_DRIVER_BRIDGE)
        alsa_append(tmp, sizeof(tmp), audio_capture_identity());
#else
        alsa_append(tmp, sizeof(tmp), "no capture");
#endif
        alsa_append(tmp, sizeof(tmp), "\n"
                    "subname: subdevice #0\n"
                    "class: 0\n"
                    "subclass: 0\n"
                    "subdevices_count: 1\n"
                    "subdevices_avail: 1\n");
        text = tmp;
    } else if (strcmp(name, "pcm0c_sub0_status") == 0) {
        if (!alsa_capture_available()) return -ENODEV;
        alsa_proc_append_status(
            tmp, sizeof(tmp),
            &g_pcm_runtime[SNDRV_PCM_STREAM_CAPTURE],
            SNDRV_PCM_STREAM_CAPTURE);
        text = tmp;
    } else if (strcmp(name, "pcm0c_sub0_hw_params") == 0) {
        if (!alsa_capture_available()) return -ENODEV;
        alsa_proc_append_hw_params(
            tmp, sizeof(tmp), SNDRV_PCM_STREAM_CAPTURE);
        text = tmp;
    } else {
        return -EINVAL;
    }
    uint32_t n = (uint32_t)strlen(text);
    if (n > max) n = max;
    memcpy(out, text, n);
    return (int)n;
}
