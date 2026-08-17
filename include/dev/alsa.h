/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Copyright (c) EdgeOS Contributors.
 *
 * Linux-compatible ALSA userspace ABI glue.
 */

#ifndef EDGEOS_DEV_ALSA_H
#define EDGEOS_DEV_ALSA_H

#include <stdint.h>

#define EDGE_ALSA_CARD_MAJOR 116u
#define EDGE_ALSA_CARD_INDEX 0u
#define EDGE_ALSA_PCM_DEVICE 0u
#define EDGE_ALSA_PCM_SUBDEVICE 0u
#define EDGE_ALSA_PCM_RATE 48000u
#define EDGE_ALSA_PCM_CHANNELS 2u
#define EDGE_ALSA_PCM_BITS 16u
#define EDGE_ALSA_PCM_FRAME_BYTES ((EDGE_ALSA_PCM_CHANNELS * EDGE_ALSA_PCM_BITS) / 8u)

#define EDGE_ALSA_PATH_CONTROL "/dev/snd/controlC0"
#define EDGE_ALSA_PATH_PCM_PLAYBACK "/dev/snd/pcmC0D0p"
#define EDGE_ALSA_PATH_PCM_CAPTURE "/dev/snd/pcmC0D0c"
#define EDGE_ALSA_PATH_TIMER "/dev/snd/timer"

enum {
    EDGE_ALSA_NODE_NONE = 0,
    EDGE_ALSA_NODE_SND_DIR,
    EDGE_ALSA_NODE_CONTROL,
    EDGE_ALSA_NODE_PCM_PLAYBACK,
    EDGE_ALSA_NODE_PCM_CAPTURE,
    EDGE_ALSA_NODE_TIMER
};

typedef int64_t edge_snd_pcm_sframes_t;
typedef uint64_t edge_snd_pcm_uframes_t;

struct edge_snd_xferi {
    edge_snd_pcm_sframes_t result;
    void *buf;
    edge_snd_pcm_uframes_t frames;
};

struct edge_snd_xfern {
    edge_snd_pcm_sframes_t result;
    void **bufs;
    edge_snd_pcm_uframes_t frames;
};

struct edge_snd_ctl_elem_id {
    uint32_t numid;
    int32_t iface;
    uint32_t device;
    uint32_t subdevice;
    uint8_t name[44];
    uint32_t index;
};

struct edge_snd_ctl_elem_list {
    uint32_t offset;
    uint32_t space;
    uint32_t used;
    uint32_t count;
    uint64_t pids;
    uint8_t reserved[50];
};

int alsa_available(void);
int alsa_playback_available(void);
int alsa_capture_available(void);
int alsa_path_kind(const char *path);
void alsa_open(const char *path);
void alsa_close(const char *path);
uint32_t alsa_dev_minor_from_kind(int kind);
uint32_t alsa_inode_from_kind(int kind);
int alsa_read(const char *path, char *out, uint32_t max);
int alsa_write(const char *path, const char *buf, uint32_t len);
int alsa_ioctl_kernel(const char *path, uint32_t cmd, void *arg);
uint32_t alsa_ioctl_arg_size(uint32_t cmd);
int alsa_proc_read(const char *name, char *out, uint32_t max);
int alsa_poll_read_ready(const char *path);
int alsa_poll_write_ready(const char *path);
int alsa_ioctl_type(uint32_t cmd);
int alsa_ioctl_nr(uint32_t cmd);
int alsa_ctl_elem_id_for_index(uint32_t index, struct edge_snd_ctl_elem_id *out);
const char *alsa_card_id(void);
const char *alsa_card_name(void);
const char *alsa_card_longname(void);

#endif
