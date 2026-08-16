/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Copyright (c) EdgeOS Contributors.
 *
 * Linux-compatible audio device front-end.
 */

#ifndef EDGEOS_DRIVERS_AUDIO_H
#define EDGEOS_DRIVERS_AUDIO_H

#include <stdint.h>

typedef int (*audio_pcm_write_fn)(const char *buf, uint32_t len);
typedef int (*audio_pcm_read_fn)(char *buf, uint32_t len);
typedef int (*audio_mixer_write_fn)(const char *buf, uint32_t len);
typedef int (*audio_capture_ready_fn)(void);
typedef int (*audio_playback_ready_fn)(void);
typedef int (*audio_stream_control_fn)(uint8_t stream, uint8_t command);
struct audio_pcm_geometry;
typedef int (*audio_pcm_geometry_fn)(uint8_t stream,
    struct audio_pcm_geometry *geometry);
typedef void (*audio_playback_control_fn)(uint8_t muted,
    uint8_t left_percent, uint8_t right_percent);

struct audio_pcm_geometry {
    uint32_t rate;
    uint32_t channels;
    uint32_t sample_bits;
    uint32_t frame_bytes;
    uint32_t period_bytes;
    uint32_t buffer_bytes;
    uint32_t queued_bytes;
};

struct audio_backend {
    const char *name;
    uint8_t kind;
    uint8_t bus;
    uint8_t slot;
    uint8_t func;
    audio_pcm_write_fn write_pcm;
    audio_pcm_read_fn read_pcm;
    audio_mixer_write_fn write_mixer;
    audio_playback_ready_fn playback_ready;
    audio_capture_ready_fn capture_ready;
    audio_stream_control_fn stream_control;
    audio_pcm_geometry_fn pcm_geometry;
    audio_playback_control_fn set_playback_control;
};

#define AUDIO_BACKEND_AC97 1u
#define AUDIO_BACKEND_HDA  2u
#define AUDIO_BACKEND_UAC  3u

#define AUDIO_STREAM_PLAYBACK 0u
#define AUDIO_STREAM_CAPTURE  1u

#define AUDIO_STREAM_COMMAND_START 1u
#define AUDIO_STREAM_COMMAND_STOP  2u
#define AUDIO_STREAM_COMMAND_RESET 3u
#define AUDIO_STREAM_COMMAND_DRAIN 4u

void audio_init(void);
int audio_available(void);
int audio_register_backend(const struct audio_backend *backend);
void audio_unregister_backend(uint8_t kind);
int audio_ac97_init(void);
int audio_hda_init(void);
int audio_uac_init(void);
int audio_ac97_pci_function_ready(uint8_t bus, uint8_t slot, uint8_t func);
int audio_hda_pci_function_ready(uint8_t bus, uint8_t slot, uint8_t func);
int audio_write_pcm(const char *buf, uint32_t len);
int audio_read_pcm(char *buf, uint32_t len);
int audio_capture_available(void);
int audio_playback_ready(void);
int audio_capture_ready(void);
int audio_stream_control(uint8_t stream, uint8_t command);
int audio_get_pcm_geometry(uint8_t stream,
    struct audio_pcm_geometry *geometry);
int audio_mixer_write(const char *buf, uint32_t len);
void audio_set_playback_control(uint8_t muted, uint8_t left_percent, uint8_t right_percent);
void audio_get_playback_control(uint8_t *muted, uint8_t *left_percent, uint8_t *right_percent);
const char *audio_identity(void);
const char *audio_capture_identity(void);

#endif
