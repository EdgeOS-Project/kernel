/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Copyright (c) EdgeOS Contributors.
 *
 * Linux-compatible audio device front-end.
 */

#include "drivers/audio.h"
#include "dev/devtmpfs.h"
#include "stdio.h"
#include "string.h"

static struct audio_backend g_audio;
static struct audio_backend g_capture_audio;
static uint8_t g_audio_ready;
static uint8_t g_capture_audio_ready;
static uint8_t g_audio_muted;
static uint8_t g_audio_left_percent = 100;
static uint8_t g_audio_right_percent = 100;

int audio_register_backend(const struct audio_backend *backend) {
    int registered = 0;
    if (!backend || !backend->name ||
        (!backend->write_pcm && !backend->read_pcm)) return -1;
    if (backend->write_pcm && !g_audio_ready) {
        memcpy(&g_audio, backend, sizeof(g_audio));
        g_audio_ready = 1;
        registered = 1;
        printf("[audio] selected %s for OSS-compatible PCM playback\n",
               g_audio.name);
    } else if (backend->write_pcm) {
        printf("[audio] keeping %s, ignoring secondary backend %s\n",
               g_audio.name, backend->name);
    }
    if (backend->read_pcm && !g_capture_audio_ready) {
        memcpy(&g_capture_audio, backend, sizeof(g_capture_audio));
        g_capture_audio_ready = 1;
        registered = 1;
        printf("[audio] selected %s for PCM capture\n",
               g_capture_audio.name);
    } else if (backend->read_pcm) {
        printf("[audio] keeping %s, ignoring secondary capture backend %s\n",
               g_capture_audio.name, backend->name);
    }
    if (registered) (void)devtmpfs_refresh_audio_nodes();
    return registered ? 0 : -1;
}

void audio_unregister_backend(uint8_t kind) {
    int removed = 0;
    if (g_audio_ready && g_audio.kind == kind) {
        printf("[audio] removed %s playback backend\n", g_audio.name);
        memset(&g_audio, 0, sizeof(g_audio));
        g_audio_ready = 0;
        removed = 1;
    }
    if (g_capture_audio_ready && g_capture_audio.kind == kind) {
        printf("[audio] removed %s capture backend\n",
               g_capture_audio.name);
        memset(&g_capture_audio, 0, sizeof(g_capture_audio));
        g_capture_audio_ready = 0;
        removed = 1;
    }
    if (removed) (void)devtmpfs_refresh_audio_nodes();
}

void audio_init(void) {
#ifdef CONFIG_AUDIO_AC97
    (void)audio_ac97_init();
#endif
#ifdef CONFIG_AUDIO_HDA
    (void)audio_hda_init();
#endif
    if (!g_audio_ready) {
#ifdef CONFIG_USB_AUDIO
        /*
         * USB Audio Class devices are discovered later by usb_init(), after
         * xHCI has enumerated root ports and configured an isochronous
         * streaming endpoint.  Do not report final audio failure here when a
         * real UAC backend may still register through the USB path.
         */
        printf("[audio] no PCI audio controller found; USB Audio Class will probe during USB init\n");
#else
        printf("[audio] no supported audio controller found\n");
#endif
    }
}

int audio_available(void) {
    return g_audio_ready ? 1 : 0;
}

int audio_ac97_pci_function_ready(uint8_t bus, uint8_t slot, uint8_t func) {
    return g_audio_ready && g_audio.kind == AUDIO_BACKEND_AC97 &&
           g_audio.bus == bus && g_audio.slot == slot && g_audio.func == func;
}

int audio_hda_pci_function_ready(uint8_t bus, uint8_t slot, uint8_t func) {
    return g_audio_ready && g_audio.kind == AUDIO_BACKEND_HDA &&
           g_audio.bus == bus && g_audio.slot == slot && g_audio.func == func;
}

int audio_write_pcm(const char *buf, uint32_t len) {
    uint32_t done = 0;
    if (!g_audio_ready || !g_audio.write_pcm) return -1;
    if (!buf && len) return -1;
    while (done < len) {
        char tmp[4096];
        uint32_t n = len - done;
        int rc;
        if (n > sizeof(tmp)) n = sizeof(tmp);
        memcpy(tmp, buf + done, n);
        if (g_audio_muted || g_audio_left_percent < 100 || g_audio_right_percent < 100) {
            uint32_t samples = n / 2u;
            int16_t *s = (int16_t *)tmp;
            for (uint32_t i = 0; i < samples; ++i) {
                uint8_t pct = (i & 1u) ? g_audio_right_percent : g_audio_left_percent;
                int32_t v = g_audio_muted ? 0 : ((int32_t)s[i] * (int32_t)pct) / 100;
                if (v > 32767) v = 32767;
                if (v < -32768) v = -32768;
                s[i] = (int16_t)v;
            }
        }
        rc = g_audio.write_pcm(tmp, n);
        if (rc < 0) return done ? (int)done : rc;
        if (rc == 0) break;
        done += (uint32_t)rc;
    }
    return (int)done;
}

int audio_read_pcm(char *buf, uint32_t len) {
    if (!g_capture_audio_ready || !g_capture_audio.read_pcm) return -1;
    if (!buf && len) return -1;
    return g_capture_audio.read_pcm(buf, len);
}

int audio_capture_available(void) {
    return g_capture_audio_ready && g_capture_audio.read_pcm;
}

int audio_playback_ready(void) {
    if (!g_audio_ready || !g_audio.write_pcm) return 0;
    if (!g_audio.playback_ready) return 1;
    return g_audio.playback_ready();
}

int audio_capture_ready(void) {
    if (!audio_capture_available()) return 0;
    if (!g_capture_audio.capture_ready) return 1;
    return g_capture_audio.capture_ready();
}

int audio_stream_control(uint8_t stream, uint8_t command) {
    struct audio_backend *backend;

    if (stream == AUDIO_STREAM_PLAYBACK) {
        if (!g_audio_ready) return -1;
        backend = &g_audio;
    } else if (stream == AUDIO_STREAM_CAPTURE) {
        if (!g_capture_audio_ready) return -1;
        backend = &g_capture_audio;
    } else {
        return -1;
    }
    if (!backend->stream_control) return 0;
    return backend->stream_control(stream, command);
}

int audio_get_pcm_geometry(uint8_t stream,
                           struct audio_pcm_geometry *geometry) {
    struct audio_backend *backend;

    if (!geometry) return -1;
    memset(geometry, 0, sizeof(*geometry));
    if (stream == AUDIO_STREAM_PLAYBACK) {
        if (!g_audio_ready) return -1;
        backend = &g_audio;
    } else if (stream == AUDIO_STREAM_CAPTURE) {
        if (!g_capture_audio_ready) return -1;
        backend = &g_capture_audio;
    } else {
        return -1;
    }
    if (!backend->pcm_geometry) return -1;
    return backend->pcm_geometry(stream, geometry);
}

int audio_mixer_write(const char *buf, uint32_t len) {
    if (!g_audio_ready) return -1;
    if (!g_audio.write_mixer) return (int)len;
    return g_audio.write_mixer(buf, len);
}

void audio_set_playback_control(uint8_t muted, uint8_t left_percent, uint8_t right_percent) {
    if (left_percent > 100) left_percent = 100;
    if (right_percent > 100) right_percent = 100;
    g_audio_muted = muted ? 1u : 0u;
    g_audio_left_percent = left_percent;
    g_audio_right_percent = right_percent;
    if (g_audio_ready && g_audio.set_playback_control) {
        g_audio.set_playback_control(g_audio_muted,
                                     g_audio_left_percent,
                                     g_audio_right_percent);
    }
}

void audio_get_playback_control(uint8_t *muted, uint8_t *left_percent, uint8_t *right_percent) {
    if (muted) *muted = g_audio_muted;
    if (left_percent) *left_percent = g_audio_left_percent;
    if (right_percent) *right_percent = g_audio_right_percent;
}

const char *audio_identity(void) {
    return g_audio_ready ? g_audio.name : "no audio";
}

const char *audio_capture_identity(void) {
    return g_capture_audio_ready ? g_capture_audio.name : "no capture";
}
