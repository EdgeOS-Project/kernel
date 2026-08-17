/* SPDX-License-Identifier: MPL-2.0 */
/* Shared FreeBSD PCM service boundary for the EdgeOS BSD driver bridge. */

#ifndef EDGEOS_COMPAT_FREEBSD_AUDIO_H
#define EDGEOS_COMPAT_FREEBSD_AUDIO_H

#include <stdint.h>

#define BSD_AUDIO_MODULE_VERSION 5

int bsd_audio_playback_available(void);
int bsd_audio_capture_available(void);
int bsd_audio_playback_write(const char *buffer, uint32_t length);
int bsd_audio_capture_read(char *buffer, uint32_t length);
int bsd_audio_capture_ready(void);
int bsd_audio_stream_control(uint8_t stream, uint8_t command);
void bsd_audio_set_playback_control(uint8_t muted, uint8_t left_percent,
    uint8_t right_percent);

#endif
