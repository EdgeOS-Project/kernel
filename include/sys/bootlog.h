/* SPDX-License-Identifier: MPL-2.0 */
/* Copyright (c) EdgeOS Contributors. */

#ifndef SYS_BOOTLOG_H
#define SYS_BOOTLOG_H

#include <stdint.h>

void bootlog_init(void);
void bootlog_stage(const char *msg);
void bootlog_append_raw(const char *s, uint32_t n);
uint32_t bootlog_read(uint32_t off, void *buf, uint32_t len);
int bootlog_read_from(uint64_t *pos_io, void *buf, uint32_t len);
uint64_t bootlog_first_offset(void);
uint64_t bootlog_next_offset(void);
int bootlog_kmsg_read_from(uint64_t *pos_io, void *buf, uint32_t len);
uint64_t bootlog_kmsg_first_offset(void);
int bootlog_kmsg_has_record(uint64_t pos);
uint32_t bootlog_kmsg_next_record_length(uint64_t pos);
void bootlog_snapshot_bounds(uint64_t *first_offset,
                             uint64_t *clear_offset,
                             uint64_t *next_offset);
uint32_t bootlog_buffer_size(void);
uint32_t bootlog_buffer_capacity(void);
void bootlog_clear(void);
int bootlog_format_version(char *buf, uint32_t max);
int bootlog_format_linux_version(char *buf, uint32_t max);
int bootlog_format_timestamp_prefix(char *buf, uint32_t max);

#endif
