/* SPDX-License-Identifier: MPL-2.0 */
/*
 * EdgeOS HPET driver interface.
 *
 * Copyright (c) EdgeOS Contributors.
 */
#ifndef EDGEOS_DRIVERS_HPET_H
#define EDGEOS_DRIVERS_HPET_H

#include <stdint.h>

void hpet_init(void);
int hpet_is_available(void);
uint64_t hpet_read_counter(void);
int hpet_snapshot(char *buf, uint32_t max);

#endif
