/* SPDX-License-Identifier: BSD-2-Clause */
/* Minimal entropy-harvest definitions used by imported random drivers. */

#ifndef SYS_DEV_RANDOM_RANDOM_HARVESTQ_H_INCLUDED
#define SYS_DEV_RANDOM_RANDOM_HARVESTQ_H_INCLUDED

#include <stdint.h>

#include <machine/cpu.h>

#define HARVESTSIZE 2

struct harvest_event {
    uint32_t he_somecounter;
    uint32_t he_entropy[HARVESTSIZE];
    uint8_t he_size;
    uint8_t he_destination;
    uint8_t he_source;
};

static __inline uint32_t
random_get_cyclecount(void)
{
    return (uint32_t)get_cyclecount();
}

#endif
