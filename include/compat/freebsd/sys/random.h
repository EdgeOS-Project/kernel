/* SPDX-License-Identifier: BSD-2-Clause */
/* Random-source identifiers used by imported FreeBSD drivers. */

#ifndef _SYS_RANDOM_H_
#define _SYS_RANDOM_H_

#include <stddef.h>
#include <stdint.h>

enum random_entropy_source {
    RANDOM_START = 0,
    RANDOM_CACHED = 0,
    RANDOM_ATTACH,
    RANDOM_KEYBOARD,
    RANDOM_MOUSE,
    RANDOM_NET_TUN,
    RANDOM_NET_ETHER,
    RANDOM_NET_NG,
    RANDOM_INTERRUPT,
    RANDOM_SWI,
    RANDOM_FS_ATIME,
    RANDOM_UMA,
    RANDOM_CALLOUT,
    RANDOM_RANDOMDEV,
    RANDOM_ENVIRONMENTAL_END = RANDOM_RANDOMDEV,
    RANDOM_PURE_START,
    RANDOM_PURE_TPM = RANDOM_PURE_START,
    RANDOM_PURE_RDRAND,
    RANDOM_PURE_RDSEED,
    RANDOM_PURE_NEHEMIAH,
    RANDOM_PURE_RNDTEST,
    RANDOM_PURE_VIRTIO,
    RANDOM_PURE_BROADCOM,
    RANDOM_PURE_CCP,
    RANDOM_PURE_DARN,
    RANDOM_PURE_VMGENID,
    RANDOM_PURE_QUALCOMM,
    RANDOM_PURE_ARMV8,
    RANDOM_PURE_ARM_TRNG,
    RANDOM_PURE_SAFE,
    RANDOM_PURE_GLXSB,
    ENTROPYSOURCE,
};

extern unsigned int hc_source_mask;
void random_harvest_queue_(const void *entropy, unsigned int size,
    enum random_entropy_source origin);
void random_harvest_fast_(const void *entropy, unsigned int size);
void random_harvest_direct_(const void *entropy, unsigned int size,
    enum random_entropy_source origin);

static inline void
random_harvest_queue(const void *entropy, unsigned int size,
    enum random_entropy_source origin)
{
    if (origin < ENTROPYSOURCE &&
        (hc_source_mask & (1u << (unsigned int)origin)) != 0)
        random_harvest_queue_(entropy, size, origin);
}

static inline void
random_harvest_fast(const void *entropy, unsigned int size,
    enum random_entropy_source origin)
{
    if (origin < ENTROPYSOURCE &&
        (hc_source_mask & (1u << (unsigned int)origin)) != 0)
        random_harvest_fast_(entropy, size);
}

static inline void
random_harvest_direct(const void *entropy, unsigned int size,
    enum random_entropy_source origin)
{
    if (origin < ENTROPYSOURCE &&
        (hc_source_mask & (1u << (unsigned int)origin)) != 0)
        random_harvest_direct_(entropy, size, origin);
}

void arc4rand(void *buffer, unsigned int length, int reseed);
uint32_t arc4random(void);
uint32_t arc4random_uniform(uint32_t upper_bound);
void arc4random_buf(void *buffer, size_t length);
void read_random(void *buffer, unsigned int length);

#endif
