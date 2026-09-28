/*
 * Copyright (c) 2000 Katsurajima Naoto <raven@katsurajima.seya.yokohama.jp>
 * Copyright (c) 2001 Cameron Grant <cg@freebsd.org>
 * All rights reserved.
 *
 * Modifications for EdgeOS.
 * Copyright (c) EdgeOS Contributors.
 *
 * BSD-derived implementation notes:
 * This file uses the Intel ICH/AC97 register model and constants from
 * FreeBSD's sys/dev/sound/pci/ich.c and ich.h as the hardware reference, but
 * replaces FreeBSD's pcm(4), busdma, mixer, and interrupt glue with a small
 * EdgeOS OSS-compatible /dev/dsp front-end.
 */

/*
 * Linux ABI red flags:
 * - /dev/dsp writes are PCM playback, not fake success.  If no AC97 bus-master
 *   engine was initialized, VFS must not expose the node.
 * - Keep the device externally OSS-like.  Old Linux desktop apps still probe
 *   /dev/dsp and /dev/mixer before trying ALSA/PulseAudio.
 * - This first driver supports blocking 16-bit little-endian stereo playback
 *   at the AC97 default 48 kHz.  Do not claim HDA/UAC support from this file.
 */

#include "drivers/audio.h"
#include "drivers/pci.h"
#include "arch/x86_64/io_ports.h"
#include "stdio.h"
#include "string.h"
#include "sys/boottime.h"
#include "sys/spinlock.h"

#include <stdint.h>

#define PCI_VENDOR_INTEL 0x8086u
#define PCI_DEVICE_INTEL_82801AA_AC97 0x2415u
#define PCI_CLASS_MULTIMEDIA 0x04u
#define PCI_SUBCLASS_AUDIO_AC97 0x01u

#define PCI_COMMAND_REG 0x04u
#define PCI_COMMAND_IO 0x0001u
#define PCI_COMMAND_BUS_MASTER 0x0004u
#define PCI_BAR_NAM 0u
#define PCI_BAR_NABM 1u

#define AC97_RESET 0x00u
#define AC97_MASTER_VOLUME 0x02u
#define AC97_PCM_OUT_VOLUME 0x18u
#define AC97_EXT_AUDIO_ID 0x28u
#define AC97_PCM_FRONT_DAC_RATE 0x2cu

#define ICH_REG_PO_BASE 0x10u
#define ICH_REG_X_BDBAR 0x00u
#define ICH_REG_X_LVI 0x05u
#define ICH_REG_X_SR 0x06u
#define ICH_REG_X_CR 0x0bu
#define ICH_REG_GLOB_CNT 0x2cu
#define ICH_REG_GLOB_STA 0x30u

#define ICH_X_SR_DCH   0x0001u
#define ICH_X_SR_CELV  0x0002u
#define ICH_X_SR_LVBCI 0x0004u
#define ICH_X_SR_BCIS  0x0008u
#define ICH_X_SR_FIFOE 0x0010u
#define ICH_X_SR_CLEAR (ICH_X_SR_LVBCI | ICH_X_SR_BCIS | ICH_X_SR_FIFOE)

#define ICH_X_CR_RPBM 0x01u
#define ICH_X_CR_RR   0x02u

#define ICH_GLOB_CTL_COLD 0x00000002u
#define ICH_GLOB_CTL_WARM 0x00000004u
#define ICH_GLOB_STA_PCR  0x00000100u

#define ICH_BDC_IOC 0x80000000u
#define AC97_DMA_BYTES (64u * 1024u)

struct ac97_bdl_entry {
    uint32_t buffer;
    uint32_t length_flags;
} __attribute__((packed, aligned(8)));

struct ac97_state {
    uint8_t ready;
    uint8_t bus;
    uint8_t slot;
    uint8_t func;
    uint16_t nam;
    uint16_t nabm;
    uint32_t writes;
    uint32_t underruns;
    spinlock_t lock;
};

static struct ac97_state g_ac97;
static struct ac97_bdl_entry g_ac97_bdl[2] __attribute__((aligned(16)));
static uint8_t g_ac97_dma[AC97_DMA_BYTES] __attribute__((aligned(4096)));

int ac97_write_pcm(const char *buf, uint32_t len);
int ac97_mixer_write(const char *buf, uint32_t len);

static uint16_t ac97_mix_read16(uint16_t reg) {
    return inports((uint16_t)(g_ac97.nam + reg));
}

static void ac97_mix_write16(uint16_t reg, uint16_t val) {
    outports((uint16_t)(g_ac97.nam + reg), val);
}

static uint8_t ac97_bm_read8(uint16_t reg) {
    return inportb((uint16_t)(g_ac97.nabm + reg));
}

static uint16_t ac97_bm_read16(uint16_t reg) {
    return inports((uint16_t)(g_ac97.nabm + reg));
}

static uint32_t ac97_bm_read32(uint16_t reg) {
    return inportl((uint16_t)(g_ac97.nabm + reg));
}

static void ac97_bm_write8(uint16_t reg, uint8_t val) {
    outportb((uint16_t)(g_ac97.nabm + reg), val);
}

static void ac97_bm_write16(uint16_t reg, uint16_t val) {
    outports((uint16_t)(g_ac97.nabm + reg), val);
}

static void ac97_bm_write32(uint16_t reg, uint32_t val) {
    outportl((uint16_t)(g_ac97.nabm + reg), val);
}

static uint64_t ac97_now_us(void) {
    return boottime_monotonic_us();
}

static int ac97_wait_reg32(uint16_t reg, uint32_t mask, uint32_t want, uint32_t timeout_us) {
    uint64_t start = ac97_now_us();
    for (;;) {
        if ((ac97_bm_read32(reg) & mask) == want) return 0;
        if (ac97_now_us() - start > timeout_us) return -1;
        __asm__ __volatile__("pause");
    }
}

static void ac97_reset_pcm_out_locked(void) {
    uint16_t base = ICH_REG_PO_BASE;
    ac97_bm_write8((uint16_t)(base + ICH_REG_X_CR), 0);
    ac97_bm_write8((uint16_t)(base + ICH_REG_X_CR), ICH_X_CR_RR);
    for (uint32_t i = 0; i < 10000u; ++i) {
        if ((ac97_bm_read8((uint16_t)(base + ICH_REG_X_CR)) & ICH_X_CR_RR) == 0) break;
        __asm__ __volatile__("pause");
    }
    ac97_bm_write16((uint16_t)(base + ICH_REG_X_SR), ICH_X_SR_CLEAR);
}

static int ac97_play_locked(const char *buf, uint32_t len) {
    uint16_t base = ICH_REG_PO_BASE;
    uint32_t n = len;
    uint32_t samples;
    uint64_t start;

    if (!g_ac97.ready) return -1;
    if (!buf && len) return -1;
    if (n == 0) return 0;
    if (n > AC97_DMA_BYTES) n = AC97_DMA_BYTES;
    if (n & 1u) n--;
    if (n == 0) return 0;

    memcpy(g_ac97_dma, buf, n);
    samples = n / 2u;
    g_ac97_bdl[0].buffer = (uint32_t)(uintptr_t)g_ac97_dma;
    g_ac97_bdl[0].length_flags = (samples & 0x0000ffffu) | ICH_BDC_IOC;
    g_ac97_bdl[1].buffer = (uint32_t)(uintptr_t)g_ac97_dma;
    g_ac97_bdl[1].length_flags = 0;

    ac97_reset_pcm_out_locked();
    ac97_bm_write32((uint16_t)(base + ICH_REG_X_BDBAR), (uint32_t)(uintptr_t)g_ac97_bdl);
    ac97_bm_write8((uint16_t)(base + ICH_REG_X_LVI), 0);
    ac97_bm_write8((uint16_t)(base + ICH_REG_X_CR), ICH_X_CR_RPBM);

    start = ac97_now_us();
    for (;;) {
        uint16_t sr = ac97_bm_read16((uint16_t)(base + ICH_REG_X_SR));
        if (sr & (ICH_X_SR_BCIS | ICH_X_SR_LVBCI | ICH_X_SR_DCH | ICH_X_SR_FIFOE)) {
            ac97_bm_write8((uint16_t)(base + ICH_REG_X_CR), 0);
            ac97_bm_write16((uint16_t)(base + ICH_REG_X_SR), ICH_X_SR_CLEAR);
            if (sr & ICH_X_SR_FIFOE) g_ac97.underruns++;
            g_ac97.writes++;
            return (int)n;
        }
        if (ac97_now_us() - start > 5000000ull) {
            ac97_bm_write8((uint16_t)(base + ICH_REG_X_CR), 0);
            g_ac97.underruns++;
            return -1;
        }
        __asm__ __volatile__("sti; hlt");
    }
}

static int ac97_probe_one(uint8_t bus, uint8_t slot, uint8_t func) {
    uint32_t nam_bar = pci_read_bar(bus, slot, func, PCI_BAR_NAM);
    uint32_t nabm_bar = pci_read_bar(bus, slot, func, PCI_BAR_NABM);
    uint16_t command;
    uint32_t glob;

    if ((nam_bar & 1u) == 0 || (nabm_bar & 1u) == 0) return -1;
    if ((nam_bar & ~3u) == 0 || (nabm_bar & ~3u) == 0) return -1;

    memset(&g_ac97, 0, sizeof(g_ac97));
    g_ac97.bus = bus;
    g_ac97.slot = slot;
    g_ac97.func = func;
    g_ac97.nam = (uint16_t)(nam_bar & ~3u);
    g_ac97.nabm = (uint16_t)(nabm_bar & ~3u);
    spinlock_init(&g_ac97.lock);

    command = pci_cfg_read16(bus, slot, func, PCI_COMMAND_REG);
    pci_cfg_write16(bus, slot, func, PCI_COMMAND_REG,
                    (uint16_t)(command | PCI_COMMAND_IO | PCI_COMMAND_BUS_MASTER));

    glob = ac97_bm_read32(ICH_REG_GLOB_CNT);
    ac97_bm_write32(ICH_REG_GLOB_CNT, glob | ICH_GLOB_CTL_COLD);
    if (ac97_wait_reg32(ICH_REG_GLOB_STA, ICH_GLOB_STA_PCR, ICH_GLOB_STA_PCR, 500000u) < 0) {
        ac97_bm_write32(ICH_REG_GLOB_CNT, glob | ICH_GLOB_CTL_WARM);
    }

    (void)ac97_mix_read16(AC97_RESET);
    ac97_mix_write16(AC97_MASTER_VOLUME, 0x0000u);
    ac97_mix_write16(AC97_PCM_OUT_VOLUME, 0x0000u);
    if (ac97_mix_read16(AC97_EXT_AUDIO_ID) & 0x0001u) {
        ac97_mix_write16(AC97_PCM_FRONT_DAC_RATE, 48000u);
    }
    ac97_reset_pcm_out_locked();

    g_ac97.ready = 1;
    printf("[audio][ac97] Intel ICH AC97 ready at %02x:%02x.%u nam=0x%x nabm=0x%x rate=48000 format=s16le-stereo\n",
           (uint32_t)bus, (uint32_t)slot, (uint32_t)func,
           (uint32_t)g_ac97.nam, (uint32_t)g_ac97.nabm);
    return 0;
}

int audio_ac97_init(void) {
    for (uint32_t bus = 0; bus < 256u; ++bus) {
        for (uint8_t slot = 0; slot < 32u; ++slot) {
            for (uint8_t func = 0; func < 8u; ++func) {
                uint16_t vendor = pci_cfg_read16((uint8_t)bus, slot, func, 0x00);
                uint16_t device;
                uint8_t class_code;
                uint8_t subclass;
                uint8_t hdr;
                if (vendor == PCI_VENDOR_INVALID) {
                    if (func == 0) break;
                    continue;
                }
                device = pci_cfg_read16((uint8_t)bus, slot, func, 0x02);
                class_code = pci_cfg_read8((uint8_t)bus, slot, func, 0x0b);
                subclass = pci_cfg_read8((uint8_t)bus, slot, func, 0x0a);
                if ((vendor == PCI_VENDOR_INTEL && device == PCI_DEVICE_INTEL_82801AA_AC97) ||
                    (class_code == PCI_CLASS_MULTIMEDIA && subclass == PCI_SUBCLASS_AUDIO_AC97)) {
                    if (ac97_probe_one((uint8_t)bus, slot, func) == 0) {
                        struct audio_backend backend;
                        memset(&backend, 0, sizeof(backend));
                        backend.name = "Intel ICH AC97";
                        backend.kind = AUDIO_BACKEND_AC97;
                        backend.bus = (uint8_t)bus;
                        backend.slot = slot;
                        backend.func = func;
                        backend.write_pcm = ac97_write_pcm;
                        backend.write_mixer = ac97_mixer_write;
                        (void)audio_register_backend(&backend);
                        return 0;
                    }
                }
                if (func == 0) {
                    hdr = pci_header_type((uint8_t)bus, slot, func);
                    if ((hdr & 0x80u) == 0) break;
                }
            }
        }
    }
    return -1;
}

int ac97_write_pcm(const char *buf, uint32_t len) {
    uint32_t done = 0;
    if (!g_ac97.ready) return -1;
    while (done < len) {
        uint32_t n = len - done;
        int rc;
        uint64_t flags;
        if (n > AC97_DMA_BYTES) n = AC97_DMA_BYTES;
        flags = spin_lock_irqsave(&g_ac97.lock);
        rc = ac97_play_locked(buf + done, n);
        spin_unlock_irqrestore(&g_ac97.lock, flags);
        if (rc < 0) return done ? (int)done : -1;
        if (rc == 0) break;
        done += (uint32_t)rc;
    }
    return (int)done;
}

int ac97_mixer_write(const char *buf, uint32_t len) {
    (void)buf;
    if (!g_ac97.ready) return -1;
    return (int)len;
}
