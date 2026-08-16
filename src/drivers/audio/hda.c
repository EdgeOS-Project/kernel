/*
 * Copyright (c) 2006 Stephane E. Potvin <sepotvin@videotron.ca>
 * All rights reserved.
 *
 * Modifications for EdgeOS.
 * Copyright (c) EdgeOS Contributors.
 *
 * BSD-derived implementation notes:
 * This file uses the Intel HD Audio controller and codec register definitions
 * from FreeBSD's sys/dev/sound/pci/hda/hdac_reg.h and hda_reg.h.  The driver
 * logic is original EdgeOS code that maps those registers to the small
 * Linux-compatible audio front-end used by /dev/dsp.
 */

/*
 * Linux ABI red flags:
 * - Userspace-visible playback must be real PCM output.  Do not expose HDA as
 *   supported until the controller, codec path, and output stream are ready.
 * - This is an OSS-compatible playback backend for Linux userspace.  Native
 *   ALSA /dev/snd ioctls still need a separate Linux ABI layer.
 */

#include "drivers/audio.h"
#include "drivers/pci.h"
#include "stdio.h"
#include "string.h"
#include "sys/boottime.h"
#include "sys/mmio.h"
#include "sys/spinlock.h"

#include <stdint.h>

#define PCI_CLASS_MULTIMEDIA 0x04u
#define PCI_SUBCLASS_AUDIO_HDA 0x03u
#define PCI_COMMAND_REG 0x04u
#define PCI_COMMAND_MEM 0x0002u
#define PCI_COMMAND_BUS_MASTER 0x0004u

#define HDAC_GCAP       0x00u
#define HDAC_GCTL       0x08u
#define HDAC_STATESTS   0x0eu
#define HDAC_CORBLBASE  0x40u
#define HDAC_CORBUBASE  0x44u
#define HDAC_CORBWP     0x48u
#define HDAC_CORBRP     0x4au
#define HDAC_CORBCTL    0x4cu
#define HDAC_CORBSTS    0x4du
#define HDAC_CORBSIZE   0x4eu
#define HDAC_RIRBLBASE  0x50u
#define HDAC_RIRBUBASE  0x54u
#define HDAC_RIRBWP     0x58u
#define HDAC_RINTCNT    0x5au
#define HDAC_RIRBCTL    0x5cu
#define HDAC_RIRBSTS    0x5du
#define HDAC_RIRBSIZE   0x5eu
#define HDAC_ICOI       0x60u
#define HDAC_ICII       0x64u
#define HDAC_ICIS       0x68u

#define HDAC_GCAP_ISS(gcap) (((gcap) >> 8) & 0x0fu)
#define HDAC_GCAP_OSS(gcap) (((gcap) >> 12) & 0x0fu)
#define HDAC_GCTL_CRST 0x00000001u
#define HDAC_CORBRP_RST 0x8000u
#define HDAC_CORBCTL_RUN 0x02u
#define HDAC_CORBSIZE_256 0x02u
#define HDAC_RIRBWP_RST 0x8000u
#define HDAC_RIRBCTL_RUN 0x02u
#define HDAC_RIRBSIZE_256 0x02u
#define HDAC_ICIS_ICB 0x0001u
#define HDAC_ICIS_IRV 0x0002u

#define HDAC_SDCTL0 0x00u
#define HDAC_SDCTL2 0x02u
#define HDAC_SDSTS  0x03u
#define HDAC_SDLPIB 0x04u
#define HDAC_SDCBL  0x08u
#define HDAC_SDLVI  0x0cu
#define HDAC_SDFMT  0x12u
#define HDAC_SDBDPL 0x18u
#define HDAC_SDBDPU 0x1cu
#define HDAC_SDCTL_SRST 0x01u
#define HDAC_SDCTL_RUN  0x02u
#define HDAC_SDCTL_IOCE 0x04u
#define HDAC_SDSTS_BCIS 0x04u
#define HDAC_SDSTS_FIFOE 0x08u
#define HDAC_SDSTS_DESE 0x10u

#define HDA_PARAM_VENDOR_ID 0x00u
#define HDA_PARAM_SUB_NODE_COUNT 0x04u
#define HDA_PARAM_FCT_GRP_TYPE 0x05u
#define HDA_PARAM_AUDIO_WIDGET_CAP 0x09u
#define HDA_PARAM_PIN_CAP 0x0cu
#define HDA_PARAM_CONN_LIST_LENGTH 0x0eu
#define HDA_PARAM_FCT_GRP_AUDIO 0x01u
#define HDA_WIDGET_AUDIO_OUTPUT 0x00u
#define HDA_WIDGET_PIN_COMPLEX 0x04u
#define HDA_PIN_CAP_OUTPUT 0x00000010u
#define HDA_PIN_CAP_HEADPHONE 0x00000008u

#define HDA_VERB_GET_PARAMETER 0xf00u
#define HDA_VERB_GET_CONN_LIST_ENTRY 0xf02u
#define HDA_VERB_SET_POWER_STATE 0x705u
#define HDA_VERB_SET_CONV_STREAM_CHAN 0x706u
#define HDA_VERB_SET_PIN_WIDGET_CTRL 0x707u
#define HDA_VERB_SET_EAPD_BTL_ENABLE 0x70cu
#define HDA_VERB_SET_CONV_FMT 0x200u
#define HDA_VERB_SET_CONN_SELECT_CONTROL 0x701u
#define HDA_VERB_SET_AMP_GAIN_MUTE 0x300u

#define HDA_PIN_OUT_ENABLE 0x40u
#define HDA_PIN_HP_ENABLE  0x80u
#define HDA_EAPD_ENABLE    0x02u
#define HDA_STREAM_TAG 1u
#define HDA_FORMAT_48K_16_STEREO 0x0011u
#define HDA_DMA_BYTES (64u * 1024u)
#define HDA_BDL_ENTRIES 2u

struct hda_bdl_entry {
    uint32_t addr_lo;
    uint32_t addr_hi;
    uint32_t length;
    uint32_t ioc;
} __attribute__((packed, aligned(16)));

struct hda_state {
    uint8_t ready;
    uint8_t bus;
    uint8_t slot;
    uint8_t func;
    uint8_t cad;
    uint8_t afg;
    uint8_t dac_nid;
    uint8_t pin_nid;
    uint8_t iss;
    uint8_t oss;
    uint32_t stream_base;
    uint32_t mmio_phys;
    volatile uint8_t *mmio;
    spinlock_t lock;
};

static struct hda_state g_hda;
static struct hda_bdl_entry g_hda_bdl[HDA_BDL_ENTRIES] __attribute__((aligned(128)));
static uint8_t g_hda_dma[HDA_DMA_BYTES] __attribute__((aligned(4096)));

static uint64_t hda_now_us(void) {
    return boottime_monotonic_us();
}

static uint8_t hda_read8(uint32_t off) {
    return *(volatile uint8_t *)(g_hda.mmio + off);
}

static uint16_t hda_read16(uint32_t off) {
    return *(volatile uint16_t *)(g_hda.mmio + off);
}

static uint32_t hda_read32(uint32_t off) {
    return *(volatile uint32_t *)(g_hda.mmio + off);
}

static void hda_write8(uint32_t off, uint8_t val) {
    *(volatile uint8_t *)(g_hda.mmio + off) = val;
}

static void hda_write16(uint32_t off, uint16_t val) {
    *(volatile uint16_t *)(g_hda.mmio + off) = val;
}

static void hda_write32(uint32_t off, uint32_t val) {
    *(volatile uint32_t *)(g_hda.mmio + off) = val;
}

static int hda_wait32(uint32_t off, uint32_t mask, uint32_t want, uint32_t timeout_us) {
    uint64_t start = hda_now_us();
    for (;;) {
        if ((hda_read32(off) & mask) == want) return 0;
        if (hda_now_us() - start > timeout_us) return -1;
        __asm__ __volatile__("pause");
    }
}

static uint32_t hda_cmd_12(uint8_t cad, uint8_t nid, uint16_t verb, uint8_t payload) {
    return ((uint32_t)cad << 28) | ((uint32_t)nid << 20) | ((uint32_t)verb << 8) | payload;
}

static uint32_t hda_cmd_4(uint8_t cad, uint8_t nid, uint8_t verb, uint16_t payload) {
    return ((uint32_t)cad << 28) | ((uint32_t)nid << 20) | ((uint32_t)verb << 16) | payload;
}

static int hda_corb_cmd(uint32_t cmd, uint32_t *response) {
    uint64_t start;

    start = hda_now_us();
    while (hda_read16(HDAC_ICIS) & HDAC_ICIS_ICB) {
        if (hda_now_us() - start > 100000u) return -1;
        __asm__ __volatile__("pause");
    }
    hda_write16(HDAC_ICIS, HDAC_ICIS_IRV);
    hda_write32(HDAC_ICOI, cmd);
    hda_write16(HDAC_ICIS, HDAC_ICIS_ICB);
    start = hda_now_us();
    for (;;) {
        uint16_t icis = hda_read16(HDAC_ICIS);
        if (icis & HDAC_ICIS_IRV) {
            if (response) *response = hda_read32(HDAC_ICII);
            hda_write16(HDAC_ICIS, HDAC_ICIS_IRV);
            return 0;
        }
        if (hda_now_us() - start > 1000000ull) return -1;
        __asm__ __volatile__("pause");
    }
}

static int hda_get_parameter(uint8_t nid, uint8_t param, uint32_t *out) {
    return hda_corb_cmd(hda_cmd_12(g_hda.cad, nid, HDA_VERB_GET_PARAMETER, param), out);
}

static int hda_find_codec(void) {
    uint16_t state = hda_read16(HDAC_STATESTS);
    printf("[audio][hda] STATESTS=0x%x\n", (uint32_t)state);
    for (uint8_t cad = 0; cad < 15u; ++cad) {
        uint32_t vendor = 0;
        if ((state & (1u << cad)) == 0) continue;
        g_hda.cad = cad;
        if (hda_get_parameter(0, HDA_PARAM_VENDOR_ID, &vendor) == 0 && vendor != 0xffffffffu && vendor != 0) {
            printf("[audio][hda] codec cad=%u vendor=0x%x\n", (uint32_t)cad, vendor);
            return 0;
        }
        printf("[audio][hda] codec cad=%u did not respond vendor=0x%x\n", (uint32_t)cad, vendor);
    }
    return -1;
}

static uint8_t hda_widget_type(uint32_t cap) {
    return (uint8_t)((cap >> 20) & 0x0fu);
}

static int hda_conn_selects_dac(uint8_t pin, uint8_t dac) {
    uint32_t len = 0;
    uint8_t count;
    uint8_t long_form;
    if (hda_get_parameter(pin, HDA_PARAM_CONN_LIST_LENGTH, &len) < 0) return -1;
    count = (uint8_t)(len & 0x7fu);
    long_form = (len & 0x80u) ? 1u : 0u;
    if (count == 0) return -1;
    for (uint8_t i = 0; i < count && i < 16u; ++i) {
        uint32_t rsp = 0;
        if (hda_corb_cmd(hda_cmd_12(g_hda.cad, pin, HDA_VERB_GET_CONN_LIST_ENTRY, i), &rsp) < 0) break;
        if (long_form) {
            if ((rsp & 0xffffu) == dac) {
                hda_corb_cmd(hda_cmd_12(g_hda.cad, pin, HDA_VERB_SET_CONN_SELECT_CONTROL, i), 0);
                return 0;
            }
        } else {
            for (uint8_t j = 0; j < 4u; ++j) {
                if (((rsp >> (j * 8u)) & 0xffu) == dac) {
                    hda_corb_cmd(hda_cmd_12(g_hda.cad, pin, HDA_VERB_SET_CONN_SELECT_CONTROL, (uint8_t)(i + j)), 0);
                    return 0;
                }
            }
        }
    }
    return -1;
}

static int hda_find_output_path(void) {
    uint32_t root_nodes = 0;
    uint8_t fg_start;
    uint8_t fg_count;

    if (hda_get_parameter(0, HDA_PARAM_SUB_NODE_COUNT, &root_nodes) < 0) {
        printf("[audio][hda] failed to read root node count\n");
        return -1;
    }
    fg_start = (uint8_t)((root_nodes >> 16) & 0xffu);
    fg_count = (uint8_t)(root_nodes & 0xffu);
    for (uint8_t f = 0; f < fg_count; ++f) {
        uint8_t fg = (uint8_t)(fg_start + f);
        uint32_t type = 0;
        uint32_t nodes = 0;
        uint8_t start;
        uint8_t count;
        uint8_t first_dac = 0;
        uint8_t first_pin = 0;

        if (hda_get_parameter(fg, HDA_PARAM_FCT_GRP_TYPE, &type) < 0) continue;
        if ((type & 0xffu) != HDA_PARAM_FCT_GRP_AUDIO) continue;
        hda_corb_cmd(hda_cmd_12(g_hda.cad, fg, HDA_VERB_SET_POWER_STATE, 0), 0);
        if (hda_get_parameter(fg, HDA_PARAM_SUB_NODE_COUNT, &nodes) < 0) continue;
        start = (uint8_t)((nodes >> 16) & 0xffu);
        count = (uint8_t)(nodes & 0xffu);
        for (uint8_t i = 0; i < count; ++i) {
            uint8_t nid = (uint8_t)(start + i);
            uint32_t cap = 0;
            if (hda_get_parameter(nid, HDA_PARAM_AUDIO_WIDGET_CAP, &cap) < 0) continue;
            if (hda_widget_type(cap) == HDA_WIDGET_AUDIO_OUTPUT && !first_dac) first_dac = nid;
            if (hda_widget_type(cap) == HDA_WIDGET_PIN_COMPLEX) {
                uint32_t pincap = 0;
                if (hda_get_parameter(nid, HDA_PARAM_PIN_CAP, &pincap) == 0 &&
                    (pincap & (HDA_PIN_CAP_OUTPUT | HDA_PIN_CAP_HEADPHONE)) && !first_pin) {
                    first_pin = nid;
                }
            }
        }
        if (first_dac && first_pin) {
            g_hda.afg = fg;
            g_hda.dac_nid = first_dac;
            g_hda.pin_nid = first_pin;
            hda_conn_selects_dac(first_pin, first_dac);
            hda_corb_cmd(hda_cmd_12(g_hda.cad, first_pin, HDA_VERB_SET_PIN_WIDGET_CTRL,
                                    HDA_PIN_OUT_ENABLE | HDA_PIN_HP_ENABLE), 0);
            hda_corb_cmd(hda_cmd_12(g_hda.cad, first_pin, HDA_VERB_SET_EAPD_BTL_ENABLE, HDA_EAPD_ENABLE), 0);
            hda_corb_cmd(hda_cmd_4(g_hda.cad, first_dac, 0x3u,
                                   0xb000u), 0);
            hda_corb_cmd(hda_cmd_4(g_hda.cad, first_dac, 0x2u,
                                   HDA_FORMAT_48K_16_STEREO), 0);
            hda_corb_cmd(hda_cmd_12(g_hda.cad, first_dac, HDA_VERB_SET_CONV_STREAM_CHAN,
                                    (HDA_STREAM_TAG << 4)), 0);
            return 0;
        }
        printf("[audio][hda] afg=%u no output path dac=%u pin=%u\n",
               (uint32_t)fg, (uint32_t)first_dac, (uint32_t)first_pin);
    }
    return -1;
}

static void hda_stream_reset(uint32_t sd) {
    hda_write8(sd + HDAC_SDCTL0, 0);
    hda_write8(sd + HDAC_SDCTL0, HDAC_SDCTL_SRST);
    for (uint32_t i = 0; i < 10000u; ++i) {
        if (hda_read8(sd + HDAC_SDCTL0) & HDAC_SDCTL_SRST) break;
        __asm__ __volatile__("pause");
    }
    hda_write8(sd + HDAC_SDCTL0, 0);
    for (uint32_t i = 0; i < 10000u; ++i) {
        if ((hda_read8(sd + HDAC_SDCTL0) & HDAC_SDCTL_SRST) == 0) break;
        __asm__ __volatile__("pause");
    }
    hda_write8(sd + HDAC_SDSTS, HDAC_SDSTS_BCIS | HDAC_SDSTS_FIFOE | HDAC_SDSTS_DESE);
}

static int hda_play_locked(const char *buf, uint32_t len) {
    uint32_t n = len;
    uint32_t sd = g_hda.stream_base;
    uint64_t start;

    if (!g_hda.ready) return -1;
    if (!buf && len) return -1;
    if (n == 0) return 0;
    if (n > HDA_DMA_BYTES) n = HDA_DMA_BYTES;
    if (n & 3u) n &= ~3u;
    if (n == 0) return 0;

    memcpy(g_hda_dma, buf, n);
    g_hda_bdl[0].addr_lo = (uint32_t)(uintptr_t)g_hda_dma;
    g_hda_bdl[0].addr_hi = 0;
    g_hda_bdl[0].length = n;
    g_hda_bdl[0].ioc = 1;
    memset(&g_hda_bdl[1], 0, sizeof(g_hda_bdl[1]));

    hda_stream_reset(sd);
    hda_write32(sd + HDAC_SDBDPL, (uint32_t)(uintptr_t)g_hda_bdl);
    hda_write32(sd + HDAC_SDBDPU, 0);
    hda_write32(sd + HDAC_SDCBL, n);
    hda_write16(sd + HDAC_SDLVI, 0);
    hda_write16(sd + HDAC_SDFMT, HDA_FORMAT_48K_16_STEREO);
    hda_write8(sd + HDAC_SDCTL2, (uint8_t)(HDA_STREAM_TAG << 4));
    hda_write8(sd + HDAC_SDCTL0, HDAC_SDCTL_IOCE | HDAC_SDCTL_RUN);

    start = hda_now_us();
    for (;;) {
        uint8_t st = hda_read8(sd + HDAC_SDSTS);
        if (st & (HDAC_SDSTS_BCIS | HDAC_SDSTS_FIFOE | HDAC_SDSTS_DESE)) {
            hda_write8(sd + HDAC_SDCTL0, 0);
            hda_write8(sd + HDAC_SDSTS, HDAC_SDSTS_BCIS | HDAC_SDSTS_FIFOE | HDAC_SDSTS_DESE);
            return (st & (HDAC_SDSTS_FIFOE | HDAC_SDSTS_DESE)) ? -1 : (int)n;
        }
        if (hda_now_us() - start > 5000000ull) {
            hda_write8(sd + HDAC_SDCTL0, 0);
            return -1;
        }
        __asm__ __volatile__("sti; hlt");
    }
}

static int hda_write_pcm(const char *buf, uint32_t len) {
    uint32_t done = 0;
    if (!g_hda.ready) return -1;
    while (done < len) {
        uint32_t n = len - done;
        int rc;
        uint64_t flags;
        if (n > HDA_DMA_BYTES) n = HDA_DMA_BYTES;
        flags = spin_lock_irqsave(&g_hda.lock);
        rc = hda_play_locked(buf + done, n);
        spin_unlock_irqrestore(&g_hda.lock, flags);
        if (rc < 0) return done ? (int)done : -1;
        if (rc == 0) break;
        done += (uint32_t)rc;
    }
    return (int)done;
}

static int hda_probe_one(uint8_t bus, uint8_t slot, uint8_t func) {
    uint32_t bar0 = pci_read_bar(bus, slot, func, 0);
    uint16_t command;
    uint16_t gcap;
    uint8_t oss;
    struct audio_backend backend;

    if ((bar0 & 1u) || ((bar0 & ~0x0fu) == 0)) {
        printf("[audio][hda] invalid BAR0=0x%x at %02x:%02x.%u\n",
               bar0, (uint32_t)bus, (uint32_t)slot, (uint32_t)func);
        return -1;
    }
    memset(&g_hda, 0, sizeof(g_hda));
    g_hda.bus = bus;
    g_hda.slot = slot;
    g_hda.func = func;
    g_hda.mmio_phys = bar0 & ~0x0fu;
    g_hda.mmio = (volatile uint8_t *)edge_mmio_low_alias(g_hda.mmio_phys);
    spinlock_init(&g_hda.lock);

    command = pci_cfg_read16(bus, slot, func, PCI_COMMAND_REG);
    pci_cfg_write16(bus, slot, func, PCI_COMMAND_REG,
                    (uint16_t)(command | PCI_COMMAND_MEM | PCI_COMMAND_BUS_MASTER));

    hda_write32(HDAC_GCTL, hda_read32(HDAC_GCTL) & ~HDAC_GCTL_CRST);
    if (hda_wait32(HDAC_GCTL, HDAC_GCTL_CRST, 0, 100000u) < 0) {
        printf("[audio][hda] controller reset assert timed out gctl=0x%x\n", hda_read32(HDAC_GCTL));
        return -1;
    }
    hda_write32(HDAC_GCTL, hda_read32(HDAC_GCTL) | HDAC_GCTL_CRST);
    if (hda_wait32(HDAC_GCTL, HDAC_GCTL_CRST, HDAC_GCTL_CRST, 1000000u) < 0) {
        printf("[audio][hda] controller reset clear timed out gctl=0x%x\n", hda_read32(HDAC_GCTL));
        return -1;
    }

    gcap = hda_read16(HDAC_GCAP);
    g_hda.iss = (uint8_t)HDAC_GCAP_ISS(gcap);
    g_hda.oss = (uint8_t)HDAC_GCAP_OSS(gcap);
    oss = g_hda.oss ? g_hda.oss : 1u;
    (void)oss;
    g_hda.stream_base = 0x80u + ((uint32_t)g_hda.iss * 0x20u);

    printf("[audio][hda] probing %02x:%02x.%u mmio=0x%x gcap=0x%x iss=%u oss=%u stream=0x%x\n",
           (uint32_t)bus, (uint32_t)slot, (uint32_t)func, g_hda.mmio_phys,
           (uint32_t)gcap, (uint32_t)g_hda.iss, (uint32_t)g_hda.oss,
           (uint32_t)g_hda.stream_base);
    if (hda_find_codec() < 0) {
        printf("[audio][hda] no responding codec found\n");
        return -1;
    }
    if (hda_find_output_path() < 0) {
        printf("[audio][hda] no playable output path found\n");
        return -1;
    }

    g_hda.ready = 1;
    memset(&backend, 0, sizeof(backend));
    backend.name = "Intel HD Audio";
    backend.kind = AUDIO_BACKEND_HDA;
    backend.bus = bus;
    backend.slot = slot;
    backend.func = func;
    backend.write_pcm = hda_write_pcm;
    if (audio_register_backend(&backend) < 0) return -1;
    printf("[audio][hda] controller ready at %02x:%02x.%u mmio=0x%x cad=%u afg=%u dac=%u pin=%u stream=0x%x rate=48000 format=s16le-stereo\n",
           (uint32_t)bus, (uint32_t)slot, (uint32_t)func, g_hda.mmio_phys,
           (uint32_t)g_hda.cad, (uint32_t)g_hda.afg, (uint32_t)g_hda.dac_nid,
           (uint32_t)g_hda.pin_nid, (uint32_t)g_hda.stream_base);
    return 0;
}

int audio_hda_init(void) {
    for (uint32_t bus = 0; bus < 256u; ++bus) {
        for (uint8_t slot = 0; slot < 32u; ++slot) {
            for (uint8_t func = 0; func < 8u; ++func) {
                uint16_t vendor = pci_cfg_read16((uint8_t)bus, slot, func, 0x00);
                uint8_t class_code;
                uint8_t subclass;
                uint8_t hdr;
                if (vendor == PCI_VENDOR_INVALID) {
                    if (func == 0) break;
                    continue;
                }
                class_code = pci_cfg_read8((uint8_t)bus, slot, func, 0x0b);
                subclass = pci_cfg_read8((uint8_t)bus, slot, func, 0x0a);
                if (class_code == PCI_CLASS_MULTIMEDIA && subclass == PCI_SUBCLASS_AUDIO_HDA) {
                    if (hda_probe_one((uint8_t)bus, slot, func) == 0) return 0;
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
