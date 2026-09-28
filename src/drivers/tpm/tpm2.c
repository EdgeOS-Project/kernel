/*-
 * Copyright (c) 2018 Stormshield.
 * Copyright (c) 2018 Semihalf.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * Modifications for EdgeOS.
 * Copyright (c) EdgeOS Contributors.
 *
 * BSD-derived from FreeBSD's sys/dev/tpm TPM 2.0 TIS/CRB register definitions.
 * The EdgeOS integration is an independent polled probe path; it does not copy
 * FreeBSD's device_t, cdev, or command queue implementation.
 */

#include "drivers/tpm2.h"
#include "drivers/acpi.h"
#include "stdio.h"
#include "sys/mmio.h"

#include <stdint.h>

#define BIT(x) (1u << (x))

#define TPM2_START_METHOD_TIS      6u
#define TPM2_START_METHOD_CRB      7u
#define TPM2_START_METHOD_CRB_ACPI 8u

#define TPM_TIS_DEFAULT_BASE 0xFED40000ULL
#define TPM_ACCESS          0x000u
#define TPM_INTF_CAPS       0x014u
#define TPM_STS             0x018u
#define TPM_INTF_ID         0x030u
#define TPM_DID_VID         0xF00u
#define TPM_RID             0xF04u

#define TPM_ACCESS_LOC_REQ    BIT(1)
#define TPM_ACCESS_LOC_ACTIVE BIT(5)
#define TPM_ACCESS_VALID      BIT(7)
#define TPM_STS_VALID         BIT(7)
#define TPM_STS_CMD_RDY       BIT(6)
#define TPM_INTF_CAPS_TPM20   0x30000000u
#define TPM_INTF_CAPS_VERSION 0x70000000u

#define TPM_CRB_INTF_ID       0x030u
#define TPM_CRB_CTRL_STS      0x044u
#define TPM_CRB_CTRL_CMD_SIZE 0x058u
#define TPM_CRB_CTRL_RSP_SIZE 0x064u
#define TPM_CRB_DATA_BUFFER   0x080u
#define TPM_CRB_INTF_ID_TYPE_CRB 0x1u
#define TPM_CRB_INTF_ID_TYPE     0x7u

struct acpi_tpm2_table {
    char signature[4];
    uint32_t length;
    uint8_t revision;
    uint8_t checksum;
    char oemid[6];
    char oem_table_id[8];
    uint32_t oem_revision;
    uint32_t creator_id;
    uint32_t creator_revision;
    uint16_t platform_class;
    uint16_t reserved;
    uint64_t control_area;
    uint32_t start_method;
} __attribute__((packed));

static int g_tpm2_available;

static uint8_t tpm_read8(volatile uint8_t *base, uint32_t off) {
    return *(volatile uint8_t *)(base + off);
}

static uint32_t tpm_read32(volatile uint8_t *base, uint32_t off) {
    return *(volatile uint32_t *)(base + off);
}

static void tpm_write8(volatile uint8_t *base, uint32_t off, uint8_t value) {
    *(volatile uint8_t *)(base + off) = value;
}

static int tpm_wait8(volatile uint8_t *base, uint32_t off, uint8_t mask, uint8_t value) {
    for (uint32_t i = 0; i < 2000000u; ++i) {
        if ((tpm_read8(base, off) & mask) == value) return 0;
        __asm__ __volatile__("pause");
    }
    return -1;
}

static int tpm_probe_tis(uint64_t phys, uint32_t start_method) {
    volatile uint8_t *base = (volatile uint8_t *)edge_mmio_low_alias(phys);
    uint8_t access;
    uint32_t caps;
    uint32_t didvid;
    uint8_t rid;
    uint32_t sts;

    access = tpm_read8(base, TPM_ACCESS);
    if ((access & TPM_ACCESS_VALID) == 0) {
        printf("[tpm2] TIS access register invalid at 0x%llx access=0x%x\n",
               (unsigned long long)phys, (uint32_t)access);
        return -1;
    }

    tpm_write8(base, TPM_ACCESS, TPM_ACCESS_LOC_REQ);
    if (tpm_wait8(base, TPM_ACCESS, TPM_ACCESS_VALID | TPM_ACCESS_LOC_ACTIVE,
                  TPM_ACCESS_VALID | TPM_ACCESS_LOC_ACTIVE) < 0) {
        printf("[tpm2] TIS locality request timed out at 0x%llx access=0x%x\n",
               (unsigned long long)phys, (uint32_t)tpm_read8(base, TPM_ACCESS));
        return -1;
    }

    caps = tpm_read32(base, TPM_INTF_CAPS);
    didvid = tpm_read32(base, TPM_DID_VID);
    rid = tpm_read8(base, TPM_RID);
    sts = tpm_read32(base, TPM_STS);
    tpm_write8(base, TPM_ACCESS, TPM_ACCESS_LOC_ACTIVE);

    if (!didvid || didvid == 0xFFFFFFFFu) {
        printf("[tpm2] TIS absent at 0x%llx didvid=0x%x\n",
               (unsigned long long)phys, didvid);
        return -1;
    }

    g_tpm2_available = 1;
    printf("[tpm2] TIS ready base=0x%llx didvid=0x%x rid=0x%x caps=0x%x tpm20=%u sts=0x%x start=%u\n",
           (unsigned long long)phys, didvid, (uint32_t)rid, caps,
           ((caps & TPM_INTF_CAPS_VERSION) == TPM_INTF_CAPS_TPM20) ? 1u : 0u,
           sts, start_method);
    return 0;
}

static int tpm_probe_crb(uint64_t control_area, uint32_t start_method) {
    volatile uint8_t *base;
    uint32_t intf_id;
    uint32_t sts;
    uint32_t cmd_size;
    uint32_t rsp_size;

    if (!control_area) return -1;
    base = (volatile uint8_t *)edge_mmio_low_alias(control_area);
    intf_id = tpm_read32(base, TPM_CRB_INTF_ID);
    if ((intf_id & TPM_CRB_INTF_ID_TYPE) != TPM_CRB_INTF_ID_TYPE_CRB) {
        printf("[tpm2] CRB control area 0x%llx has non-CRB interface id=0x%x\n",
               (unsigned long long)control_area, intf_id);
        return -1;
    }
    sts = tpm_read32(base, TPM_CRB_CTRL_STS);
    cmd_size = tpm_read32(base, TPM_CRB_CTRL_CMD_SIZE);
    rsp_size = tpm_read32(base, TPM_CRB_CTRL_RSP_SIZE);
    g_tpm2_available = 1;
    printf("[tpm2] CRB ready control=0x%llx intf=0x%x sts=0x%x cmd=%u rsp=%u start=%u\n",
           (unsigned long long)control_area, intf_id, sts, cmd_size, rsp_size,
           start_method);
    return 0;
}

void tpm2_init(void) {
    const struct acpi_tpm2_table *tbl =
        (const struct acpi_tpm2_table *)(uintptr_t)acpi_find_table("TPM2", 0);

    g_tpm2_available = 0;
    if (tbl && tbl->length >= sizeof(*tbl)) {
        printf("[tpm2] ACPI TPM2 start=%u control=0x%llx class=%u\n",
               tbl->start_method, (unsigned long long)tbl->control_area,
               (uint32_t)tbl->platform_class);
        if ((tbl->start_method == TPM2_START_METHOD_CRB ||
             tbl->start_method == TPM2_START_METHOD_CRB_ACPI) &&
            tpm_probe_crb(tbl->control_area, tbl->start_method) == 0) {
            return;
        }
        if (tbl->start_method == TPM2_START_METHOD_TIS &&
            tpm_probe_tis(TPM_TIS_DEFAULT_BASE, tbl->start_method) == 0) {
            return;
        }
    }

    if (tpm_probe_tis(TPM_TIS_DEFAULT_BASE, 0) == 0) return;
    printf("[tpm2] no TPM 2.0 device found\n");
}

int tpm2_available(void) {
    return g_tpm2_available;
}
