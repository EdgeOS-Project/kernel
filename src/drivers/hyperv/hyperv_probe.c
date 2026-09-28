/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Hyper-V CPUID/VMBus availability probe for EdgeOS.
 *
 * Copyright (c) EdgeOS Contributors.
 */

#include "drivers/hyperv.h"

#include "stdio.h"

#include <stdint.h>

static int g_hyperv_present;

static void cpuid_leaf(uint32_t leaf, uint32_t subleaf,
                       uint32_t *a, uint32_t *b, uint32_t *c, uint32_t *d) {
    uint32_t ra, rb, rc, rd;
    __asm__ volatile("cpuid"
                     : "=a"(ra), "=b"(rb), "=c"(rc), "=d"(rd)
                     : "a"(leaf), "c"(subleaf));
    if (a) *a = ra;
    if (b) *b = rb;
    if (c) *c = rc;
    if (d) *d = rd;
}

void hyperv_probe_init(void) {
    uint32_t max_leaf = 0, ebx = 0, ecx = 0, edx = 0;
    char sig[13];
    g_hyperv_present = 0;
    cpuid_leaf(0x40000000u, 0, &max_leaf, &ebx, &ecx, &edx);
    sig[0] = (char)(ebx & 0xffu);
    sig[1] = (char)((ebx >> 8) & 0xffu);
    sig[2] = (char)((ebx >> 16) & 0xffu);
    sig[3] = (char)((ebx >> 24) & 0xffu);
    sig[4] = (char)(ecx & 0xffu);
    sig[5] = (char)((ecx >> 8) & 0xffu);
    sig[6] = (char)((ecx >> 16) & 0xffu);
    sig[7] = (char)((ecx >> 24) & 0xffu);
    sig[8] = (char)(edx & 0xffu);
    sig[9] = (char)((edx >> 8) & 0xffu);
    sig[10] = (char)((edx >> 16) & 0xffu);
    sig[11] = (char)((edx >> 24) & 0xffu);
    sig[12] = 0;
    if (sig[0] == 'M' && sig[1] == 'i' && sig[2] == 'c' && sig[3] == 'r' &&
        sig[4] == 'o' && sig[5] == 's' && sig[6] == 'o' && sig[7] == 'f' &&
        sig[8] == 't' && sig[9] == ' ' && sig[10] == 'H' && sig[11] == 'v') {
        uint32_t features = 0, rec = 0;
        g_hyperv_present = 1;
        if (max_leaf >= 0x40000003u) cpuid_leaf(0x40000003u, 0, &features, &rec, 0, 0);
        printf("[hyperv] detected vendor=\"%s\" max_leaf=0x%x features=0x%x recommendations=0x%x\n",
               sig, max_leaf, features, rec);
        printf("[hyperv] NetVSC requires VMBus channel support; data path not enabled yet\n");
    } else {
        printf("[hyperv] not detected vendor=\"%s\" max_leaf=0x%x\n", sig, max_leaf);
    }
}

int hyperv_is_present(void) {
    return g_hyperv_present;
}
