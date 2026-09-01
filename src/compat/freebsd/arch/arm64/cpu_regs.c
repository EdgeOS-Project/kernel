/* SPDX-License-Identifier: MPL-2.0 */
/* AArch64 identification-register access for the FreeBSD VMM bridge. */

#include <stdint.h>

#include <machine/armreg.h>
#include <machine/cpu.h>

#define EDGE_READ_ID_REGISTER(name, destination) \
    __asm__ __volatile__("mrs %0, " #name : "=r"(destination))

void
get_kernel_reg_iss(unsigned int iss, uint64_t *value)
{
    uint64_t result = 0;

    if (!value)
        return;
    switch (iss) {
    case ID_AA64AFR0_EL1_ISS:
        EDGE_READ_ID_REGISTER(id_aa64afr0_el1, result);
        break;
    case ID_AA64AFR1_EL1_ISS:
        EDGE_READ_ID_REGISTER(id_aa64afr1_el1, result);
        break;
    case ID_AA64DFR0_EL1_ISS:
        EDGE_READ_ID_REGISTER(id_aa64dfr0_el1, result);
        break;
    case ID_AA64DFR1_EL1_ISS:
        EDGE_READ_ID_REGISTER(id_aa64dfr1_el1, result);
        break;
    case ID_AA64ISAR0_EL1_ISS:
        EDGE_READ_ID_REGISTER(id_aa64isar0_el1, result);
        break;
    case ID_AA64ISAR1_EL1_ISS:
        EDGE_READ_ID_REGISTER(id_aa64isar1_el1, result);
        break;
    case ID_AA64ISAR2_EL1_ISS:
        EDGE_READ_ID_REGISTER(id_aa64isar2_el1, result);
        break;
    case ID_AA64MMFR0_EL1_ISS:
        EDGE_READ_ID_REGISTER(id_aa64mmfr0_el1, result);
        if ((result & ID_AA64MMFR0_PARange_MASK) >
            ID_AA64MMFR0_PARange_256T) {
            result &= ~ID_AA64MMFR0_PARange_MASK;
            result |= ID_AA64MMFR0_PARange_256T;
        }
        break;
    case ID_AA64MMFR1_EL1_ISS:
        EDGE_READ_ID_REGISTER(id_aa64mmfr1_el1, result);
        break;
    case ID_AA64MMFR2_EL1_ISS:
        EDGE_READ_ID_REGISTER(id_aa64mmfr2_el1, result);
        break;
    case ID_AA64PFR0_EL1_ISS:
        EDGE_READ_ID_REGISTER(id_aa64pfr0_el1, result);
        break;
    case ID_AA64PFR1_EL1_ISS:
        EDGE_READ_ID_REGISTER(id_aa64pfr1_el1, result);
        break;
    default:
        return;
    }
    *value = result;
}

void
get_kernel_reg_iss_masked(unsigned int iss, uint64_t *value,
    uint64_t mask)
{
    uint64_t host;
    uint64_t result = 0;
    uint64_t unsigned_fields = 0;

    if (!value)
        return;
    host = *value;
    get_kernel_reg_iss(iss, &host);
    if (iss == ID_AA64DFR0_EL1_ISS) {
        unsigned_fields = ID_AA64DFR0_CTX_CMPs_MASK |
            ID_AA64DFR0_WRPs_MASK | ID_AA64DFR0_BRPs_MASK;
    }
    for (unsigned int shift = 0; shift < 64u; shift += 4u) {
        unsigned int host_field = (unsigned int)((host >> shift) & 0xfu);
        unsigned int limit_field = (unsigned int)((mask >> shift) & 0xfu);
        int host_signed = host_field >= 8u ? (int)host_field - 16 :
            (int)host_field;
        int limit_signed = limit_field >= 8u ? (int)limit_field - 16 :
            (int)limit_field;
        unsigned int selected;

        if ((unsigned_fields & (UINT64_C(0xf) << shift)) != 0) {
            selected = host_field < limit_field ?
                host_field : limit_field;
        } else {
            selected = host_signed < limit_signed ?
                host_field : limit_field;
        }

        result |= (uint64_t)selected << shift;
    }
    *value = result;
}
