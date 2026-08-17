/* SPDX-License-Identifier: BSD-2-Clause */
/* x86 interrupt-remapping constants used by imported IOMMU drivers. */

#ifndef _X86_APICREG_H_
#define _X86_APICREG_H_

#define IOART_TRGREDG 0x00000000u
#define IOART_TRGRLVL 0x00008000u
#define IOART_INTAHI 0x00000000u
#define IOART_INTALO 0x00002000u
#define IOART_DELFIXED 0x00000000u
#define IOART_INTVEC 0x000000ffu

#endif
