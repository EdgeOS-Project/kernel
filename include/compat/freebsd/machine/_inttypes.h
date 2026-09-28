/* SPDX-License-Identifier: MPL-2.0 */
/* Integer format macros for the shared 64-bit BSD driver personality. */

#ifndef _MACHINE__INTTYPES_H_
#define _MACHINE__INTTYPES_H_

#if __SIZEOF_LONG__ == 8
#define EDGEOS_PRI64 "l"
#define EDGEOS_PRIPTR "l"
#else
#define EDGEOS_PRI64 "ll"
#define EDGEOS_PRIPTR
#endif

#define PRId8 "d"
#define PRId16 "d"
#define PRId32 "d"
#define PRId64 EDGEOS_PRI64 "d"
#define PRIi8 "i"
#define PRIi16 "i"
#define PRIi32 "i"
#define PRIi64 EDGEOS_PRI64 "i"
#define PRIo8 "o"
#define PRIo16 "o"
#define PRIo32 "o"
#define PRIo64 EDGEOS_PRI64 "o"
#define PRIu8 "u"
#define PRIu16 "u"
#define PRIu32 "u"
#define PRIu64 EDGEOS_PRI64 "u"
#define PRIx8 "x"
#define PRIx16 "x"
#define PRIx32 "x"
#define PRIx64 EDGEOS_PRI64 "x"
#define PRIX8 "X"
#define PRIX16 "X"
#define PRIX32 "X"
#define PRIX64 EDGEOS_PRI64 "X"

#define PRIdMAX "jd"
#define PRIiMAX "ji"
#define PRIoMAX "jo"
#define PRIuMAX "ju"
#define PRIxMAX "jx"
#define PRIXMAX "jX"
#define PRIdPTR EDGEOS_PRIPTR "d"
#define PRIiPTR EDGEOS_PRIPTR "i"
#define PRIoPTR EDGEOS_PRIPTR "o"
#define PRIuPTR EDGEOS_PRIPTR "u"
#define PRIxPTR EDGEOS_PRIPTR "x"
#define PRIXPTR EDGEOS_PRIPTR "X"

#endif
