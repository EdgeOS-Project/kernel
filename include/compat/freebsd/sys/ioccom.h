/* SPDX-License-Identifier: BSD-2-Clause */
/* FreeBSD ioctl command encoding used by imported device interfaces. */

#ifndef _SYS_IOCCOM_H_
#define _SYS_IOCCOM_H_

#define IOCPARM_MASK 0x1fffUL
#define IOCPARM_MAX (1UL << 13)
#define IOC_VOID 0x20000000UL
#define IOC_OUT 0x40000000UL
#define IOC_IN 0x80000000UL
#define IOC_INOUT (IOC_IN | IOC_OUT)
#define IOCPARM_LEN(command) \
    (((unsigned long)(command) >> 16) & IOCPARM_MASK)
#define IOCBASECMD(command) \
    ((unsigned long)(command) & ~(IOCPARM_MASK << 16))
#define IOCGROUP(command) \
    (((unsigned long)(command) >> 8) & 0xffUL)

#define _IOC(direction, group, number, length) \
    ((unsigned long)(direction) | \
     (((unsigned long)(length) & IOCPARM_MASK) << 16) | \
     ((unsigned long)(group) << 8) | (unsigned long)(number))
#define _IO(group, number) _IOC(IOC_VOID, group, number, 0)
#define _IOWINT(group, number) _IOC(IOC_VOID, group, number, sizeof(int))
#define _IOR(group, number, type) \
    _IOC(IOC_OUT, group, number, sizeof(type))
#define _IOW(group, number, type) \
    _IOC(IOC_IN, group, number, sizeof(type))
#define _IOWR(group, number, type) \
    _IOC(IOC_INOUT, group, number, sizeof(type))

#endif
