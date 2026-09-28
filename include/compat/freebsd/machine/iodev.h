/* SPDX-License-Identifier: MPL-2.0 */
/* Direct x86 I/O access used by the imported firmware emulator. */

#ifndef _MACHINE_IODEV_H_
#define _MACHINE_IODEV_H_

#include <machine/cpufunc.h>

#define iodev_read_1 inb
#define iodev_read_2 inw
#define iodev_read_4 inl
#define iodev_write_1 outb
#define iodev_write_2 outw
#define iodev_write_4 outl

#endif
