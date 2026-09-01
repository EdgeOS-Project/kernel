/* SPDX-License-Identifier: MPL-2.0 */
/* Kernel open flags used by imported character-device drivers. */

#ifndef _SYS_FCNTL_H_
#define _SYS_FCNTL_H_

#define FREAD 0x0001
#define FWRITE 0x0002
#define O_RDONLY 0x0000
#define O_WRONLY 0x0001
#define O_RDWR 0x0002
#define O_NONBLOCK 0x0004
#define O_APPEND 0x0008
#define O_CREAT 0x0200
#define O_ASYNC 0x0040
#define O_EXCL 0x0800
#define O_DIRECTORY 0x00020000
#define O_CLOEXEC 0x00100000
#define O_VERIFY 0x00200000
#define FNONBLOCK O_NONBLOCK
#define FNDELAY O_NONBLOCK
#define FAPPEND O_APPEND
#define FASYNC O_ASYNC
#define FLASTCLOSE O_DIRECTORY
#define FREVOKE O_VERIFY

#endif
