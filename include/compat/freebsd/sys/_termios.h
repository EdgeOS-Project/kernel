/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright (c) 1988, 1989, 1993, 1994
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef _SYS__TERMIOS_H_
#define _SYS__TERMIOS_H_

#define VEOF 0
#define VEOL 1
#define VEOL2 2
#define VERASE 3
#define VWERASE 4
#define VKILL 5
#define VREPRINT 6
#define VERASE2 7
#define VINTR 8
#define VQUIT 9
#define VSUSP 10
#define VDSUSP 11
#define VSTART 12
#define VSTOP 13
#define VLNEXT 14
#define VDISCARD 15
#define VMIN 16
#define VTIME 17
#define VSTATUS 18
#define NCCS 20

#define _POSIX_VDISABLE 0xff

#define IGNBRK 0x00000001u
#define BRKINT 0x00000002u
#define IGNPAR 0x00000004u
#define PARMRK 0x00000008u
#define INPCK 0x00000010u
#define ISTRIP 0x00000020u
#define INLCR 0x00000040u
#define IGNCR 0x00000080u
#define ICRNL 0x00000100u
#define IXON 0x00000200u
#define IXOFF 0x00000400u
#define IXANY 0x00000800u
#define IMAXBEL 0x00002000u
#define IUTF8 0x00004000u

#define OPOST 0x00000001u
#define ONLCR 0x00000002u
#define TABDLY 0x00000004u
#define TAB0 0x00000000u
#define TAB3 0x00000004u
#define ONOEOT 0x00000008u
#define OCRNL 0x00000010u
#define ONOCR 0x00000020u
#define ONLRET 0x00000040u

#define CIGNORE 0x00000001u
#define CSIZE 0x00000300u
#define CS5 0x00000000u
#define CS6 0x00000100u
#define CS7 0x00000200u
#define CS8 0x00000300u
#define CSTOPB 0x00000400u
#define CREAD 0x00000800u
#define PARENB 0x00001000u
#define PARODD 0x00002000u
#define HUPCL 0x00004000u
#define CLOCAL 0x00008000u
#define CCTS_OFLOW 0x00010000u
#define CRTS_IFLOW 0x00020000u
#define CRTSCTS (CCTS_OFLOW | CRTS_IFLOW)
#define CDTR_IFLOW 0x00040000u
#define CDSR_OFLOW 0x00080000u
#define CCAR_OFLOW 0x00100000u
#define CNO_RTSDTR 0x00200000u

#define ECHOKE 0x00000001u
#define ECHOE 0x00000002u
#define ECHOK 0x00000004u
#define ECHO 0x00000008u
#define ECHONL 0x00000010u
#define ECHOPRT 0x00000020u
#define ECHOCTL 0x00000040u
#define ISIG 0x00000080u
#define ICANON 0x00000100u
#define ALTWERASE 0x00000200u
#define IEXTEN 0x00000400u
#define EXTPROC 0x00000800u
#define TOSTOP 0x00400000u
#define FLUSHO 0x00800000u
#define NOKERNINFO 0x02000000u
#define PENDIN 0x20000000u
#define NOFLSH 0x80000000u

#define B0 0u
#define B50 50u
#define B75 75u
#define B110 110u
#define B134 134u
#define B150 150u
#define B200 200u
#define B300 300u
#define B600 600u
#define B1200 1200u
#define B1800 1800u
#define B2400 2400u
#define B4800 4800u
#define B7200 7200u
#define B9600 9600u
#define B14400 14400u
#define B19200 19200u
#define B28800 28800u
#define B38400 38400u
#define B57600 57600u
#define B76800 76800u
#define B115200 115200u
#define B230400 230400u
#define B460800 460800u
#define B500000 500000u
#define B921600 921600u
#define B1000000 1000000u
#define B1500000 1500000u
#define B2000000 2000000u
#define B2500000 2500000u
#define B3000000 3000000u
#define B3500000 3500000u
#define B4000000 4000000u
#define EXTA B19200
#define EXTB B38400

typedef unsigned int tcflag_t;
typedef unsigned char cc_t;
typedef unsigned int speed_t;

struct termios {
    tcflag_t c_iflag;
    tcflag_t c_oflag;
    tcflag_t c_cflag;
    tcflag_t c_lflag;
    cc_t c_cc[NCCS];
    speed_t c_ispeed;
    speed_t c_ospeed;
};

#endif
