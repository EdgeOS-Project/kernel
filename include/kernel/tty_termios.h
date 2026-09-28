/* SPDX-License-Identifier: MPL-2.0 */
#ifndef EDGEOS_KERNEL_TTY_TERMIOS_H
#define EDGEOS_KERNEL_TTY_TERMIOS_H
#include <stdint.h>

#define EDGE_LINUX_TCGETS2 0x802c542au
#define EDGE_LINUX_TCSETS2 0x402c542bu
#define EDGE_LINUX_TCSETSW2 0x402c542cu
#define EDGE_LINUX_TCSETSF2 0x402c542du
#define EDGE_LINUX_TERMIOS_CBAUD 0x100fu
#define EDGE_LINUX_TERMIOS_BOTHER 0x1000u

typedef struct edge_linux_termios2 {
    uint32_t c_iflag, c_oflag, c_cflag, c_lflag;
    uint8_t c_line;
    uint8_t c_cc[19];
    uint32_t c_ispeed, c_ospeed;
} edge_linux_termios2_t;
_Static_assert(sizeof(edge_linux_termios2_t) == 44u, "Linux termios2 ABI size");

static inline int edge_linux_termios2_is_set(uint32_t command) {
    return command == EDGE_LINUX_TCSETS2 || command == EDGE_LINUX_TCSETSW2 ||
           command == EDGE_LINUX_TCSETSF2;
}

static inline uint32_t edge_linux_termios_baud(uint32_t code, uint32_t custom) {
    static const uint32_t rates[16] = {
        0, 50, 75, 110, 134, 150, 200, 300, 600, 1200, 1800, 2400,
        4800, 9600, 19200, 38400
    };
    static const uint32_t extended[16] = {
        0, 57600, 115200, 230400, 460800, 500000, 576000, 921600,
        1000000, 1152000, 1500000, 2000000, 2500000, 3000000, 3500000, 4000000
    };
    code &= EDGE_LINUX_TERMIOS_CBAUD;
    if (code == EDGE_LINUX_TERMIOS_BOTHER) return custom;
    return code & 0x1000u ? extended[code & 15u] : rates[code];
}

static inline void edge_linux_termios2_normalize_speeds(edge_linux_termios2_t *value) {
    uint32_t input_code = (value->c_cflag >> 16) & EDGE_LINUX_TERMIOS_CBAUD;
    value->c_ospeed = edge_linux_termios_baud(value->c_cflag, value->c_ospeed);
    value->c_ispeed = input_code ? edge_linux_termios_baud(input_code, value->c_ispeed) : value->c_ospeed;
}
#endif
