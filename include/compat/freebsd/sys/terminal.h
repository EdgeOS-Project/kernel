/* SPDX-License-Identifier: BSD-2-Clause */
/* Minimal FreeBSD terminal types used by imported framebuffer drivers. */

#ifndef _SYS_TERMINAL_H_
#define _SYS_TERMINAL_H_

#include <stdint.h>

typedef uint32_t term_char_t;
typedef uint8_t term_color_t;

typedef struct {
    unsigned short tp_row;
    unsigned short tp_col;
} term_pos_t;

typedef struct {
    term_pos_t tr_begin;
    term_pos_t tr_end;
} term_rect_t;

#define TF_BOLD 0x01
#define TF_UNDERLINE 0x02
#define TF_BLINK 0x04
#define TF_REVERSE 0x08

#define TC_BLACK 0
#define TC_RED 1
#define TC_GREEN 2
#define TC_YELLOW 3
#define TC_BLUE 4
#define TC_MAGENTA 5
#define TC_CYAN 6
#define TC_WHITE 7
#define TC_LIGHT 8

#define TCHAR_CHARACTER(character) ((character) & 0x1fffffU)
#define TCHAR_FORMAT(character) (((character) >> 21) & 0x1fU)
#define TCHAR_FGCOLOR(character) (((character) >> 26) & 0x7U)
#define TCHAR_BGCOLOR(character) (((character) >> 29) & 0x7U)
#define TCOLOR_LIGHT(color) ((color) | TC_LIGHT)

#endif
