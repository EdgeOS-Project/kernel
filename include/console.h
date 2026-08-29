#ifndef CONSOLE_H
#define CONSOLE_H

#include <stdint.h>
#include "console_backend.h"

#define MAXIMUM_PAGES  16
#define SCROLL_UP      1
#define SCROLL_DOWN    2

#define COLOR_BLACK    0xFF000000u
#define COLOR_BLUE     0xFF0000AAu
#define COLOR_GREEN    0xFF00AA00u
#define COLOR_WHITE    0xFFFFFFFFu

void console_set_backend(const console_backend_t* be);

void console_init(uint32_t fore_color, uint32_t back_color);
void console_clear(uint32_t fore_color, uint32_t back_color);
void console_scroll(int type);
void console_gotoxy(uint16_t x, uint16_t y);

void console_putchar(char ch);
void console_putchar_vt(int vt, char ch);
void console_putstr(const char *str);
void console_output_batch_begin(void);
void console_output_batch_end(void);
void console_kernel_log_putstr(const char *str);
void console_kernel_log_off(void);
void console_kernel_log_on(void);
int console_kernel_log_set_level(int level);
void console_activate_vt(int vt);
int console_get_active_vt(void);
uint32_t console_active_vt_generation(void);
typedef void (*console_active_vt_notifier_fn)(uint32_t generation);
void console_active_vt_notifier_register(console_active_vt_notifier_fn notifier);
void console_set_kernel_log_timestamps(int enabled);

void printf(const char *format, ...);
void printf_color(uint32_t color, const char *format, ...);

#define console_printf printf


void console_ungetchar(void);
void console_ungetchar_bound(uint8_t n);


void getstr(char *buffer);
void getstr_bound(char *buffer, uint8_t bound);


uint8_t get_cursor_x(void);
uint8_t get_cursor_y(void);

#endif /* CONSOLE_H */
