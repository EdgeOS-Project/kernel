#ifndef SERIAL_CONSOLE_H
#define SERIAL_CONSOLE_H

void serial_console_init(void);
int serial_console_is_ready(void);
void serial_console_write_raw(char ch);
void serial_console_write_emergency(char ch);
void serial_console_clear(void);
int serial_console_pollchar(void);
int serial_console_haschar(void);
int serial_console_probechar(void);
int serial_console_buffered(void);
void serial_console_inject_input(const char *s);
int serial_console_proc_snapshot(char *buf, unsigned int max);

#endif
