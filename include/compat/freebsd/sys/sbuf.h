/* SPDX-License-Identifier: BSD-2-Clause */
/* FreeBSD sbuf interface for unmodified driver sources. */

#ifndef _SYS_SBUF_H_
#define _SYS_SBUF_H_

#include <stddef.h>
#include <stdarg.h>

#ifndef _SSIZE_T_DECLARED
typedef __PTRDIFF_TYPE__ ssize_t;
#define _SSIZE_T_DECLARED
#endif

struct sbuf;
typedef int sbuf_drain_func(void *, const char *, int);

struct sbuf {
    char *s_buf;
    sbuf_drain_func *s_drain_func;
    void *s_drain_arg;
    int s_error;
    ssize_t s_size;
    ssize_t s_len;
#define SBUF_FIXEDLEN 0x00000000
#define SBUF_AUTOEXTEND 0x00000001
#define SBUF_INCLUDENUL 0x00000002
#define SBUF_DRAINTOEOR 0x00000004
#define SBUF_NOWAIT 0x00000008
#define SBUF_USRFLAGMSK 0x0000ffff
#define SBUF_DYNAMIC 0x00010000
#define SBUF_FINISHED 0x00020000
#define SBUF_DYNSTRUCT 0x00080000
#define SBUF_INSECTION 0x00100000
#define SBUF_DRAINATEOL 0x00200000
    int s_flags;
    ssize_t s_sect_len;
    ssize_t s_rec_off;
};

struct sbuf *sbuf_new(struct sbuf *, char *, int, int);
#define sbuf_new_auto() sbuf_new(0, 0, 0, SBUF_AUTOEXTEND)
int sbuf_get_flags(struct sbuf *);
void sbuf_clear_flags(struct sbuf *, int);
void sbuf_set_flags(struct sbuf *, int);
void sbuf_clear(struct sbuf *);
int sbuf_setpos(struct sbuf *, ssize_t);
int sbuf_bcat(struct sbuf *, const void *, size_t);
int sbuf_bcpy(struct sbuf *, const void *, size_t);
int sbuf_cat(struct sbuf *, const char *);
int sbuf_cpy(struct sbuf *, const char *);
int sbuf_printf(struct sbuf *, const char *, ...);
int sbuf_vprintf(struct sbuf *, const char *, va_list);
int sbuf_nl_terminate(struct sbuf *);
int sbuf_putc(struct sbuf *, int);
void sbuf_hexdump(struct sbuf *, const void *, int, const char *, int);
void sbuf_set_drain(struct sbuf *, sbuf_drain_func *, void *);
int sbuf_drain(struct sbuf *);
int sbuf_trim(struct sbuf *);
int sbuf_error(const struct sbuf *);
int sbuf_finish(struct sbuf *);
char *sbuf_data(struct sbuf *);
ssize_t sbuf_len(struct sbuf *);
int sbuf_done(const struct sbuf *);
void sbuf_delete(struct sbuf *);
void sbuf_start_section(struct sbuf *, ssize_t *);
ssize_t sbuf_end_section(struct sbuf *, ssize_t, size_t, int);
int sbuf_count_drain(void *, const char *, int);
int sbuf_printf_drain(void *, const char *, int);
void sbuf_putbuf(struct sbuf *);

#endif
