/* SPDX-License-Identifier: BSD-2-Clause */
/* Source-compatible string buffer runtime for imported FreeBSD drivers. */

#include "compat/freebsd/sys/sbuf.h"

#include "compat/freebsd/edgeos/malloc.h"
#include "compat/freebsd/edgeos/systm.h"

#ifdef BSD_BRIDGE_HOST_TEST
#include <stdio.h>
#else
void printf(const char *format, ...);
#endif

#define BSD_SBUF_EINVAL 22
#define BSD_SBUF_ENOMEM 12
#define BSD_SBUF_INITIAL_CAPACITY 64

static int
sbuf_set_error(struct sbuf *buffer, int error)
{
    if (buffer && buffer->s_error == 0)
        buffer->s_error = error;
    return -1;
}

static int
sbuf_extend(struct sbuf *buffer, size_t required)
{
    char *replacement;
    size_t capacity;

    if ((buffer->s_flags & SBUF_AUTOEXTEND) == 0)
        return sbuf_set_error(buffer, BSD_SBUF_ENOMEM);
    capacity = buffer->s_size > 0 ?
        (size_t)buffer->s_size : BSD_SBUF_INITIAL_CAPACITY;
    while (capacity < required) {
        if (capacity > SIZE_MAX / 2)
            return sbuf_set_error(buffer, BSD_SBUF_ENOMEM);
        capacity *= 2;
    }
    replacement = bsd_malloc(capacity, M_TEMP,
        ((buffer->s_flags & SBUF_NOWAIT) != 0 ? M_NOWAIT : M_WAITOK));
    if (!replacement)
        return sbuf_set_error(buffer, BSD_SBUF_ENOMEM);
    if (buffer->s_buf && buffer->s_len > 0)
        bsd_memcpy(replacement, buffer->s_buf, (size_t)buffer->s_len);
    if ((buffer->s_flags & SBUF_DYNAMIC) != 0)
        bsd_free(buffer->s_buf, M_TEMP);
    buffer->s_buf = replacement;
    buffer->s_size = (ssize_t)capacity;
    buffer->s_flags |= SBUF_DYNAMIC;
    return 0;
}

static int
sbuf_reserve(struct sbuf *buffer, size_t additional)
{
    size_t required;

    if (!buffer || buffer->s_error != 0)
        return -1;
    if (additional > SIZE_MAX - (size_t)buffer->s_len - 1)
        return sbuf_set_error(buffer, BSD_SBUF_ENOMEM);
    required = (size_t)buffer->s_len + additional + 1;
    if (required <= (size_t)buffer->s_size)
        return 0;
    return sbuf_extend(buffer, required);
}

struct sbuf *
sbuf_new(struct sbuf *buffer, char *storage, int length, int flags)
{
    int dynamic_structure = 0;

    if (length < 0 ||
        (flags & ~SBUF_USRFLAGMSK) != 0 ||
        (!storage && (flags & SBUF_AUTOEXTEND) == 0))
        return 0;
    if (!buffer) {
        buffer = bsd_malloc(sizeof(*buffer), M_TEMP, M_WAITOK | M_ZERO);
        if (!buffer)
            return 0;
        dynamic_structure = 1;
    } else {
        bsd_memset(buffer, 0, sizeof(*buffer));
    }
    buffer->s_buf = storage;
    buffer->s_size = length;
    buffer->s_flags = flags |
        (dynamic_structure ? SBUF_DYNSTRUCT : 0);
    if (!storage) {
        size_t initial = length > 0 ?
            (size_t)length : BSD_SBUF_INITIAL_CAPACITY;

        buffer->s_buf = bsd_malloc(initial, M_TEMP,
            (flags & SBUF_NOWAIT) != 0 ? M_NOWAIT : M_WAITOK);
        if (!buffer->s_buf) {
            if (dynamic_structure)
                bsd_free(buffer, M_TEMP);
            return 0;
        }
        buffer->s_size = (ssize_t)initial;
        buffer->s_flags |= SBUF_DYNAMIC;
    }
    if (buffer->s_size > 0)
        buffer->s_buf[0] = '\0';
    return buffer;
}

int
sbuf_get_flags(struct sbuf *buffer)
{
    return buffer ? buffer->s_flags & SBUF_USRFLAGMSK : 0;
}

void
sbuf_clear_flags(struct sbuf *buffer, int flags)
{
    if (buffer)
        buffer->s_flags &= ~(flags & SBUF_USRFLAGMSK);
}

void
sbuf_set_flags(struct sbuf *buffer, int flags)
{
    if (buffer)
        buffer->s_flags |= flags & SBUF_USRFLAGMSK;
}

void
sbuf_clear(struct sbuf *buffer)
{
    if (!buffer)
        return;
    buffer->s_error = 0;
    buffer->s_len = 0;
    buffer->s_sect_len = 0;
    buffer->s_rec_off = 0;
    buffer->s_flags &= ~(SBUF_FINISHED | SBUF_INSECTION);
    if (buffer->s_buf && buffer->s_size > 0)
        buffer->s_buf[0] = '\0';
}

int
sbuf_setpos(struct sbuf *buffer, ssize_t position)
{
    if (!buffer || position < 0 || position > buffer->s_len)
        return sbuf_set_error(buffer, BSD_SBUF_EINVAL);
    buffer->s_len = position;
    buffer->s_flags &= ~SBUF_FINISHED;
    if (buffer->s_buf && position < buffer->s_size)
        buffer->s_buf[position] = '\0';
    return 0;
}

int
sbuf_bcat(struct sbuf *buffer, const void *data, size_t length)
{
    if (!buffer || (!data && length != 0) ||
        (buffer->s_flags & SBUF_FINISHED) != 0)
        return sbuf_set_error(buffer, BSD_SBUF_EINVAL);
    if (sbuf_reserve(buffer, length) != 0)
        return -1;
    if (length != 0)
        bsd_memcpy(buffer->s_buf + buffer->s_len, data, length);
    buffer->s_len += (ssize_t)length;
    buffer->s_buf[buffer->s_len] = '\0';
    if ((buffer->s_flags & SBUF_INSECTION) != 0)
        buffer->s_sect_len += (ssize_t)length;
    return 0;
}

int
sbuf_bcpy(struct sbuf *buffer, const void *data, size_t length)
{
    sbuf_clear(buffer);
    return sbuf_bcat(buffer, data, length);
}

int
sbuf_cat(struct sbuf *buffer, const char *text)
{
    return text ? sbuf_bcat(buffer, text, bsd_strlen(text)) :
        sbuf_set_error(buffer, BSD_SBUF_EINVAL);
}

int
sbuf_cpy(struct sbuf *buffer, const char *text)
{
    sbuf_clear(buffer);
    return sbuf_cat(buffer, text);
}

int
sbuf_vprintf(struct sbuf *buffer, const char *format, va_list arguments)
{
    va_list measure_arguments;
    va_list write_arguments;
    int length;

    if (!buffer || !format ||
        (buffer->s_flags & SBUF_FINISHED) != 0)
        return sbuf_set_error(buffer, BSD_SBUF_EINVAL);
    va_copy(measure_arguments, arguments);
    length = bsd_vsnprintf(0, 0, format, measure_arguments);
    va_end(measure_arguments);
    if (length < 0 || sbuf_reserve(buffer, (size_t)length) != 0)
        return -1;
    va_copy(write_arguments, arguments);
    (void)bsd_vsnprintf(buffer->s_buf + buffer->s_len,
        (size_t)(buffer->s_size - buffer->s_len),
        format, write_arguments);
    va_end(write_arguments);
    buffer->s_len += length;
    if ((buffer->s_flags & SBUF_INSECTION) != 0)
        buffer->s_sect_len += length;
    return 0;
}

int
sbuf_printf(struct sbuf *buffer, const char *format, ...)
{
    va_list arguments;
    int result;

    va_start(arguments, format);
    result = sbuf_vprintf(buffer, format, arguments);
    va_end(arguments);
    return result;
}

int
sbuf_putc(struct sbuf *buffer, int value)
{
    char byte = (char)value;

    return sbuf_bcat(buffer, &byte, 1);
}

void
sbuf_hexdump(struct sbuf *buffer, const void *data, int length,
    const char *header, int flags)
{
    const unsigned char *bytes = data;
    int columns = flags & HD_COLUMN_MASK;
    char delimiter = (char)((flags & HD_DELIM_MASK) >> 8);

    if (!buffer || !bytes || length <= 0)
        return;
    if (columns == 0)
        columns = 16;
    if (delimiter == 0)
        delimiter = ' ';
    for (int offset = 0; offset < length; offset += columns) {
        if (header)
            (void)sbuf_cat(buffer, header);
        if ((flags & HD_OMIT_COUNT) == 0)
            (void)sbuf_printf(buffer, "%04x  ", offset);
        if ((flags & HD_OMIT_HEX) == 0) {
            for (int column = 0; column < columns; ++column) {
                int index = offset + column;

                if (index < length)
                    (void)sbuf_printf(buffer, "%c%02x", delimiter,
                        bytes[index]);
                else
                    (void)sbuf_cat(buffer, "   ");
            }
        }
        if ((flags & HD_OMIT_CHARS) == 0) {
            (void)sbuf_cat(buffer, "  |");
            for (int column = 0; column < columns; ++column) {
                int index = offset + column;
                int value = index < length ? bytes[index] : ' ';

                if (index < length && (value < ' ' || value > '~'))
                    value = '.';
                (void)sbuf_putc(buffer, value);
            }
            (void)sbuf_putc(buffer, '|');
        }
        (void)sbuf_putc(buffer, '\n');
    }
}

int
sbuf_nl_terminate(struct sbuf *buffer)
{
    if (!buffer)
        return -1;
    if (buffer->s_len == 0 ||
        buffer->s_buf[buffer->s_len - 1] != '\n')
        return sbuf_putc(buffer, '\n');
    return 0;
}

void
sbuf_set_drain(struct sbuf *buffer, sbuf_drain_func *drain, void *argument)
{
    if (!buffer)
        return;
    buffer->s_drain_func = drain;
    buffer->s_drain_arg = argument;
}

int
sbuf_drain(struct sbuf *buffer)
{
    int drained;

    if (!buffer || !buffer->s_drain_func)
        return 0;
    if (buffer->s_len == 0)
        return 0;
    drained = buffer->s_drain_func(buffer->s_drain_arg,
        buffer->s_buf, (int)buffer->s_len);
    if (drained < 0)
        return sbuf_set_error(buffer, -drained);
    if (drained > buffer->s_len)
        drained = (int)buffer->s_len;
    if (drained != 0) {
        size_t remaining = (size_t)buffer->s_len - (size_t)drained;

        bsd_memmove(buffer->s_buf, buffer->s_buf + drained, remaining);
        buffer->s_len = (ssize_t)remaining;
        buffer->s_buf[remaining] = '\0';
    }
    return drained;
}

int
sbuf_trim(struct sbuf *buffer)
{
    if (!buffer)
        return -1;
    while (buffer->s_len > 0) {
        char value = buffer->s_buf[buffer->s_len - 1];

        if (value != ' ' && value != '\t' && value != '\n' &&
            value != '\r')
            break;
        buffer->s_len--;
    }
    if (buffer->s_buf && buffer->s_size > 0)
        buffer->s_buf[buffer->s_len] = '\0';
    return 0;
}

int
sbuf_error(const struct sbuf *buffer)
{
    return buffer ? buffer->s_error : BSD_SBUF_EINVAL;
}

int
sbuf_finish(struct sbuf *buffer)
{
    int result;

    if (!buffer)
        return BSD_SBUF_EINVAL;
    if (buffer->s_error != 0)
        return buffer->s_error;
    if (sbuf_reserve(buffer, 0) != 0)
        return buffer->s_error;
    buffer->s_buf[buffer->s_len] = '\0';
    if (buffer->s_drain_func) {
        result = sbuf_drain(buffer);
        if (result < 0 || buffer->s_len != 0)
            return buffer->s_error ? buffer->s_error : BSD_SBUF_ENOMEM;
    }
    buffer->s_flags |= SBUF_FINISHED;
    return 0;
}

char *
sbuf_data(struct sbuf *buffer)
{
    return buffer ? buffer->s_buf : 0;
}

ssize_t
sbuf_len(struct sbuf *buffer)
{
    if (!buffer)
        return -1;
    return buffer->s_len +
        ((buffer->s_flags & SBUF_INCLUDENUL) != 0 ? 1 : 0);
}

int
sbuf_done(const struct sbuf *buffer)
{
    return buffer && (buffer->s_flags & SBUF_FINISHED) != 0;
}

void
sbuf_putbuf(struct sbuf *buffer)
{
    char *data;

    if (!buffer)
        return;
    data = sbuf_data(buffer);
    if (data)
        bsd_printf("%s", data);
}

void
sbuf_delete(struct sbuf *buffer)
{
    int dynamic_structure;

    if (!buffer)
        return;
    dynamic_structure = (buffer->s_flags & SBUF_DYNSTRUCT) != 0;
    if ((buffer->s_flags & SBUF_DYNAMIC) != 0)
        bsd_free(buffer->s_buf, M_TEMP);
    if (dynamic_structure)
        bsd_free(buffer, M_TEMP);
    else
        bsd_memset(buffer, 0, sizeof(*buffer));
}

void
sbuf_start_section(struct sbuf *buffer, ssize_t *old_length)
{
    if (!buffer)
        return;
    if ((buffer->s_flags & SBUF_INSECTION) == 0) {
        if (old_length)
            *old_length = -1;
        buffer->s_rec_off = buffer->s_len;
        buffer->s_flags |= SBUF_INSECTION;
    } else {
        if (old_length)
            *old_length = buffer->s_sect_len;
        buffer->s_sect_len = 0;
    }
}

ssize_t
sbuf_end_section(struct sbuf *buffer, ssize_t old_length, size_t padding,
    int pad_character)
{
    size_t remainder;
    ssize_t section_length;

    if (!buffer || (buffer->s_flags & SBUF_INSECTION) == 0)
        return -1;
    if (padding > 1) {
        remainder = (size_t)buffer->s_sect_len % padding;
        if (remainder != 0) {
            size_t count = padding - remainder;

            while (count-- != 0) {
                if (sbuf_putc(buffer, pad_character) != 0)
                    return -1;
            }
        }
    }
    section_length = buffer->s_sect_len;
    if (old_length == -1) {
        buffer->s_rec_off = 0;
        buffer->s_sect_len = 0;
        buffer->s_flags &= ~SBUF_INSECTION;
    } else {
        buffer->s_sect_len += old_length;
    }
    return section_length;
}

int
sbuf_count_drain(void *argument, const char *data, int length)
{
    size_t *count = argument;

    (void)data;
    if (count && length > 0)
        *count += (size_t)length;
    return length;
}

int
sbuf_printf_drain(void *argument, const char *data, int length)
{
    size_t *count = argument;
    int result;

    if (!data || length < 0)
        return -BSD_SBUF_EINVAL;
    result = bsd_snprintf(0, 0, "%.*s", length, data);
    if (result != length)
        return -BSD_SBUF_EINVAL;
    printf("%.*s", length, data);
    if (count)
        *count += (size_t)length;
    return length;
}
