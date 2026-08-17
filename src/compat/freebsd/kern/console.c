/* SPDX-License-Identifier: MPL-2.0 */
/* Console selection for imported FreeBSD device drivers. */

#include <stddef.h>

#include <sys/param.h>
#include <sys/cons.h>
#include <sys/tty.h>

#define BSD_CONSOLE_MAX_DEVICES 32u
#define BSD_CONSOLE_ENOSPC 28

int cn_mute;
struct tty *constty;

static struct consdev *g_console_devices[BSD_CONSOLE_MAX_DEVICES];
static struct consdev *g_selected_console;

static struct consdev *
console_best(void)
{
    struct consdev *best = 0;

    for (size_t index = 0; index < BSD_CONSOLE_MAX_DEVICES; ++index) {
        struct consdev *candidate = g_console_devices[index];

        if (!candidate || candidate->cn_pri == CN_DEAD ||
            (candidate->cn_flags & CN_FLAG_NOAVAIL) != 0)
            continue;
        if (!best || candidate->cn_pri > best->cn_pri)
            best = candidate;
    }
    return best;
}

int
cnadd(struct consdev *console)
{
    size_t available = BSD_CONSOLE_MAX_DEVICES;

    if (!console || !console->cn_ops)
        return BSD_CONSOLE_ENOSPC;
    for (size_t index = 0; index < BSD_CONSOLE_MAX_DEVICES; ++index) {
        if (g_console_devices[index] == console)
            return 0;
        if (!g_console_devices[index] &&
            available == BSD_CONSOLE_MAX_DEVICES)
            available = index;
    }
    if (available == BSD_CONSOLE_MAX_DEVICES)
        return BSD_CONSOLE_ENOSPC;
    if (console->cn_ops->cn_probe)
        console->cn_ops->cn_probe(console);
    if (console->cn_pri == CN_DEAD)
        return BSD_CONSOLE_ENOSPC;
    g_console_devices[available] = console;
    if (console->cn_ops->cn_init)
        console->cn_ops->cn_init(console);
    g_selected_console = console_best();
    return 0;
}

void
cnavailable(struct consdev *console, int available)
{
    if (!console)
        return;
    if (available)
        console->cn_flags &= ~CN_FLAG_NOAVAIL;
    else
        console->cn_flags |= CN_FLAG_NOAVAIL;
    g_selected_console = console_best();
}

void
cnremove(struct consdev *console)
{
    if (!console)
        return;
    for (size_t index = 0; index < BSD_CONSOLE_MAX_DEVICES; ++index) {
        if (g_console_devices[index] == console)
            g_console_devices[index] = 0;
    }
    if (console->cn_ops && console->cn_ops->cn_term)
        console->cn_ops->cn_term(console);
    g_selected_console = console_best();
}

void
cnselect(struct consdev *console)
{
    if (!console ||
        (console->cn_flags & CN_FLAG_NOAVAIL) != 0 ||
        console->cn_pri == CN_DEAD)
        return;
    g_selected_console = console;
}

void
cngrab(void)
{
    if (g_selected_console && g_selected_console->cn_ops &&
        g_selected_console->cn_ops->cn_grab)
        g_selected_console->cn_ops->cn_grab(g_selected_console);
}

void
cnungrab(void)
{
    if (g_selected_console && g_selected_console->cn_ops &&
        g_selected_console->cn_ops->cn_ungrab)
        g_selected_console->cn_ops->cn_ungrab(g_selected_console);
}

void
cnresume(void)
{
    if (g_selected_console && g_selected_console->cn_ops &&
        g_selected_console->cn_ops->cn_resume)
        g_selected_console->cn_ops->cn_resume(g_selected_console);
}

int
cncheckc(void)
{
    if (!g_selected_console || !g_selected_console->cn_ops ||
        !g_selected_console->cn_ops->cn_getc)
        return -1;
    return g_selected_console->cn_ops->cn_getc(g_selected_console);
}

int
cngetc(void)
{
    return cncheckc();
}

void
cnputc(int character)
{
    if (cn_mute || !g_selected_console ||
        !g_selected_console->cn_ops ||
        !g_selected_console->cn_ops->cn_putc)
        return;
    g_selected_console->cn_ops->cn_putc(
        g_selected_console, character);
}

void
cnputsn(const char *text, size_t length)
{
    if (!text)
        return;
    for (size_t index = 0; index < length; ++index)
        cnputc((unsigned char)text[index]);
}

void
cnputs(const char *text)
{
    if (!text)
        return;
    while (*text != '\0')
        cnputc((unsigned char)*text++);
}

int
cnunavailable(void)
{
    return !g_selected_console ||
        (g_selected_console->cn_flags & CN_FLAG_NOAVAIL) != 0;
}

int
constty_set(struct tty *tty)
{
    constty = tty;
    return 0;
}

int
constty_clear(struct tty *tty)
{
    if (constty == tty)
        constty = 0;
    return 0;
}
