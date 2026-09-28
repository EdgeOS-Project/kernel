/* SPDX-License-Identifier: MPL-2.0 */
/* Host behavior tests for shared FreeBSD TTY and character devices. */

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "compat/freebsd/edgeos/allocator.h"
#include "compat/freebsd/edgeos/cdev.h"
#include "compat/freebsd/edgeos/sync.h"
#include "compat/freebsd/sys/conf.h"
#include "compat/freebsd/sys/tty.h"
#include "compat/freebsd/vm/vm_object.h"

#define TEST_PAGE_SIZE 4096u

typedef struct tty_test_context {
    struct mtx mutex;
    struct tty *tty;
    char output[128];
    uint32_t output_length;
    uint32_t open_count;
    uint32_t close_count;
    uint32_t free_count;
    uint32_t param_count;
    uint32_t break_start_count;
    uint32_t break_stop_count;
    struct termios parameters;
} tty_test_context_t;

static _Thread_local uint8_t g_thread_token;
static uint32_t g_devtmpfs_change_count;

int
vm_object_pager_physical_address(vm_object_t object,
    vm_ooffset_t offset, vm_paddr_t *physical_address)
{
    (void)object;
    (void)offset;
    (void)physical_address;
    return 6;
}

void
vm_object_deallocate(vm_object_t object)
{
    (void)object;
}

void
bsd_bridge_devtmpfs_changed(void)
{
    ++g_devtmpfs_change_count;
}

static void *
allocate_pages(uint64_t pages, void *context)
{
    void *memory = 0;

    (void)context;
    if (pages > SIZE_MAX / TEST_PAGE_SIZE ||
        posix_memalign(&memory, TEST_PAGE_SIZE,
        (size_t)pages * TEST_PAGE_SIZE) != 0)
        return 0;
    memset(memory, 0, (size_t)pages * TEST_PAGE_SIZE);
    return memory;
}

static void
release_pages(void *base, uint64_t pages, void *context)
{
    (void)pages;
    (void)context;
    free(base);
}

static void *
current_thread(void *context)
{
    (void)context;
    return &g_thread_token;
}

static int
cannot_block(void *thread, void *context)
{
    (void)thread;
    (void)context;
    return 0;
}

static void
noop_thread(void *thread, void *context)
{
    (void)thread;
    (void)context;
}

static void
noop_context(void *context)
{
    (void)context;
}

static int
test_open(struct tty *tty)
{
    tty_test_context_t *test = tty_softc(tty);

    assert(mtx_owned(&test->mutex));
    ++test->open_count;
    return 0;
}

static void
test_close(struct tty *tty)
{
    tty_test_context_t *test = tty_softc(tty);

    assert(mtx_owned(&test->mutex));
    ++test->close_count;
}

static void
test_output(struct tty *tty)
{
    tty_test_context_t *test = tty_softc(tty);
    size_t capacity = sizeof(test->output) - test->output_length;
    size_t received;

    assert(mtx_owned(&test->mutex));
    received = ttydisc_getc(tty, test->output + test->output_length,
        capacity);
    test->output_length += (uint32_t)received;
}

static void
test_free(void *context)
{
    tty_test_context_t *test = context;

    ++test->free_count;
    mtx_destroy(&test->mutex);
}

static int
test_param(struct tty *tty, struct termios *parameters)
{
    tty_test_context_t *test = tty_softc(tty);

    assert(mtx_owned(&test->mutex));
    ++test->param_count;
    test->parameters = *parameters;
    return 0;
}

static int
test_ioctl(struct tty *tty, unsigned long command, char *data,
    struct thread *thread)
{
    tty_test_context_t *test = tty_softc(tty);

    (void)data;
    (void)thread;
    assert(mtx_owned(&test->mutex));
    if (command == TIOCSBRK) {
        ++test->break_start_count;
        return 0;
    }
    if (command == TIOCCBRK) {
        ++test->break_stop_count;
        return 0;
    }
    return 25;
}

static uint64_t
linux_device_number(uint32_t major, uint32_t minor)
{
    return ((uint64_t)(minor & 0xffu)) |
        ((uint64_t)(major & 0xfffu) << 8) |
        ((uint64_t)(minor & ~0xffu) << 12) |
        ((uint64_t)(major & ~0xfffu) << 32);
}

int
main(void)
{
    bsd_allocator_ops_t allocator = {
        .allocate_pages = allocate_pages,
        .release_pages = release_pages,
    };
    bsd_sync_ops_t sync = {
        .current_thread = current_thread,
        .can_block = cannot_block,
        .prepare_block = noop_thread,
        .block_current = noop_thread,
        .wake_thread = noop_thread,
        .yield_thread = noop_context,
    };
    struct ttydevsw driver = {
        .tsw_flags = TF_CALLOUT,
        .tsw_open = test_open,
        .tsw_close = test_close,
        .tsw_outwakeup = test_output,
        .tsw_ioctl = test_ioctl,
        .tsw_param = test_param,
        .tsw_free = test_free,
    };
    tty_test_context_t test = {0};
    bsd_bridge_cdev_node_t primary;
    bsd_bridge_cdev_node_t alias;
    struct cdev *alias_device = 0;
    struct winsize size = {
        .ws_row = 48,
        .ws_col = 132,
    };
    uint64_t device;
    uint64_t read_sequence = 0;
    uint64_t write_sequence = 0;
    uint64_t change_sequence;
    uint32_t events = 0;
    bsd_bridge_linux_termios_t termios;
    bsd_bridge_linux_winsize_t linux_size;
    int32_t available = -1;
    char input[16] = {0};

    assert(bsd_allocator_initialize(&allocator) == 0);
    assert(bsd_sync_initialize(&sync) == 0);
    mtx_init(&test.mutex, "tty-unit", 0, MTX_DEF);
    test.tty = tty_alloc_mutex(&driver, &test, &test.mutex);
    assert(test.tty != 0);

    assert(tty_makedevf(test.tty, 0, 0, "%s%r.%r", "V", 4, 2) == 0);
    assert(bsd_bridge_cdev_node_count() == 2);
    assert(bsd_bridge_cdev_node_at(0, &primary) == 0);
    assert(strcmp(primary.name, "ttyV4.2") == 0);
    assert(primary.major == 229);
    assert(primary.minor == 0);
    assert(primary.mode == 0620);
    assert(primary.alias == 0);
    assert(bsd_bridge_cdev_node_at(1, &alias) == 0);
    assert(strcmp(alias.name, "cuaV4.2") == 0);
    assert(alias.major == primary.major && alias.minor == primary.minor);
    assert(alias.alias == 1);

    assert(make_dev_alias_p(MAKEDEV_NOWAIT | MAKEDEV_CHECKNAME,
        &alias_device, test.tty->t_dev, "%s/%*s",
        "vtcon", 5, "port0-tail") == 0);
    assert(alias_device != 0);
    assert(bsd_bridge_cdev_node_count() == 3);
    assert(bsd_bridge_cdev_node_at(2, &alias) == 0);
    assert(strcmp(alias.name, "vtcon/port0") == 0);
    assert(alias.major == primary.major && alias.minor == primary.minor);
    assert(alias.alias == 1);
    assert(make_dev_alias_p(MAKEDEV_NOWAIT | MAKEDEV_CHECKNAME,
        0, test.tty->t_dev, "%s", "../bad") == 22);

    device = linux_device_number(primary.major, primary.minor);
    change_sequence = bsd_bridge_cdev_change_sequence();
    assert(change_sequence != 0);
    assert(bsd_bridge_cdev_is_tty(device));
    assert(bsd_bridge_cdev_poll(device, &events) == 0);
    assert(events == BSD_BRIDGE_CDEV_POLL_WRITE);
    assert(bsd_bridge_cdev_poll_sequences(device, &read_sequence,
        &write_sequence) == 0);
    assert(read_sequence == 1 && write_sequence == 1);
    assert(bsd_bridge_cdev_write(device, "hello", 5) == 5);
    assert(test.open_count == 1);
    assert(test.output_length == 5);
    assert(memcmp(test.output, "hello", 5) == 0);

    tty_lock(test.tty);
    assert(ttydisc_rint_simple(test.tty, "world\n", 6) == 6);
    ttydisc_rint_done(test.tty);
    tty_set_winsize(test.tty, &size);
    tty_unlock(test.tty);
    assert(test.output_length == 12);
    assert(memcmp(test.output + 5, "world\r\n", 7) == 0);
    assert(test.tty->t_winsize.ws_row == 48);
    assert(test.tty->t_winsize.ws_col == 132);
    assert(bsd_bridge_cdev_poll(device, &events) == 0);
    assert((events & BSD_BRIDGE_CDEV_POLL_READ) != 0);
    assert(bsd_bridge_cdev_ioctl_supported(
        BSD_BRIDGE_LINUX_TCGETS));
    assert(bsd_bridge_cdev_ioctl_output_size(
        BSD_BRIDGE_LINUX_TCGETS) == sizeof(termios));
    assert(bsd_bridge_cdev_ioctl(device, BSD_BRIDGE_LINUX_TCGETS,
        0, &termios, sizeof(termios)) == 0);
    assert(termios.iflag == 0x500u);
    assert(termios.oflag == 0x5u);
    assert(termios.cflag == 0xbfu);
    assert(termios.lflag == 0x8a3bu);
    assert(bsd_bridge_cdev_ioctl(device, BSD_BRIDGE_LINUX_FIONREAD,
        0, &available, sizeof(available)) == 0);
    assert(available == 6);
    assert(bsd_bridge_cdev_read(device, input, sizeof(input)) == 6);
    assert(memcmp(input, "world\n", 6) == 0);
    assert(bsd_bridge_cdev_read(device, input, sizeof(input)) == -11);
    assert(test.open_count == 1);
    assert(bsd_bridge_cdev_ioctl(device,
        BSD_BRIDGE_LINUX_TIOCGWINSZ, 0,
        &linux_size, sizeof(linux_size)) == 0);
    assert(linux_size.rows == 48 && linux_size.columns == 132);

    termios.lflag = 0;
    termios.oflag = 0;
    termios.cflag = 0x80000000u | 0x1002u | 0x20u | 0x40u |
        0x80u | 0x100u | 0x800u;
    assert(bsd_bridge_cdev_ioctl(device, BSD_BRIDGE_LINUX_TCSETS,
        0, &termios, sizeof(termios)) == 0);
    assert(test.param_count == 1);
    assert(test.parameters.c_ispeed == B115200);
    assert(test.parameters.c_ospeed == B115200);
    assert((test.parameters.c_cflag &
        (CSIZE | CSTOPB | CREAD | PARENB | CLOCAL | CRTSCTS)) ==
        (CS7 | CSTOPB | CREAD | PARENB | CLOCAL | CRTSCTS));
    tty_lock(test.tty);
    assert(ttydisc_rint(test.tty, 'x', 0) == 0);
    ttydisc_rint_done(test.tty);
    tty_unlock(test.tty);
    assert(bsd_bridge_cdev_read(device, input, sizeof(input)) == 1);
    assert(input[0] == 'x');
    assert(bsd_bridge_cdev_ioctl(device, BSD_BRIDGE_LINUX_TCFLSH,
        2, 0, 0) == 0);
    assert(bsd_bridge_cdev_ioctl(device, BSD_BRIDGE_LINUX_TCSBRK,
        1, 0, 0) == 0);
    assert(test.break_start_count == 0 && test.break_stop_count == 0);
    assert(bsd_bridge_cdev_ioctl(device, BSD_BRIDGE_LINUX_TCSBRKP,
        1, 0, 0) == 0);
    assert(test.break_start_count == 1 && test.break_stop_count == 1);
    assert(bsd_bridge_cdev_poll_sequences(device, &read_sequence,
        &write_sequence) == 0);
    assert(read_sequence > 1 && write_sequence > 1);
    assert(bsd_bridge_cdev_change_sequence() > change_sequence);

    tty_lock(test.tty);
    tty_rel_gone(test.tty);
    test.tty = 0;
    assert(test.close_count == 1);
    assert(test.free_count == 1);
    assert(bsd_bridge_cdev_node_count() == 0);
    assert(bsd_bridge_cdev_read(device, input, sizeof(input)) ==
        BSD_BRIDGE_CDEV_NOT_HANDLED);
    assert(g_devtmpfs_change_count == 4);

    printf("bsd_bridge_tty_unit: PASS\n");
    return 0;
}
