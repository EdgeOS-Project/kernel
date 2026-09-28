/* SPDX-License-Identifier: MPL-2.0 */
/* Host behavior tests for shared per-open FreeBSD character devices. */

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "compat/freebsd/edgeos/allocator.h"
#include "compat/freebsd/edgeos/cdev.h"
#include "compat/freebsd/edgeos/kthread.h"
#include "compat/freebsd/edgeos/sync.h"
#include "compat/freebsd/sys/conf.h"
#include "compat/freebsd/sys/fcntl.h"
#include "compat/freebsd/sys/ioccom.h"
#include "compat/freebsd/sys/kthread.h"
#include "compat/freebsd/sys/poll.h"
#include "compat/freebsd/sys/uio.h"
#include "compat/freebsd/vm/vm_object.h"

#define TEST_PAGE_SIZE 4096u
#define TEST_IOCTL _IOWR('T', 1, uint32_t)
#define TEST_LINUX_READ_IOCTL 0x80045402u
#define TEST_FREEBSD_READ_IOCTL _IOR('T', 2, uint32_t)
#define TEST_LINUX_VOID_IOCTL 0x00005103u
#define TEST_FREEBSD_VOID_IOCTL _IO('Q', 3)
#define TEST_LINUX_V4L2_QUERYBUF 0xc0585609u
#define TEST_FREEBSD_LLP64_V4L2_QUERYBUF 0xc0505609u
#define TEST_FREEBSD_VARIABLE_IOCTL _IOR('H', 7, uint64_t)
#define TEST_MMAP_PHYSICAL 0x12345000u
#define TEST_MMAP_SINGLE_PHYSICAL 0x23456000u

typedef struct cdev_test_private {
    uint32_t ordinal;
} cdev_test_private_t;

static _Thread_local uint8_t g_thread_token;
static uint32_t g_open_count;
static uint32_t g_close_count;
static uint32_t g_destructor_count;
static uint32_t g_open_ordinal;
static uint32_t g_last_close_count;
static uint32_t g_devtmpfs_change_count;
static uint32_t g_lifecycle_sequence;
static uint32_t g_close_sequence[4];
static uint32_t g_destructor_sequence[4];
static char g_written[32];
static uint32_t g_written_length;
static uint32_t g_void_ioctl_count;
static uint32_t g_mmap_single_release_count;
static struct vm_object g_mmap_single_object;

int
bsd_bus_dma_virtual_address(uint64_t physical_address, size_t length,
    void **virtual_address)
{
    if (!physical_address || !length || !virtual_address)
        return -1;
    *virtual_address = (void *)(uintptr_t)physical_address;
    return 0;
}

int
vm_object_pager_physical_address(vm_object_t object,
    vm_ooffset_t offset, vm_paddr_t *physical_address)
{
    assert(object == &g_mmap_single_object);
    assert(physical_address != 0);
    if (offset >= 2u * TEST_PAGE_SIZE)
        return 22;
    *physical_address = TEST_MMAP_SINGLE_PHYSICAL + offset;
    return 0;
}

void
vm_object_deallocate(vm_object_t object)
{
    assert(object == &g_mmap_single_object);
    g_mmap_single_release_count++;
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

static void
test_private_destructor(void *argument)
{
    cdev_test_private_t *private_data = argument;

    assert(private_data != 0);
    assert(g_destructor_count < 4);
    g_destructor_sequence[g_destructor_count++] =
        ++g_lifecycle_sequence;
    free(private_data);
}

static d_priv_dtor_t *const test_destructor_type =
    test_private_destructor;

static int
test_open(struct cdev *device, int flags, int device_type,
    struct thread *thread)
{
    cdev_test_private_t *private_data;

    assert(device != 0);
    assert(device_type == 0020000);
    assert(thread != 0);
    assert(thread->td_proc != 0);
    assert((flags & (FREAD | FWRITE)) != 0);
    private_data = calloc(1, sizeof(*private_data));
    assert(private_data != 0);
    private_data->ordinal = ++g_open_ordinal;
    assert(devfs_set_cdevpriv(
        private_data, test_private_destructor) == 0);
    ++g_open_count;
    return 0;
}

static int
test_close(struct cdev *device, int flags, int device_type,
    struct thread *thread)
{
    cdev_test_private_t *private_data = 0;

    assert(device != 0);
    assert(device_type == 0020000);
    assert(thread != 0);
    assert(devfs_get_cdevpriv((void **)&private_data) == 0);
    assert(private_data != 0);
    assert(g_close_count < 4);
    g_close_sequence[g_close_count++] = ++g_lifecycle_sequence;
    if ((flags & FLASTCLOSE) != 0)
        ++g_last_close_count;
    return 0;
}

static int
test_read(struct cdev *device, struct uio *operation, int flags)
{
    static char contents[] = "abcdef";
    cdev_test_private_t *private_data = 0;

    assert(device != 0);
    assert(operation != 0);
    assert((flags & FREAD) != 0);
    assert(devfs_get_cdevpriv((void **)&private_data) == 0);
    assert(private_data != 0);
    return uiomove_frombuf(contents, 6, operation);
}

static int
test_write(struct cdev *device, struct uio *operation, int flags)
{
    cdev_test_private_t *private_data = 0;
    int available;

    assert(device != 0);
    assert(operation != 0);
    assert((flags & FWRITE) != 0);
    assert(devfs_get_cdevpriv((void **)&private_data) == 0);
    assert(private_data != 0);
    available = (int)(sizeof(g_written) - g_written_length);
    if (available > operation->uio_resid)
        available = (int)operation->uio_resid;
    if (available == 0)
        return 0;
    {
        int error = uiomove(
            g_written + g_written_length, available, operation);

        if (error)
            return error;
    }
    g_written_length += (uint32_t)available;
    return 0;
}

static int
test_ioctl(struct cdev *device, unsigned long command, caddr_t data,
    int flags, struct thread *thread)
{
    cdev_test_private_t *private_data = 0;
    uint32_t *value = (uint32_t *)(void *)data;

    assert(device != 0);
    assert(data != 0);
    assert((flags & FREAD) != 0);
    assert(thread != 0);
    assert(devfs_get_cdevpriv((void **)&private_data) == 0);
    assert(private_data != 0);
    switch (command) {
    case TEST_IOCTL:
        *value += private_data->ordinal;
        break;
    case TEST_FREEBSD_READ_IOCTL:
        assert(*value == 0);
        *value = 100u + private_data->ordinal;
        break;
    case TEST_FREEBSD_VOID_IOCTL:
        assert(*(uint64_t *)(void *)data == UINT64_C(0x1234));
        g_void_ioctl_count++;
        break;
    case TEST_FREEBSD_LLP64_V4L2_QUERYBUF:
        assert(*(uint32_t *)(void *)(data + 0u) == 3u);
        assert(*(uint32_t *)(void *)(data + 60u) == 1u);
        assert(*(uint32_t *)(void *)(data + 64u) == 0x2000u);
        *(uint32_t *)(void *)(data + 68u) = 0x3000u;
        *(uint32_t *)(void *)(data + 76u) = 7u;
        break;
    default:
        assert(0);
    }
    return 0;
}

static int
test_mmap(struct cdev *device, vm_ooffset_t offset, vm_paddr_t *physical,
    int protection, vm_memattr_t *memory_attribute)
{
    cdev_test_private_t *private_data = 0;

    assert(device != 0);
    assert(physical != 0);
    assert(memory_attribute != 0);
    assert(protection == 3);
    assert(devfs_get_cdevpriv((void **)&private_data) == 0);
    assert(private_data != 0);
    if (offset >= 2u * TEST_PAGE_SIZE)
        return 22;
    *physical = TEST_MMAP_PHYSICAL + offset;
    *memory_attribute = BSD_BRIDGE_CDEV_MEMORY_WRITE_COMBINING;
    return 0;
}

static int
test_mmap_single(struct cdev *device, vm_ooffset_t *offset,
    vm_size_t size, vm_object_t *object, int protection)
{
    cdev_test_private_t *private_data = 0;

    assert(device != 0);
    assert(offset != 0);
    assert(object != 0);
    assert(size == TEST_PAGE_SIZE);
    assert(protection == 3);
    assert(devfs_get_cdevpriv((void **)&private_data) == 0);
    assert(private_data != 0);
    if (*offset >= 2u * TEST_PAGE_SIZE)
        return 22;
    *object = &g_mmap_single_object;
    return 0;
}

static int
test_poll(struct cdev *device, int events, struct thread *thread)
{
    cdev_test_private_t *private_data = 0;

    assert(device != 0);
    assert(thread != 0);
    assert((events & POLLIN) != 0);
    assert((events & POLLOUT) != 0);
    assert(devfs_get_cdevpriv((void **)&private_data) == 0);
    assert(private_data != 0);
    return POLLIN | POLLOUT;
}

static int
sum_private_ordinals(void *data, void *argument)
{
    cdev_test_private_t *private_data = data;
    uint32_t *sum = argument;

    assert(private_data != 0);
    assert(sum != 0);
    *sum += private_data->ordinal;
    return 0;
}

static uint64_t
linux_device_number(uint32_t major, uint32_t minor)
{
    return ((uint64_t)(minor & 0xffu)) |
        ((uint64_t)(major & 0xfffu) << 8) |
        ((uint64_t)(minor & ~0xffu) << 12) |
        ((uint64_t)(major & ~0xfffu) << 32);
}

static void
test_clone_devices(struct cdevsw *driver)
{
    struct clonedevs *clones = 0;
    struct cdev *device = 0;
    struct cdev *existing = 0;
    char exact_name[] = "vkbd12";
    char suffix_name[] = "vkbd12extra";
    char leading_zero_name[] = "vkbd01";
    char *name_end = 0;
    int unit = -1;

    assert(dev_stdclone(exact_name, &name_end, "vkbd", &unit) == 1);
    assert(unit == 12);
    assert(name_end == exact_name + 6);
    assert(dev_stdclone(suffix_name, &name_end, "vkbd", &unit) == 2);
    assert(name_end == suffix_name + 6);
    assert(dev_stdclone(leading_zero_name, 0, "vkbd", &unit) == 0);

    clone_setup(&clones);
    assert(clones != 0);
    unit = -1;
    assert(clone_create(&clones, driver, &unit, &device, 0) == 1);
    assert(unit == 0);
    assert(device == 0);
    device = make_dev_credf(MAKEDEV_REF, driver, unit, 0,
        0, 0, 0600, "vkbd%d", unit);
    assert(device != 0);
    assert(device->si_drv0 == unit);
    assert(device->edgeos_references == 1);
    assert(bsd_bridge_cdev_node_count() == 1);

    unit = 0;
    assert(clone_create(&clones, driver, &unit, &existing, 0) == 0);
    assert(existing == device);
    dev_ref(existing);
    assert(existing->edgeos_references == 2);
    dev_rel(existing);
    dev_rel(device);
    assert(device->edgeos_references == 0);

    clone_cleanup(&clones);
    assert(clones == 0);
    assert(bsd_bridge_cdev_node_count() == 0);
}

static void
test_mmap_single_device(struct cdevsw *driver)
{
    bsd_bridge_cdev_node_t node;
    struct cdev *device;
    uint64_t linux_device;
    uint64_t mapped_physical = 0;
    int32_t memory_attribute = -1;

    driver->d_mmap = 0;
    driver->d_mmap_single = test_mmap_single;
    driver->d_name = "cdev-mmap-single";
    device = make_dev(driver, 9, 0, 0, 0600, "cdev-mmap-single%r", 9);
    assert(device != 0);
    assert(bsd_bridge_cdev_node_count() == 1);
    assert(bsd_bridge_cdev_node_at(0, &node) == 0);
    linux_device = linux_device_number(node.major, node.minor);
    assert(bsd_bridge_cdev_mmap_supported(linux_device));
    assert(bsd_bridge_cdev_open(linux_device, 2, 2001, 50, 40) == 0);
    assert(bsd_bridge_cdev_mmap_page(linux_device, 2001,
        TEST_PAGE_SIZE, 3, &mapped_physical, &memory_attribute) == 0);
    assert(mapped_physical == TEST_MMAP_SINGLE_PHYSICAL + TEST_PAGE_SIZE);
    assert(memory_attribute == BSD_BRIDGE_CDEV_MEMORY_DEFAULT);
    assert(g_mmap_single_release_count == 1);
    assert(bsd_bridge_cdev_mmap_page(linux_device, 2001,
        2u * TEST_PAGE_SIZE, 3,
        &mapped_physical, &memory_attribute) == -22);
    assert(g_mmap_single_release_count == 1);
    assert(bsd_bridge_cdev_close(2001) == 0);
    destroy_dev(device);
    assert(bsd_bridge_cdev_node_count() == 0);
}

int
main(void)
{
    assert(test_destructor_type == test_private_destructor);
    assert(IOCBASECMD(TEST_FREEBSD_VARIABLE_IOCTL) ==
        _IOC(IOC_OUT, 'H', 7, 0));
    assert(IOCGROUP(TEST_FREEBSD_VARIABLE_IOCTL) == 'H');
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
    struct cdevsw driver = {
        .d_version = D_VERSION,
        .d_open = test_open,
        .d_close = test_close,
        .d_read = test_read,
        .d_write = test_write,
        .d_ioctl = test_ioctl,
        .d_poll = test_poll,
        .d_mmap = test_mmap,
        .d_name = "cdev-unit",
        .d_flags = D_TRACKCLOSE | D_NEEDMINOR,
    };
    struct cdev *device;
    struct cdev *alias;
    bsd_bridge_cdev_node_t node;
    uint64_t linux_device;
    uint32_t events = 0;
    uint32_t private_sum = 0;
    uint32_t ioctl_value = 10;
    uint32_t read_ioctl_value = 0;
    _Alignas(uint64_t) uint8_t v4l2_buffer[88] = {0};
    uint64_t mapped_physical = 0;
    int32_t memory_attribute = -1;
    char buffer[8] = {0};
    void *private_data = 0;

    assert(bsd_allocator_initialize(&allocator) == 0);
    assert(bsd_sync_initialize(&sync) == 0);
    assert(bsd_kthread_runtime_initialize() == 0);
    test_clone_devices(&driver);
    g_devtmpfs_change_count = 0;
    device = make_dev(&driver, 7, 0, 0, 0600, "cdev-unit%r", 7);
    assert(device != 0);
    assert(bsd_bridge_cdev_node_count() == 1);
    assert(bsd_bridge_cdev_node_at(0, &node) == 0);
    assert(strcmp(node.name, "cdev-unit7") == 0);
    alias = make_dev_alias(device, "cdev-unit-alias");
    assert(alias != 0);
    assert(alias->si_parent == device);
    assert(bsd_bridge_cdev_node_count() == 2);
    linux_device = linux_device_number(node.major, node.minor);
    assert(bsd_bridge_cdev_present(linux_device));
    assert(bsd_bridge_cdev_mmap_supported(linux_device));
    assert(bsd_bridge_cdev_ioctl_supported(TEST_IOCTL));
    assert(bsd_bridge_cdev_ioctl_input_size(TEST_IOCTL) ==
        sizeof(ioctl_value));
    assert(bsd_bridge_cdev_ioctl_output_size(TEST_IOCTL) ==
        sizeof(ioctl_value));
    assert(bsd_bridge_cdev_ioctl_supported(TEST_LINUX_READ_IOCTL));
    assert(bsd_bridge_cdev_ioctl_input_size(
        TEST_LINUX_READ_IOCTL) == 0);
    assert(bsd_bridge_cdev_ioctl_output_size(
        TEST_LINUX_READ_IOCTL) == sizeof(read_ioctl_value));
    assert(bsd_bridge_cdev_ioctl_supported(TEST_LINUX_VOID_IOCTL));
    assert(bsd_bridge_cdev_ioctl_input_size(
        TEST_LINUX_VOID_IOCTL) == 0);
    assert(bsd_bridge_cdev_ioctl_output_size(
        TEST_LINUX_VOID_IOCTL) == 0);

    assert(bsd_bridge_cdev_open(
        linux_device, 2, 1001, 42, 40) == 0);
    assert(bsd_bridge_cdev_open(
        linux_device, 0, 1002, 43, 40) == 0);
    assert(bsd_bridge_cdev_open(
        linux_device, 2, 1001, 42, 40) == -16);
    assert(g_open_count == 2);
    assert(devfs_get_cdevpriv(&private_data) == 9);

    assert(bsd_bridge_cdev_read_session(
        linux_device, 1001, buffer, 3) == 3);
    assert(memcmp(buffer, "abc", 3) == 0);
    assert(bsd_bridge_cdev_read_session(
        linux_device, 1001, buffer, 3) == 3);
    assert(memcmp(buffer, "def", 3) == 0);
    assert(bsd_bridge_cdev_read_session(
        linux_device, 1002, buffer, 2) == 2);
    assert(memcmp(buffer, "ab", 2) == 0);
    assert(bsd_bridge_cdev_write_session(
        linux_device, 1001, "write", 5) == 5);
    assert(g_written_length == 5);
    assert(memcmp(g_written, "write", 5) == 0);

    assert(bsd_bridge_cdev_poll_session(
        linux_device, 1001, &events) == 0);
    assert(events == (BSD_BRIDGE_CDEV_POLL_READ |
        BSD_BRIDGE_CDEV_POLL_WRITE));
    assert(bsd_bridge_cdev_ioctl_session(
        linux_device, 1001, TEST_IOCTL, 0,
        &ioctl_value, sizeof(ioctl_value)) == 0);
    assert(ioctl_value == 11);
    assert(bsd_bridge_cdev_ioctl_session(
        linux_device, 1001, TEST_LINUX_READ_IOCTL, 0,
        &read_ioctl_value, sizeof(read_ioctl_value)) == 0);
    assert(read_ioctl_value == 101);
    assert(bsd_bridge_cdev_ioctl_session(
        linux_device, 1001, TEST_LINUX_VOID_IOCTL, UINT64_C(0x1234),
        0, 0) == 0);
    assert(g_void_ioctl_count == 1);
    *(uint32_t *)(void *)(v4l2_buffer + 0u) = 3u;
    *(uint32_t *)(void *)(v4l2_buffer + 60u) = 1u;
    *(uint64_t *)(void *)(v4l2_buffer + 64u) = UINT64_C(0x2000);
    assert(bsd_bridge_cdev_ioctl_session(
        linux_device, 1001, TEST_LINUX_V4L2_QUERYBUF, 0,
        v4l2_buffer, sizeof(v4l2_buffer)) == 0);
    assert(*(uint32_t *)(void *)(v4l2_buffer + 0u) == 3u);
    assert(*(uint32_t *)(void *)(v4l2_buffer + 60u) == 1u);
    assert(*(uint64_t *)(void *)(v4l2_buffer + 64u) ==
        UINT64_C(0x2000));
    assert(*(uint32_t *)(void *)(v4l2_buffer + 72u) == 0x3000u);
    assert(*(uint32_t *)(void *)(v4l2_buffer + 80u) == 7u);
    assert(bsd_bridge_cdev_mmap_page(
        linux_device, 1001, TEST_PAGE_SIZE, 3,
        &mapped_physical, &memory_attribute) == 0);
    assert(mapped_physical ==
        TEST_MMAP_PHYSICAL + TEST_PAGE_SIZE);
    assert(memory_attribute ==
        BSD_BRIDGE_CDEV_MEMORY_WRITE_COMBINING);
    assert(bsd_bridge_cdev_mmap_page(
        linux_device, 1001, 2u * TEST_PAGE_SIZE, 3,
        &mapped_physical, &memory_attribute) == -22);
    assert(devfs_foreach_cdevpriv(
        device, sum_private_ordinals, &private_sum) == 0);
    assert(private_sum == 3);

    delist_dev(device);
    assert(bsd_bridge_cdev_node_count() == 0);
    assert(!bsd_bridge_cdev_present(linux_device));
    assert(!bsd_bridge_cdev_mmap_supported(linux_device));
    assert(bsd_bridge_cdev_open(
        linux_device, 2, 1003, 44, 40) ==
        BSD_BRIDGE_CDEV_NOT_HANDLED);
    assert(bsd_bridge_cdev_read_session(
        linux_device, 1002, buffer, 2) == 2);
    assert(memcmp(buffer, "cd", 2) == 0);
    assert(bsd_bridge_cdev_poll_session(
        linux_device, 1002, &events) == 0);
    assert(events == BSD_BRIDGE_CDEV_POLL_HANGUP);

    assert(bsd_bridge_cdev_close(1001) == 0);
    assert(g_close_count == 1);
    assert(g_destructor_count == 1);
    assert(g_close_sequence[0] < g_destructor_sequence[0]);
    assert(g_last_close_count == 0);
    assert(bsd_bridge_cdev_close(1002) == 0);
    assert(g_close_count == 2);
    assert(g_destructor_count == 2);
    assert(g_close_sequence[1] < g_destructor_sequence[1]);
    assert(g_last_close_count == 1);
    assert(bsd_bridge_cdev_close(1002) ==
        BSD_BRIDGE_CDEV_NOT_HANDLED);

    destroy_dev(device);
    assert(bsd_bridge_cdev_read_session(
        linux_device, 1001, buffer, 1) ==
        BSD_BRIDGE_CDEV_NOT_HANDLED);
    assert(g_devtmpfs_change_count == 3);

    test_mmap_single_device(&driver);

    printf("bsd_bridge_cdev_unit: PASS\n");
    return 0;
}
