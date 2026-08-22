/* SPDX-License-Identifier: MPL-2.0 */
/* Original EdgeOS Linux virtual-terminal sysfs ABI regression test. */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>

#ifndef VT_GETSTATE
#define VT_GETSTATE 0x5603
#endif
#ifndef VT_OPENQRY
#define VT_OPENQRY 0x5600
#endif

struct edge_vt_stat {
    unsigned short active;
    unsigned short signal;
    unsigned short state;
};

static int fail(const char *operation) {
    fprintf(stderr, "vt_sysfs_abi_probe: %s: %s\n",
            operation, strerror(errno));
    return 1;
}

static int check_virtual_terminal(unsigned int number) {
    struct edge_vt_stat state;
    struct stat status;
    char path[64];
    char value[32];
    int descriptor;
    int length;
    ssize_t count;

    length = snprintf(path, sizeof(path), "/dev/tty%u", number);
    if (length < 0 || (size_t)length >= sizeof(path)) {
        errno = ENAMETOOLONG;
        return fail("format VT device path");
    }
    descriptor = open(path, O_RDONLY | O_NOCTTY | O_CLOEXEC);
    if (descriptor < 0) return fail(path);
    memset(&state, 0, sizeof(state));
    if (ioctl(descriptor, VT_GETSTATE, &state) < 0) {
        close(descriptor);
        return fail("VT_GETSTATE on numbered VT");
    }
    if (fstat(descriptor, &status) < 0) {
        close(descriptor);
        return fail("fstat numbered VT");
    }
    if (!S_ISCHR(status.st_mode) || major(status.st_rdev) != 4u ||
        minor(status.st_rdev) != number) {
        close(descriptor);
        errno = EPROTO;
        return fail("numbered VT device identity");
    }
    if (close(descriptor) < 0) return fail("close numbered VT");

    length = snprintf(path, sizeof(path), "/sys/class/tty/tty%u/dev", number);
    if (length < 0 || (size_t)length >= sizeof(path)) {
        errno = ENAMETOOLONG;
        return fail("format VT sysfs path");
    }
    descriptor = open(path, O_RDONLY | O_CLOEXEC);
    if (descriptor < 0) return fail(path);
    count = read(descriptor, value, sizeof(value) - 1u);
    if (count < 0) {
        close(descriptor);
        return fail("read numbered VT sysfs dev");
    }
    if (close(descriptor) < 0) return fail("close numbered VT sysfs dev");
    value[count] = 0;
    length = snprintf(path, sizeof(path), "4:%u\n", number);
    if (length < 0 || count != length || memcmp(value, path, (size_t)count)) {
        errno = EPROTO;
        return fail("numbered VT sysfs identity");
    }
    return 0;
}

int main(void) {
    struct edge_vt_stat state;
    char expected[32];
    char active[32];
    int available;
    int tty;
    int attribute;
    ssize_t length;
    int expected_length;

    if (check_virtual_terminal(1u) || check_virtual_terminal(63u)) return 1;

    tty = open("/dev/tty0", O_RDONLY | O_NOCTTY | O_CLOEXEC);
    if (tty < 0) return fail("open /dev/tty0");
    memset(&state, 0, sizeof(state));
    if (ioctl(tty, VT_GETSTATE, &state) < 0) {
        close(tty);
        return fail("VT_GETSTATE");
    }
    available = -1;
    if (ioctl(tty, VT_OPENQRY, &available) < 0) {
        close(tty);
        return fail("VT_OPENQRY after numbered VT probes");
    }
    if (available < 1 || available > 63 ||
        available == (int)state.active) {
        close(tty);
        errno = EPROTO;
        return fail("VT_OPENQRY returned an unavailable VT");
    }
    if (close(tty) < 0) return fail("close /dev/tty0");
    if (state.active == 0) {
        errno = EPROTO;
        return fail("VT_GETSTATE returned VT zero");
    }

    attribute = open("/sys/class/tty/tty0/active", O_RDONLY | O_CLOEXEC);
    if (attribute < 0) return fail("open tty0 active attribute");
    length = read(attribute, active, sizeof(active) - 1u);
    if (length < 0) {
        close(attribute);
        return fail("read tty0 active attribute");
    }
    if (close(attribute) < 0) return fail("close tty0 active attribute");
    active[length] = 0;
    expected_length = snprintf(expected, sizeof(expected), "tty%u\n",
                               (unsigned int)state.active);
    if (expected_length < 0 || (size_t)expected_length >= sizeof(expected) ||
        length != expected_length || memcmp(active, expected, (size_t)length)) {
        fprintf(stderr,
                "vt_sysfs_abi_probe: active mismatch: sysfs=%s ioctl=%u\n",
                active, (unsigned int)state.active);
        return 1;
    }

    attribute = open("/sys/class/tty/console/active", O_RDONLY | O_CLOEXEC);
    if (attribute < 0) return fail("open console active attribute");
    length = read(attribute, active, sizeof(active) - 1u);
    if (length < 0) {
        close(attribute);
        return fail("read console active attribute");
    }
    if (close(attribute) < 0) return fail("close console active attribute");
    active[length] = 0;
    expected[expected_length - 1] = 0;
    if (!strstr(active, expected)) {
        errno = EPROTO;
        return fail("console active missing current VT");
    }

    puts("vt_sysfs_abi_probe: PASS");
    return 0;
}
