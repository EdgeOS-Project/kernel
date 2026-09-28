/* SPDX-License-Identifier: MPL-2.0 */
/* Shared character-device contract for imported FreeBSD drivers. */

#ifndef EDGEOS_COMPAT_FREEBSD_CDEV_H
#define EDGEOS_COMPAT_FREEBSD_CDEV_H

#include <stddef.h>
#include <stdint.h>

#define BSD_BRIDGE_CDEV_NOT_HANDLED (-4096)

#define BSD_BRIDGE_CDEV_POLL_READ 0x01u
#define BSD_BRIDGE_CDEV_POLL_WRITE 0x02u
#define BSD_BRIDGE_CDEV_POLL_HANGUP 0x04u

#define BSD_BRIDGE_CDEV_IOCTL_MAX_PAYLOAD 512u

#define BSD_BRIDGE_CDEV_MEMORY_UNCACHEABLE 0
#define BSD_BRIDGE_CDEV_MEMORY_WRITE_COMBINING 1
#define BSD_BRIDGE_CDEV_MEMORY_WRITE_THROUGH 2
#define BSD_BRIDGE_CDEV_MEMORY_WRITE_PROTECTED 3
#define BSD_BRIDGE_CDEV_MEMORY_WRITE_BACK 4
#define BSD_BRIDGE_CDEV_MEMORY_WEAK_UNCACHEABLE 5
#define BSD_BRIDGE_CDEV_MEMORY_DEVICE 6
#define BSD_BRIDGE_CDEV_MEMORY_DEVICE_NP 7
#define BSD_BRIDGE_CDEV_MEMORY_DEFAULT BSD_BRIDGE_CDEV_MEMORY_WRITE_BACK

#define BSD_BRIDGE_LINUX_TCGETS 0x5401u
#define BSD_BRIDGE_LINUX_TCSETS 0x5402u
#define BSD_BRIDGE_LINUX_TCSETSW 0x5403u
#define BSD_BRIDGE_LINUX_TCSETSF 0x5404u
#define BSD_BRIDGE_LINUX_TCSBRK 0x5409u
#define BSD_BRIDGE_LINUX_TCXONC 0x540au
#define BSD_BRIDGE_LINUX_TCFLSH 0x540bu
#define BSD_BRIDGE_LINUX_TIOCGWINSZ 0x5413u
#define BSD_BRIDGE_LINUX_TIOCSWINSZ 0x5414u
#define BSD_BRIDGE_LINUX_FIONREAD 0x541bu
#define BSD_BRIDGE_LINUX_TCSBRKP 0x5425u

typedef struct bsd_bridge_linux_termios {
    uint32_t iflag;
    uint32_t oflag;
    uint32_t cflag;
    uint32_t lflag;
    uint8_t line;
    uint8_t cc[19];
} bsd_bridge_linux_termios_t;

typedef struct bsd_bridge_linux_winsize {
    uint16_t rows;
    uint16_t columns;
    uint16_t xpixel;
    uint16_t ypixel;
} bsd_bridge_linux_winsize_t;

typedef struct bsd_bridge_cdev_node {
    char name[128];
    uint32_t major;
    uint32_t minor;
    uint16_t mode;
    uint16_t uid;
    uint16_t gid;
    uint8_t alias;
} bsd_bridge_cdev_node_t;

uint32_t bsd_bridge_cdev_node_count(void);
int bsd_bridge_cdev_node_at(uint32_t ordinal,
    bsd_bridge_cdev_node_t *node);

/*
 * A session is keyed by the architecture-neutral open-file-description
 * identity. Descriptor duplication shares that identity, so imported driver
 * open and private-data destructors run exactly once per open description.
 */
int bsd_bridge_cdev_open(uint64_t linux_rdev, uint32_t linux_flags,
    uint64_t description_identity, int32_t process_id,
    int32_t process_group_id);
int bsd_bridge_cdev_close(uint64_t description_identity);

int bsd_bridge_cdev_read_session(uint64_t linux_rdev,
    uint64_t description_identity, void *buffer, uint32_t length);
int bsd_bridge_cdev_write_session(uint64_t linux_rdev,
    uint64_t description_identity, const void *buffer, uint32_t length);
int bsd_bridge_cdev_poll_session(uint64_t linux_rdev,
    uint64_t description_identity, uint32_t *events);
int bsd_bridge_cdev_ioctl_session(uint64_t linux_rdev,
    uint64_t description_identity, uint32_t command,
    uint64_t scalar_argument, void *payload, uint32_t payload_size);

/* Legacy helpers remain available to kernel-internal callers without an OFD. */
int bsd_bridge_cdev_read(uint64_t linux_rdev, void *buffer,
    uint32_t length);
int bsd_bridge_cdev_write(uint64_t linux_rdev, const void *buffer,
    uint32_t length);
int bsd_bridge_cdev_poll(uint64_t linux_rdev, uint32_t *events);
int bsd_bridge_cdev_poll_sequences(uint64_t linux_rdev,
    uint64_t *read_sequence, uint64_t *write_sequence);
int bsd_bridge_cdev_present(uint64_t linux_rdev);
int bsd_bridge_cdev_is_tty(uint64_t linux_rdev);
int bsd_bridge_cdev_mmap_supported(uint64_t linux_rdev);
int bsd_bridge_cdev_mmap_page(uint64_t linux_rdev,
    uint64_t description_identity, uint64_t offset,
    uint32_t protection, uint64_t *physical_address,
    int32_t *memory_attribute);
uint64_t bsd_bridge_cdev_change_sequence(void);

int bsd_bridge_cdev_ioctl_supported(uint32_t command);
uint32_t bsd_bridge_cdev_ioctl_input_size(uint32_t command);
uint32_t bsd_bridge_cdev_ioctl_output_size(uint32_t command);
int bsd_bridge_cdev_ioctl(uint64_t linux_rdev, uint32_t command,
    uint64_t scalar_argument, void *payload, uint32_t payload_size);

/*
 * The kernel devtmpfs implementation overrides this weak bridge hook.  Host
 * tests and kernels without devtmpfs retain the no-op implementation.
 */
void bsd_bridge_devtmpfs_changed(void);

#endif
